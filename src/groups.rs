//! Read shared keychain groups from the `com.apple.security.shared.keychain`
//! container. A group is a CloudKit zone named `group-<UUID>` whose records are
//! PCS-encrypted. This module only reads: it never accepts, declines, or writes
//! a share.

use crate::cloudkit::{Gateway, Participant, Record, Scope, ShareInfo, Zone};
use crate::error::{Error, Result};
use crate::kcsharing;
use crate::model::{Entry, EntryKind, Group, Passkey};
use crate::pcs::{Decoded, PcsKey, Protection, ServiceKey};

pub struct GroupData {
    pub group: Group,
    pub entries: Vec<Entry>,
    /// Items in this group that could not be decrypted.
    pub skipped: usize,
}

/// Every group zone that could be read, plus one warning per zone that could
/// not. A caller that must not drop shared entries checks `warnings` and
/// `GroupData::skipped` before replacing its snapshot.
pub struct GroupRead {
    pub groups: Vec<GroupData>,
    pub warnings: Vec<String>,
}

/// Read every group zone visible to this gateway.
pub async fn read_all(gateway: &Gateway, service_keys: &[ServiceKey]) -> Result<GroupRead> {
    let mut out = GroupRead {
        groups: Vec::new(),
        warnings: Vec::new(),
    };
    for zone in zones(gateway).await? {
        if !zone.name.starts_with("group-") || zone.change_type == 2 {
            continue;
        }
        match read_zone(gateway, &zone.name, &zone.owner, service_keys).await {
            Ok(Some(group)) => out.groups.push(group),
            Ok(None) => {}
            Err(error) => out.warnings.push(format!(
                "group zone {} ({:?}) could not be read: {error}",
                zone.name,
                gateway.scope()
            )),
        }
    }
    Ok(out)
}

/// One group zone as `group list` shows it.
#[derive(Debug, Clone)]
pub struct ZoneSummary {
    pub zone: String,
    pub owner: String,
    /// The decrypted `displayName`, when the zone opens with our keys.
    pub name: Option<String>,
    pub participants: usize,
}

/// Summarize every group zone this gateway can see without reading items.
///
/// This is the read path `group list` uses: the zone list, then per zone the
/// zoneshare record for its name and member count. A zone that does not open
/// with our service keys is still listed, with no name.
pub async fn summaries(gateway: &Gateway, service_keys: &[ServiceKey]) -> Result<Vec<ZoneSummary>> {
    let mut out = Vec::new();
    for info in zones(gateway).await? {
        if !info.name.starts_with("group-") || info.change_type == 2 {
            continue;
        }
        let records = records(gateway, &info.name, &info.owner)
            .await
            .unwrap_or_default();
        let share = records.iter().find(|record| {
            record.name == "cloudkit.zoneshare" || record.record_type == "cloudkit.share"
        });
        let participants = share
            .and_then(|record| record.share_info.as_ref())
            .map(|share| share.participants.len())
            .unwrap_or(0);
        let name = match gateway.zone_retrieve(&info.name, &info.owner).await {
            Ok(zone) => {
                let keys = open_zone(
                    &zone,
                    share.and_then(|record| record.share_info.as_ref()),
                    gateway,
                    service_keys,
                )
                .unwrap_or_default();
                display_name(&records, &keys, &info.name)
            }
            Err(_) => None,
        };
        out.push(ZoneSummary {
            zone: info.name,
            owner: info.owner,
            name,
            participants,
        });
    }
    Ok(out)
}

/// The keys a writer needs for one owner-side zone.
#[derive(Clone)]
pub struct ZoneKeys {
    /// Every key that can decrypt the zone, newest first.
    pub keys: Vec<PcsKey>,
    /// The record key a new item is sealed with.
    pub record_key: PcsKey,
    /// The record protection tag the server sent, when it sent one. A save
    /// quotes it so the server knows which protection the write trusts.
    pub record_tag: Option<String>,
}

/// Open one group zone for writing: its record key and protection tag.
///
/// A zone that does not open with this account's service keys is refused, so a
/// write never lands in somebody else's group.
pub async fn zone_keys(
    gateway: &Gateway,
    zone_name: &str,
    owner: &str,
    service_keys: &[ServiceKey],
) -> Result<ZoneKeys> {
    let zone = gateway.zone_retrieve(zone_name, owner).await?;
    let records = records(gateway, zone_name, owner).await?;
    let share = records
        .iter()
        .find(|record| {
            record.name == "cloudkit.zoneshare" || record.record_type == "cloudkit.share"
        })
        .and_then(|record| record.share_info.as_ref());
    let parts = open_zone_parts(&zone, share, gateway, service_keys)?;
    let record_key = parts.record.first().cloned().ok_or_else(|| {
        Error::Message(format!(
            "zone {zone_name} has no record key; refusing to write"
        ))
    })?;
    Ok(ZoneKeys {
        keys: parts.keys,
        record_key,
        record_tag: zone.record_protection_info_tag.clone(),
    })
}

pub(crate) async fn zones(gateway: &Gateway) -> Result<Vec<crate::cloudkit::ZoneInfo>> {
    let mut out = Vec::new();
    let mut token: Option<Vec<u8>> = None;
    let mut pages = 0;
    loop {
        let page = gateway.zone_changes(token.as_deref()).await?;
        out.extend(page.zones);
        pages += 1;
        if page.status == 2 {
            break;
        }
        if pages >= 10 {
            return Err(Error::Message("zone list did not finish paging".into()));
        }
        match page.token {
            Some(next) if Some(&next) != token.as_ref() => token = Some(next),
            _ => return Err(Error::Message("zone list did not finish paging".into())),
        }
    }
    Ok(out)
}

pub(crate) async fn records(gateway: &Gateway, zone: &str, owner: &str) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    let mut token: Option<Vec<u8>> = None;
    let mut pages = 0;
    loop {
        let page = gateway
            .record_sync(zone, Some(owner), token.as_deref())
            .await?;
        out.extend(page.records);
        pages += 1;
        if page.status != 1 {
            break;
        }
        if pages >= 20 {
            return Err(Error::Message(format!("zone {zone} did not finish paging")));
        }
        match page.token {
            Some(next) if Some(&next) != token.as_ref() => token = Some(next),
            _ => return Err(Error::Message(format!("zone {zone} did not finish paging"))),
        }
    }
    Ok(out)
}

async fn read_zone(
    gateway: &Gateway,
    zone_name: &str,
    owner: &str,
    service_keys: &[ServiceKey],
) -> Result<Option<GroupData>> {
    let zone = gateway.zone_retrieve(zone_name, owner).await?;
    let records = records(gateway, zone_name, owner).await?;

    if std::env::var_os("APW_DEBUG").is_some() {
        let names: Vec<String> = records
            .iter()
            .map(|record| format!("{}/{}", record.name, record.record_type))
            .collect();
        eprintln!(
            "groups: {} records {:?}",
            records.len(),
            &names[..names.len().min(12)]
        );
    }
    let share_record = records.iter().find(|record| {
        record.name == "cloudkit.zoneshare" || record.record_type == "cloudkit.share"
    });
    if std::env::var_os("APW_DEBUG").is_some() {
        if let Some(record) = share_record {
            eprintln!(
                "groups: share record {} fields {:?} share_info {}",
                record.name,
                record.fields.keys().collect::<Vec<_>>(),
                record.share_info.is_some()
            );
        }
    }
    let share = share_record.and_then(|record| record.share_info.as_ref());
    let share = match share {
        Some(share) => Some(share),
        // A group the user owns but never shared has no zoneshare record; the
        // zone protection opens with the service key alone.
        None if gateway.scope() == Scope::Private => None,
        None => {
            return Err(Error::Message(format!(
                "group zone has no share record ({} records)",
                records.len()
            )))
        }
    };
    if share.is_none() && !records.iter().any(|record| record.record_type == "item") {
        return Ok(None);
    }

    let keys = open_zone(&zone, share, gateway, service_keys)?;
    if std::env::var_os("APW_DEBUG").is_some() {
        for key in &keys {
            eprintln!("groups: key id {:02x?}", &key.key_id()[..4]);
        }
    }
    let id = zone_name.trim_start_matches("group-").to_string();

    let mut entries = Vec::new();
    let mut sidecars = Vec::new();
    let mut skipped = 0usize;
    for record in &records {
        if record.record_type != "item" {
            continue;
        }
        let Some(payload) = record.bytes("payload") else {
            continue;
        };
        let aad = format!("{zone_name}-{}-payload", record.name);
        let plain = match decrypt_any(&keys, payload, &aad) {
            Ok(plain) => plain,
            Err(error) => {
                skipped += 1;
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("groups: {} payload failed: {error}", record.name);
                }
                continue;
            }
        };
        let item = match kcsharing::decode_item(&plain) {
            Ok(item) => item,
            Err(error) => {
                skipped += 1;
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("groups: {} decode failed: {error}", record.name);
                }
                continue;
            }
        };

        if let Some(password) = item.internet_password {
            let entry = password_entry(&record.name, &id, password);
            if entry.agrp.as_deref() == Some("com.apple.password-manager") {
                sidecars.push(entry);
            } else {
                entries.push(entry);
            }
        } else if let Some(key) = item.private_key {
            entries.push(Entry {
                id: record.name.clone(),
                kind: EntryKind::Passkey,
                agrp: Some(key.access_group),
                title: (!key.label.is_empty()).then_some(key.label),
                group: Some(id.clone()),
                passkey: Some(Passkey {
                    relying_party: String::from_utf8(key.application_label).ok(),
                    username: None,
                    created_at: None,
                    ..Passkey::default()
                }),
                ..Entry::default()
            });
        }
    }

    let _ = crate::model::merge_sidecars(&mut entries, sidecars);

    let name = display_name(&records, &keys, zone_name);

    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!("group {zone_name}: name={name:?}");
    }
    Ok(Some(GroupData {
        group: Group {
            id,
            name,
            shared: gateway.scope() == Scope::Shared,
        },
        entries,
        skipped,
    }))
}

/// Decrypt the zoneshare `displayName` with one of `keys`.
///
/// The plaintext is Apple's `Record.Field.EncryptedValue` message carrying the
/// name as field 6 (`0x32`, a length-delimited string).
fn display_name(records: &[Record], keys: &[PcsKey], zone_name: &str) -> Option<String> {
    records
        .iter()
        .find(|record| record.name == "cloudkit.zoneshare")
        .and_then(|record| record.bytes("displayName"))
        .and_then(|value| {
            let aad = format!("{zone_name}-cloudkit.zoneshare-displayName");
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!(
                    "groups: displayName {} bytes, {} keys",
                    value.len(),
                    keys.len()
                );
            }
            decrypt_any(keys, value, &aad).ok()
        })
        .and_then(|plain| {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!(
                    "groups: displayName plain {} bytes {plain:02x?}",
                    plain.len()
                );
            }
            // The name is a protobuf string: tag 1, length, UTF-8.
            // Protobuf string: a length-delimited field (wire type 2),
            // observed as field 6 (`0x32`) on Apple's zoneshare.
            let text = match plain.split_first() {
                Some((tag, rest))
                    if tag & 0x07 == 2 && rest.first() == Some(&(rest.len() as u8 - 1)) =>
                {
                    &rest[1..]
                }
                _ => &plain[..],
            };
            String::from_utf8(text.to_vec()).ok()
        })
}

fn password_entry(record_name: &str, group: &str, password: kcsharing::SharedPassword) -> Entry {
    let domain = if password.server.is_empty() {
        password.label.clone()
    } else {
        password.server.clone()
    };
    let notes = String::from_utf8(password.notes)
        .ok()
        .filter(|notes| !notes.is_empty());
    Entry {
        id: record_name.to_string(),
        kind: EntryKind::Login,
        agrp: Some(password.access_group),
        title: if password.label.is_empty() {
            None
        } else {
            Some(password.label)
        },
        url: (!domain.is_empty()).then(|| format!("https://{domain}")),
        sites: if domain.is_empty() {
            Vec::new()
        } else {
            vec![domain]
        },
        username: (!password.account.is_empty()).then_some(password.account),
        password: String::from_utf8(password.data).ok(),
        notes,
        group: Some(group.to_string()),
        ..Entry::default()
    }
}

/// The working keys of an opened zone.
struct ZoneParts {
    /// Zone keys followed by record keys, as the read path wants them.
    keys: Vec<PcsKey>,
    /// The record protection's keys, master first.
    record: Vec<PcsKey>,
}

/// Open the zone keyset. Shared zones chain through the participant protection
/// and the owner's invited protection; private zones use the service key
/// directly.
fn open_zone(
    zone: &Zone,
    share: Option<&ShareInfo>,
    gateway: &Gateway,
    service_keys: &[ServiceKey],
) -> Result<Vec<PcsKey>> {
    Ok(open_zone_parts(zone, share, gateway, service_keys)?.keys)
}

fn open_zone_parts(
    zone: &Zone,
    share: Option<&ShareInfo>,
    gateway: &Gateway,
    service_keys: &[ServiceKey],
) -> Result<ZoneParts> {
    let service: Vec<_> = service_keys.iter().map(|key| key.secret.clone()).collect();
    let protection = zone
        .protection_info
        .as_deref()
        .ok_or_else(|| Error::Message("zone has no protection info".into()))?;
    let zone_protection = Protection::parse(protection)?;

    let decoded = if gateway.scope() == Scope::Shared {
        let share =
            share.ok_or_else(|| Error::Message("shared zone has no share record".into()))?;
        let participant = find_participant(share, gateway.user_id(), service_keys)?;
        let protection = participant
            .protection_info
            .as_deref()
            .ok_or_else(|| Error::Message("participant has no protection info".into()))?;
        let user = Protection::parse(protection)?.decode(&service, true)?;

        let invited = share
            .invited_pcs
            .as_deref()
            .ok_or_else(|| Error::Message("share has no invited protection".into()))?;
        let invited = Protection::parse(invited)?;
        let owner = invited.signer();
        let invited = invited.decode(&user.identities, true)?;

        zone_protection.decode(&invited.identities, owner.as_ref().is_some())?
    } else {
        zone_protection.decode(&service, false)?
    };

    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "groups: zone protection keys {} identities {}",
            decoded.keys.len(),
            decoded.identities.len()
        );
        let object_ok = service_keys
            .iter()
            .find_map(|service| zone_protection.unwrap_entry(&service.secret).ok())
            .is_some_and(|raw| zone_protection.verify_object(&raw).is_ok());
        let hmac_ok = decoded
            .keys
            .first()
            .is_some_and(|master| zone_protection.verify_hmac(master).is_ok());
        let outer_ok = service_keys.iter().any(|service| {
            std::iter::once(&service.secret)
                .chain(service.signing.as_ref())
                .any(|key| zone_protection.verify_outer(&key.public_key()).is_ok())
        });
        eprintln!(
            "groups: zone protection verified object={object_ok} hmac={hmac_ok} outer={outer_ok}"
        );
    }
    let mut keys = decoded.keys;
    let mut record = Vec::new();
    if let Some(record_protection) = zone.record_protection_info.as_deref() {
        let record_protection = Protection::parse(record_protection)?;
        match record_protection.decode(&decoded.identities, false) {
            Ok(decoded_record) => {
                record = decoded_record.keys.clone();
                keys.extend(decoded_record.keys);
            }
            Err(error) => {
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("groups: record protection: {error}");
                }
            }
        }
    }
    Ok(ZoneParts { keys, record })
}

fn find_participant<'a>(
    share: &'a ShareInfo,
    user_id: &str,
    service_keys: &[ServiceKey],
) -> Result<&'a Participant> {
    if let Some(participant) = share
        .participants
        .iter()
        .find(|participant| participant.user_id.as_deref() == Some(user_id))
    {
        return Ok(participant);
    }

    let public: Vec<Vec<u8>> = service_keys.iter().map(ServiceKey::public_x).collect();
    share
        .participants
        .iter()
        .find(|participant| {
            participant
                .public_key
                .as_deref()
                .is_some_and(|key| public.iter().any(|candidate| candidate == key))
        })
        .ok_or_else(|| Error::Message("not a participant in this group".into()))
}

fn decrypt_any(keys: &[PcsKey], ciphertext: &[u8], aad: &str) -> Result<Vec<u8>> {
    let mut last = None;
    for key in keys {
        match key.decrypt(ciphertext, aad.as_bytes()) {
            Ok(plain) => return Ok(plain),
            Err(error) => {
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("pcs: field decrypt failed: {error}");
                }
                last = Some(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::Message("no PCS key for this field".into())))
}

#[allow(dead_code)]
fn _assert_decoded(_: &Decoded) {}
