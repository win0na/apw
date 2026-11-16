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
}

/// Read every group zone visible to this gateway.
pub async fn read_all(gateway: &Gateway, service_keys: &[ServiceKey]) -> Result<Vec<GroupData>> {
    let mut out = Vec::new();
    for zone in zones(gateway).await? {
        if !zone.name.starts_with("group-") || zone.change_type == 2 {
            continue;
        }
        match read_zone(gateway, &zone.name, &zone.owner, service_keys).await {
            Ok(group) => out.push(group),
            Err(error) => {
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("groups: {} skipped: {error}", zone.name);
                }
            }
        }
    }
    Ok(out)
}

async fn zones(gateway: &Gateway) -> Result<Vec<crate::cloudkit::ZoneInfo>> {
    let mut out = Vec::new();
    let mut token: Option<Vec<u8>> = None;
    let mut pages = 0;
    loop {
        let page = gateway.zone_changes(token.as_deref()).await?;
        out.extend(page.zones);
        pages += 1;
        if page.status == 2 || pages >= 10 {
            break;
        }
        match page.token {
            Some(next) if Some(&next) != token.as_ref() => token = Some(next),
            _ => break,
        }
    }
    Ok(out)
}

async fn records(gateway: &Gateway, zone: &str, owner: &str) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    let mut token: Option<Vec<u8>> = None;
    let mut pages = 0;
    loop {
        let page = gateway
            .record_sync(zone, Some(owner), token.as_deref())
            .await?;
        out.extend(page.records);
        pages += 1;
        if page.status != 1 || pages >= 20 {
            break;
        }
        match page.token {
            Some(next) if Some(&next) != token.as_ref() => token = Some(next),
            _ => break,
        }
    }
    Ok(out)
}

async fn read_zone(
    gateway: &Gateway,
    zone_name: &str,
    owner: &str,
    service_keys: &[ServiceKey],
) -> Result<GroupData> {
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
    let share = share_record
        .and_then(|record| record.share_info.as_ref())
        .ok_or_else(|| Error::Message("group zone has no share record".into()))?;

    let keys = open_zone(&zone, share, gateway, service_keys)?;
    let id = zone_name.trim_start_matches("group-").to_string();

    let mut entries = Vec::new();
    let mut sidecars = Vec::new();
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
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("groups: {} payload failed: {error}", record.name);
                }
                continue;
            }
        };
        let item = match kcsharing::decode_item(&plain) {
            Ok(item) => item,
            Err(error) => {
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
                }),
                ..Entry::default()
            });
        }
    }

    let _ = crate::model::merge_sidecars(&mut entries, sidecars);

    let name = records
        .iter()
        .find(|record| record.name == "cloudkit.zoneshare")
        .and_then(|record| record.bytes("displayName"))
        .and_then(|value| {
            let aad = format!("{zone_name}-cloudkit.zoneshare-displayName");
            decrypt_any(&keys, value, &aad).ok()
        })
        .and_then(|plain| String::from_utf8(plain).ok());

    let participants = share
        .participants
        .iter()
        .filter(|participant| participant.state == 3)
        .count();

    let _ = participants;
    Ok(GroupData {
        group: Group {
            id,
            name,
            shared: gateway.scope() == Scope::Shared,
        },
        entries,
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

/// Open the zone keyset. Shared zones chain through the participant protection
/// and the owner's invited protection; private zones use the service key
/// directly.
fn open_zone(
    zone: &Zone,
    share: &ShareInfo,
    gateway: &Gateway,
    service_keys: &[ServiceKey],
) -> Result<Vec<PcsKey>> {
    let service: Vec<_> = service_keys.iter().map(|key| key.secret.clone()).collect();
    let protection = zone
        .protection_info
        .as_deref()
        .ok_or_else(|| Error::Message("zone has no protection info".into()))?;
    let zone_protection = Protection::parse(protection)?;

    let decoded = if gateway.scope() == Scope::Shared {
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

    let mut keys = decoded.keys;
    if let Some(record_protection) = zone.record_protection_info.as_deref() {
        let record_protection = Protection::parse(record_protection)?;
        if let Ok(record) = record_protection.decode(&decoded.identities, false) {
            keys.extend(record.keys);
        }
    }
    Ok(keys)
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
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| Error::Message("no PCS key for this field".into())))
}

#[allow(dead_code)]
fn _assert_decoded(_: &Decoded) {}
