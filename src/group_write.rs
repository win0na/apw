//! Items in an existing password group.
//!
//! A group is a private CloudKit zone in the shared keychain container. This
//! module only writes item records into a zone somebody else created: an item
//! is sealed with the zone's record key, so the next sync reads it back with
//! the same key the share handed out.

use chrono::{DateTime, Utc};

use crate::cloudkit::{self, FieldValue, Gateway, OutgoingField, OutgoingRecord, SAVE_CREATE};
use crate::error::{Error, Result};
use crate::kcsharing::{self, SharedItem, SharedPassword};
use crate::model::Entry;
use crate::pcs::PcsKey;
use crate::wire::Writer;

/// The record type of a group item.
const ITEM_TYPE: &str = "item";
/// `EncryptedValue.signedValue` for a shared internet password.
const ITEM_TYPE_PASSWORD: i64 = 2;

/// Add one personal login to a group zone and return the item record's name.
///
/// The item is sealed with the zone's record key, so the next sync reads it
/// back with the same key the share handed out.
pub async fn add_item(
    gateway: &Gateway,
    zone: &str,
    record_key: &PcsKey,
    tag: Option<&str>,
    entry: &Entry,
    now: DateTime<Utc>,
) -> Result<String> {
    let record = item_record(zone, record_key, tag, entry, now)?;
    let name = record.name.clone();
    gateway.save_record(zone, None, &record).await?;
    Ok(name)
}

/// Delete one group item record.
///
/// CloudKit's `RecordDeleteRequest` has no protection-tag field, so `tag` is
/// checked against the zone first: a stale key must not delete a record whose
/// protection it cannot open.
pub async fn remove_item(
    gateway: &Gateway,
    zone: &str,
    tag: Option<&str>,
    record_name: &str,
) -> Result<()> {
    if record_name.is_empty() || record_name.starts_with("cloudkit.") {
        return Err(Error::Invalid(format!(
            "refusing to delete {record_name:?} from a group zone"
        )));
    }
    if let Some(tag) = tag {
        let info = gateway.zone_retrieve(zone, gateway.user_id()).await?;
        if info.record_protection_info_tag.as_deref() != Some(tag) {
            return Err(Error::Message(format!(
                "zone {zone} now holds a different record protection; run `apw sync` and try again"
            )));
        }
    }
    gateway.delete_record(zone, None, record_name).await
}

/// The `OutgoingRecord` for one shared login.
///
/// `payload` is the `SharingItem` plaintext and `type` is Apple's
/// `EncryptedValue { signedValue = 2 }`, both sealed with the zone's record key
/// under their own AAD.
pub(crate) fn item_record(
    zone: &str,
    record_key: &PcsKey,
    tag: Option<&str>,
    entry: &Entry,
    now: DateTime<Utc>,
) -> Result<OutgoingRecord> {
    let name = format!("item-{}", cloudkit::uppercase_uuid());
    let password = password_from_entry(entry, now)?;
    let payload = kcsharing::encode_item(&SharedItem {
        internet_password: Some(password),
        private_key: None,
    });

    let mut kind = Writer::new();
    // `EncryptedValue.signedValue = 2`: an internet password item.
    kind.int64(3, ITEM_TYPE_PASSWORD);

    let payload = record_key.encrypt(&payload, format!("{zone}-{name}-payload").as_bytes())?;
    let kind = record_key.encrypt(&kind.finish(), format!("{zone}-{name}-type").as_bytes())?;

    Ok(OutgoingRecord {
        name,
        record_type: ITEM_TYPE.into(),
        etag: None,
        semantics: SAVE_CREATE,
        fields: vec![
            OutgoingField {
                name: "payload".into(),
                value: FieldValue::Bytes(payload),
                encrypted: true,
                encrypted_string: false,
                encrypted_int: false,
            },
            OutgoingField {
                name: "type".into(),
                value: FieldValue::Bytes(kind),
                encrypted: true,
                encrypted_string: false,
                encrypted_int: true,
            },
        ],
        plugin_fields: Vec::new(),
        delete_fields: Vec::new(),
        share_info: None,
        stable_url: None,
        pcs_key: Some(record_key.key_id()[..4].to_vec()),
        zone_protection_tag: None,
        record_protection_tag: tag.map(str::to_string),
    })
}

/// The shared-password body of a personal login.
///
/// The values are the ones every shared login carries: the login plist's
/// `site (username)` label, the form-auth defaults, and Apple-epoch dates.
fn password_from_entry(entry: &Entry, now: DateTime<Utc>) -> Result<SharedPassword> {
    let password = entry.password.clone().ok_or_else(|| {
        Error::Invalid(format!(
            "{} has no password; only a login with a stored password can be added to a group",
            entry.display_name()
        ))
    })?;
    let domain = entry.domain();
    let account = entry.username.clone().unwrap_or_default();
    let seconds = apple_seconds(now);
    let label = format!("{domain} ({account})");

    Ok(SharedPassword {
        access_group: "com.apple.cfnetwork".into(),
        account,
        server: domain,
        protocol: "htps".into(),
        path: String::new(),
        authentication_type: "form".into(),
        label,
        comment: String::new(),
        item_description: "Web form password".into(),
        data: password.into_bytes(),
        notes: entry
            .notes
            .as_deref()
            .map(|notes| notes.as_bytes().to_vec())
            .unwrap_or_default(),
        creation_date: seconds,
        modification_date: seconds,
        port: 0,
    })
}

/// Seconds between 1970-01-01 and Apple's 2001-01-01 epoch.
const APPLE_EPOCH: f64 = 978_307_200.0;

fn apple_seconds(now: DateTime<Utc>) -> f64 {
    now.timestamp_millis() as f64 / 1000.0 - APPLE_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcs;
    use crate::wire::Reader;

    fn fields(data: &[u8]) -> Vec<crate::wire::Field<'_>> {
        Reader::new(data).fields().unwrap()
    }

    fn field<'a>(fields: &[crate::wire::Field<'a>], number: u32) -> crate::wire::Field<'a> {
        *fields.iter().find(|field| field.number == number).unwrap()
    }

    /// One personal login, the shape `group add` accepts.
    fn login() -> Entry {
        Entry {
            id: "login-1".into(),
            kind: crate::model::EntryKind::Login,
            title: Some("Example".into()),
            url: Some("https://example.com/login".into()),
            sites: vec!["example.com".into()],
            username: Some("alice@example.com".into()),
            password: Some("hunter2".into()),
            notes: Some("second factor".into()),
            ..Entry::default()
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed time")
    }

    /// The `Record.Field.Value` of one named item field, as a `Field` list.
    fn item_value<'a>(
        record_fields: &[crate::wire::Field<'a>],
        name: &str,
    ) -> Vec<crate::wire::Field<'a>> {
        record_fields
            .iter()
            .filter(|field| field.number == 7)
            .find_map(|field| {
                let parts = fields(field.bytes().ok()?);
                let identifier = fields(field_of(&parts, 1).bytes().ok()?);
                if field_of(&identifier, 1).string().ok()? != name {
                    return None;
                }
                Some(fields(field_of(&parts, 2).bytes().ok()?))
            })
            .unwrap_or_else(|| panic!("no {name} field"))
    }

    fn field_of<'a>(fields: &[crate::wire::Field<'a>], number: u32) -> crate::wire::Field<'a> {
        *fields.iter().find(|field| field.number == number).unwrap()
    }

    #[test]
    fn an_item_record_has_the_encrypted_field_set() {
        let key = PcsKey::random();
        let record = item_record("group-1234", &key, Some("ABCDEF"), &login(), now()).unwrap();

        assert!(record.name.starts_with("item-"), "{}", record.name);
        assert_eq!(record.name.len(), "item-".len() + 36);
        assert_eq!(record.record_type, "item");
        assert_eq!(record.semantics, SAVE_CREATE);
        let pcs_key = record.pcs_key.as_ref().expect("pcsKey");
        assert_eq!(pcs_key.len(), 4);
        assert_eq!(pcs_key, &key.key_id()[..4]);
        assert_eq!(record.record_protection_tag.as_deref(), Some("ABCDEF"));
        assert_eq!(record.zone_protection_tag, None);
        assert!(record.plugin_fields.is_empty());
        assert!(record.share_info.is_none());

        let request = crate::cloudkit::save_request(&record, "group-1234", "owner-1");
        let top = fields(request.as_slice());
        assert_eq!(field(&top, 6).varint().unwrap(), 2, "create semantics");
        assert_eq!(field(&top, 8).string().unwrap(), "ABCDEF");
        let record_fields = fields(field(&top, 1).bytes().unwrap());
        let identifier = fields(field(&record_fields, 2).bytes().unwrap());
        let name = fields(field(&identifier, 1).bytes().unwrap());
        assert_eq!(field(&name, 1).string().unwrap(), record.name);
        let record_type = fields(field(&record_fields, 3).bytes().unwrap());
        assert_eq!(field(&record_type, 1).string().unwrap(), "item");

        let payload = item_value(&record_fields, "payload");
        assert_eq!(field(&payload, 1).varint().unwrap(), 20, "encrypted bytes");
        assert_eq!(field(&payload, 13).varint().unwrap(), 1, "isEncrypted");
        let aad = format!("group-1234-{}-payload", record.name);
        let plain = pcs::decrypt_field(&key, field(&payload, 2).bytes().unwrap(), aad.as_bytes())
            .expect("payload decrypts with the record key");
        let item = kcsharing::decode_item(&plain).unwrap();
        let password = item.internet_password.expect("internet password");
        assert_eq!(password.account, "alice@example.com");
        assert_eq!(password.server, "example.com");
        assert_eq!(password.data, b"hunter2");
        assert_eq!(password.notes, b"second factor");
        assert_eq!(password.label, "example.com (alice@example.com)");
        assert_eq!(password.protocol, "htps");
        assert_eq!(password.authentication_type, "form");
        assert_eq!(password.access_group, "com.apple.cfnetwork");
        assert_eq!(password.item_description, "Web form password");
        assert_eq!(password.port, 0);
        assert_eq!(password.creation_date, 721_692_800.0);
        assert_eq!(
            password.modification_date.to_bits(),
            721_692_800.0f64.to_bits()
        );

        let kind = item_value(&record_fields, "type");
        assert_eq!(field(&kind, 1).varint().unwrap(), 7, "int64 type");
        assert_eq!(field(&kind, 13).varint().unwrap(), 1, "isEncrypted");
        let aad = format!("group-1234-{}-type", record.name);
        let plain = pcs::decrypt_field(&key, field(&kind, 2).bytes().unwrap(), aad.as_bytes())
            .expect("type decrypts with the record key");
        let encrypted_value = fields(&plain);
        assert_eq!(
            field(&encrypted_value, 3).varint().unwrap(),
            2,
            "EncryptedValue.signedValue = 2"
        );
    }

    #[test]
    fn an_item_payload_uses_the_login_fields() {
        let mut entry = login();
        entry.title = Some("A custom title".into());
        entry.notes = None;
        entry.username = None;
        let password = password_from_entry(&entry, now()).unwrap();

        assert_eq!(password.server, "example.com");
        assert_eq!(password.account, "");
        assert_eq!(
            password.label, "example.com ()",
            "the plist label keeps the empty username"
        );
        assert!(password.notes.is_empty());
        assert_eq!(password.path, "");
        assert_eq!(password.comment, "");

        let mut no_password = login();
        no_password.password = None;
        let error = password_from_entry(&no_password, now()).unwrap_err();
        assert!(error.to_string().contains("has no password"), "{error}");
    }

    #[test]
    fn an_item_without_a_record_tag_still_saves() {
        let key = PcsKey::random();
        let record = item_record("group-1234", &key, None, &login(), now()).unwrap();
        let request = crate::cloudkit::save_request(&record, "group-1234", "owner-1");
        let top = fields(request.as_slice());
        assert!(
            top.iter().all(|field| field.number != 8),
            "no record protection tag is sent when the zone has none"
        );
    }
}
