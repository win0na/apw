//! `apw passkey` — import passkeys from a Credential Exchange Format export.
//!
//! Each accepted credential becomes one item record in the `Passwords` zone and
//! one queued `Create`, so `apw sync` pushes it under the classC key.

use std::collections::HashSet;
use std::path::Path;

use base64::Engine;
use chrono::{DateTime, Utc};
use plist::{Dictionary, Value};
use rand::RngCore;
use serde_json::json;
use sha1::{Digest, Sha1};

use crate::commands::write::{ensure_queue_room, entry_label};
use crate::config::{Config, Paths};
use crate::cxf::{self, Candidate, Skipped};
use crate::error::{Error, Result};
use crate::model::{Entry, EntryKind, OpKind, Passkey, PendingOp, RecordMeta, Vault};
use crate::output::{self, Style};
use crate::vault;

/// The 2001-01-01 UTC epoch keychain plists use for `edat` and `sdat`.
const KEYCHAIN_EPOCH: i64 = 978_307_200;

/// Import every passkey in a CXF file. File-level problems fail the command;
/// a bad credential is reported as one skipped row.
pub fn import(
    paths: &Paths,
    config: &mut Config,
    file: &Path,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    let text = std::fs::read_to_string(file)
        .map_err(|error| Error::Invalid(format!("cannot read {}: {error}", file.display())))?;
    let parsed = cxf::parse(&text)?;
    let mut working = vault::load(paths, config)?;

    let now = Utc::now();
    let existing = Existing::from_vault(&working);
    let mut seen_ids = existing.credential_ids;
    let mut seen_accounts = existing.accounts;
    let seen_trash_ids = existing.trashed_ids;
    let seen_trash_accounts = existing.trashed_accounts;
    let mut imported = Vec::new();
    let mut skipped = parsed.skipped;
    let mut planned = Vec::new();

    for candidate in parsed.passkeys {
        let account = (candidate.rp_id.clone(), candidate.user_handle.clone());
        if seen_trash_ids.contains(&candidate.credential_id)
            || seen_trash_accounts.contains(&account)
        {
            skipped.push(skipped_row(&candidate, "already in Recently Deleted"));
            continue;
        }
        if seen_ids.contains(&candidate.credential_id) {
            skipped.push(skipped_row(&candidate, "already imported"));
            continue;
        }
        if seen_accounts.contains(&account) {
            skipped.push(skipped_row(
                &candidate,
                "another passkey for this account already exists",
            ));
            continue;
        }
        seen_ids.insert(candidate.credential_id.clone());
        seen_accounts.insert(account);

        let item_b64 = encode(&passkey_plist(&candidate, now)?);
        let (entry, op) = item_and_op(&candidate, item_b64, now);
        imported.push(json!({
            "id": entry.id,
            "name": entry.display_name(),
            "username": candidate.username,
            "rp_id": candidate.rp_id,
            "pending_id": if dry_run { serde_json::Value::Null } else { json!(op.id) },
        }));
        planned.push((entry, op));
    }

    for credential_type in parsed.unsupported.keys() {
        skipped.push(Skipped {
            rp_id: String::new(),
            username: String::new(),
            reason: format!("unsupported credential type: {credential_type}"),
        });
    }

    if dry_run {
        print_result(&imported, &skipped, true, style.json);
        return Ok(());
    }

    for (entry, op) in planned {
        working.entries.push(entry);
        working.pending.push(op);
        ensure_queue_room(&working)?;
    }
    vault::save(paths, config, &working)?;

    print_result(&imported, &skipped, false, style.json);
    Ok(())
}

fn skipped_row(candidate: &Candidate, reason: &str) -> Skipped {
    Skipped {
        rp_id: candidate.rp_id.clone(),
        username: candidate.username.clone(),
        reason: reason.into(),
    }
}

fn print_result(imported: &[serde_json::Value], skipped: &[Skipped], dry_run: bool, json: bool) {
    if json {
        let mut data = json!({
            "imported": imported,
            "skipped": skipped
                .iter()
                .map(|row| json!({
                    "rp_id": row.rp_id,
                    "username": row.username,
                    "reason": row.reason,
                }))
                .collect::<Vec<_>>(),
        });
        if dry_run {
            data["dry_run"] = json!(true);
        }
        output::print_json(&output::success(data));
        return;
    }

    if imported.is_empty() {
        println!("no passkeys imported");
    }
    for row in imported {
        println!(
            "{}  {}",
            row["rp_id"].as_str().unwrap_or(""),
            row["username"].as_str().unwrap_or("")
        );
    }
    if !skipped.is_empty() {
        println!();
        println!("skipped:");
        for row in skipped {
            println!("{}  {}  {}", row.rp_id, row.username, row.reason);
        }
    }
    if dry_run {
        println!();
        println!("dry run: nothing queued");
    }
}

/// What the snapshot already holds, keyed for the dedupe rules. Live entries
/// and Recently Deleted are tracked apart so the skip reason is accurate.
#[derive(Default)]
struct Existing {
    credential_ids: HashSet<Vec<u8>>,
    accounts: HashSet<(String, Vec<u8>)>,
    trashed_ids: HashSet<Vec<u8>>,
    trashed_accounts: HashSet<(String, Vec<u8>)>,
}

impl Existing {
    fn from_vault(vault: &Vault) -> Self {
        let mut existing = Self::default();
        for entry in &vault.entries {
            existing.insert(entry, false);
        }
        for item in &vault.trash {
            existing.insert(&item.entry, true);
        }
        existing
    }

    fn insert(&mut self, entry: &Entry, trashed: bool) {
        if entry.kind != EntryKind::Passkey {
            return;
        }
        let Some(plist) = entry
            .record
            .as_ref()
            .and_then(|record| record.plist.as_deref())
        else {
            return;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(plist) else {
            return;
        };
        let Ok(value) = plist::from_bytes::<Value>(&bytes) else {
            return;
        };
        let Some(dict) = value.as_dictionary() else {
            return;
        };
        let credential_ids = if trashed {
            &mut self.trashed_ids
        } else {
            &mut self.credential_ids
        };
        if let Some(alis) = dict.get("alis").and_then(Value::as_data) {
            credential_ids.insert(alis.to_vec());
        }
        let Some(labl) = dict.get("labl").and_then(Value::as_string) else {
            return;
        };
        let Some(atag) = dict.get("atag").and_then(Value::as_data) else {
            return;
        };
        if let Some(id) = cbor_map_get(atag, "id") {
            let accounts = if trashed {
                &mut self.trashed_accounts
            } else {
                &mut self.accounts
            };
            accounts.insert((labl.to_string(), id));
        }
    }
}

fn item_and_op(candidate: &Candidate, item_b64: String, now: DateTime<Utc>) -> (Entry, PendingOp) {
    let id = crate::model::record_name();
    let username = (!candidate.username.is_empty()).then(|| candidate.username.clone());
    let entry = Entry {
        id: id.clone(),
        kind: EntryKind::Passkey,
        agrp: Some("com.apple.webkit.webauthn".into()),
        title: Some(candidate.rp_id.clone()),
        sites: vec![candidate.rp_id.clone()],
        username,
        passkey: Some(Passkey {
            relying_party: Some(candidate.rp_id.clone()),
            username: (!candidate.username.is_empty()).then(|| candidate.username.clone()),
            created_at: Some(candidate.created_at.unwrap_or(now)),
        }),
        record: Some(RecordMeta {
            zone: "Passwords".into(),
            item_type: "item".into(),
            plist: Some(item_b64.clone()),
            ..RecordMeta::default()
        }),
        ..Entry::default()
    };
    let label = entry_label(&entry);
    let op = PendingOp {
        id: crate::model::record_name(),
        kind: OpKind::Create,
        entry_kind: EntryKind::Passkey,
        zone: "Passwords".into(),
        owner: None,
        item_name: id,
        item_type: "item".into(),
        item_base: None,
        item_new: Some(item_b64),
        item_etag: None,
        item_dirty: true,
        sidecar_name: None,
        sidecar_type: None,
        sidecar_base: None,
        sidecar_new: None,
        sidecar_write: None,
        sidecar_etag: None,
        sidecar_dirty: false,
        blocked: None,
        attempts: 0,
        next_attempt: None,
        force: false,
        restore: false,
        label,
    };
    (entry, op)
}

/// Build a passkey item plist from scratch. The key set and the v_Data layout
/// match the items Apple writes; only the credential fields differ per import.
pub(crate) fn passkey_plist(candidate: &Candidate, now: DateTime<Utc>) -> Result<Vec<u8>> {
    let mut dict = Dictionary::new();
    dict.insert(
        "agrp".into(),
        Value::String("com.apple.webkit.webauthn".into()),
    );
    dict.insert("class".into(), Value::String("keys".into()));
    dict.insert("pdmn".into(), Value::String("ck".into()));
    dict.insert("type".into(), Value::Integer(73.into()));
    for (key, value) in [
        ("bsiz", 256u64),
        ("esiz", 256),
        ("kcls", 1),
        ("perm", 1),
        ("priv", 1),
        ("modi", 1),
        ("sens", 0),
        ("asen", 0),
        ("extr", 1),
        ("next", 0),
        ("encr", 0),
        ("decr", 1),
        ("sign", 1),
        ("vrfy", 0),
        ("snrc", 0),
        ("vyrc", 0),
        ("drve", 1),
        ("wrap", 0),
        ("unwp", 1),
        ("crtr", 0),
    ] {
        dict.insert(key.into(), Value::Integer(value.into()));
    }
    dict.insert("musr".into(), Value::Data(Vec::new()));
    let epoch = DateTime::from_timestamp(KEYCHAIN_EPOCH, 0).expect("valid keychain epoch");
    dict.insert("edat".into(), date_value(epoch));
    dict.insert("sdat".into(), date_value(epoch));
    dict.insert("tomb".into(), Value::Integer(0.into()));
    dict.insert(
        "cdat".into(),
        date_value(candidate.created_at.unwrap_or(now)),
    );
    dict.insert(
        "mdat".into(),
        date_value(candidate.modified_at.unwrap_or(now)),
    );
    dict.insert("labl".into(), Value::String(candidate.rp_id.clone()));
    dict.insert("alis".into(), Value::Data(candidate.credential_id.clone()));
    let klbl = Sha1::digest(candidate.key.point);
    dict.insert("klbl".into(), Value::Data(klbl.to_vec()));
    dict.insert(
        "atag".into(),
        Value::Data(cbor_atag(
            &candidate.user_handle,
            &candidate.username,
            &candidate.user_display_name,
        )),
    );
    let mut v_data = Vec::with_capacity(97);
    v_data.extend_from_slice(&candidate.key.point);
    v_data.extend_from_slice(&candidate.key.scalar);
    dict.insert("v_Data".into(), Value::Data(v_data));
    let mut sha1 = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut sha1);
    dict.insert("sha1".into(), Value::Data(sha1.to_vec()));
    crate::ckks::plist_bytes(&Value::Dictionary(dict))
}

fn date_value(at: DateTime<Utc>) -> Value {
    Value::Date(plist::Date::from(std::time::SystemTime::from(at)))
}

/// Encode the `atag` CBOR map Apple stores: three text keys, with the user
/// handle as a byte string.
fn cbor_atag(user_handle: &[u8], username: &str, display_name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xA3);
    write_cbor_text(&mut out, "id");
    write_cbor_bytes(&mut out, user_handle);
    write_cbor_text(&mut out, "name");
    write_cbor_text(&mut out, username);
    write_cbor_text(&mut out, "displayName");
    write_cbor_text(&mut out, display_name);
    out
}

fn write_cbor_text(out: &mut Vec<u8>, text: &str) {
    write_cbor_head(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}

fn write_cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_cbor_head(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}

fn write_cbor_head(out: &mut Vec<u8>, major: u8, length: usize) {
    let prefix = major << 5;
    if length < 24 {
        out.push(prefix | length as u8);
    } else if length <= u8::MAX as usize {
        out.push(prefix | 24);
        out.push(length as u8);
    } else if length <= u16::MAX as usize {
        out.push(prefix | 25);
        out.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        out.push(prefix | 26);
        out.extend_from_slice(&(length as u32).to_be_bytes());
    }
}

/// Read one byte-string member out of a definite-length CBOR map. Only the
/// map shape Apple writes for `atag` is supported.
fn cbor_map_get(bytes: &[u8], wanted: &str) -> Option<Vec<u8>> {
    let (&head, mut rest) = bytes.split_first()?;
    if head >> 5 != 5 {
        return None;
    }
    let count = cbor_length(head & 0x1f, &mut rest)?;
    for _ in 0..count {
        let (&key_head, after) = rest.split_first()?;
        rest = after;
        if key_head >> 5 != 3 {
            return None;
        }
        let key_len = cbor_length(key_head & 0x1f, &mut rest)?;
        if rest.len() < key_len {
            return None;
        }
        let key = &rest[..key_len];
        rest = &rest[key_len..];
        let (&value_head, after) = rest.split_first()?;
        rest = after;
        let value_len = cbor_length(value_head & 0x1f, &mut rest)?;
        if rest.len() < value_len {
            return None;
        }
        let value = &rest[..value_len];
        rest = &rest[value_len..];
        if key == wanted.as_bytes() && value_head >> 5 == 2 {
            return Some(value.to_vec());
        }
    }
    None
}

fn cbor_length(additional: u8, rest: &mut &[u8]) -> Option<usize> {
    match additional {
        value @ 0..=23 => Some(value as usize),
        24 => {
            let (&value, tail) = rest.split_first()?;
            *rest = tail;
            Some(value as usize)
        }
        25 => {
            if rest.len() < 2 {
                return None;
            }
            let value = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            *rest = &rest[2..];
            Some(value)
        }
        26 => {
            if rest.len() < 4 {
                return None;
            }
            let value = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            *rest = &rest[4..];
            Some(value)
        }
        _ => None,
    }
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxf::PasskeyKey;
    use p256::pkcs8::EncodePrivateKey;

    fn candidate() -> Candidate {
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        let der = key.to_pkcs8_der().unwrap();
        let parsed = PasskeyKey::parse(der.as_bytes()).unwrap();
        Candidate {
            credential_id: vec![3; 32],
            rp_id: "webauthn.io".into(),
            username: "alice".into(),
            user_display_name: "Alice".into(),
            user_handle: vec![4; 16],
            key: parsed,
            created_at: DateTime::from_timestamp(1_700_000_000, 0),
            modified_at: DateTime::from_timestamp(1_700_000_100, 0),
        }
    }

    fn decode_item(bytes: &[u8]) -> Dictionary {
        plist::from_bytes::<Value>(bytes)
            .unwrap()
            .as_dictionary()
            .cloned()
            .unwrap()
    }

    #[test]
    fn passkey_plist_has_the_expected_fields() {
        let candidate = candidate();
        let bytes = passkey_plist(&candidate, Utc::now()).unwrap();
        let dict = decode_item(&bytes);

        assert_eq!(
            dict.get("agrp").and_then(Value::as_string),
            Some("com.apple.webkit.webauthn")
        );
        assert_eq!(dict.get("class").and_then(Value::as_string), Some("keys"));
        assert_eq!(dict.get("pdmn").and_then(Value::as_string), Some("ck"));
        assert_eq!(
            dict.get("type").and_then(Value::as_signed_integer),
            Some(73)
        );
        assert_eq!(
            dict.get("bsiz").and_then(Value::as_signed_integer),
            Some(256)
        );
        assert_eq!(
            dict.get("esiz").and_then(Value::as_signed_integer),
            Some(256)
        );
        assert_eq!(dict.get("kcls").and_then(Value::as_signed_integer), Some(1));
        assert_eq!(
            dict.get("labl").and_then(Value::as_string),
            Some("webauthn.io")
        );
        assert_eq!(
            dict.get("alis").and_then(Value::as_data),
            Some(candidate.credential_id.as_slice())
        );
        assert_eq!(
            dict.get("musr").and_then(Value::as_data),
            Some([].as_slice())
        );
        assert_eq!(dict.get("tomb").and_then(Value::as_signed_integer), Some(0));
        assert_eq!(
            dict.get("klbl").and_then(Value::as_data),
            Some(Sha1::digest(candidate.key.point).as_slice())
        );
        assert_eq!(
            dict.get("cdat").and_then(Value::as_date),
            Some(plist::Date::from(std::time::SystemTime::from(
                candidate.created_at.unwrap()
            )))
        );
        assert_eq!(
            dict.get("mdat").and_then(Value::as_date),
            Some(plist::Date::from(std::time::SystemTime::from(
                candidate.modified_at.unwrap()
            )))
        );
    }

    #[test]
    fn v_data_is_the_point_and_scalar() {
        let candidate = candidate();
        let dict = decode_item(&passkey_plist(&candidate, Utc::now()).unwrap());
        let v_data = dict.get("v_Data").and_then(Value::as_data).unwrap();

        assert_eq!(v_data.len(), 97);
        assert_eq!(v_data[0], 0x04);
        assert_eq!(&v_data[1..65], &candidate.key.point[1..]);
        assert_eq!(&v_data[65..], candidate.key.scalar.as_ref());
    }

    #[test]
    fn atag_is_a_cbor_map_with_the_user_handle() {
        let candidate = candidate();
        let dict = decode_item(&passkey_plist(&candidate, Utc::now()).unwrap());
        let atag = dict.get("atag").and_then(Value::as_data).unwrap();

        assert_eq!(
            cbor_map_get(atag, "id"),
            Some(candidate.user_handle.clone())
        );
        assert_eq!(cbor_map_get(atag, "name"), None);
        assert!(atag.starts_with(&[0xA3]));
    }
}
