//! CKKS record decryption.
//!
//! The unwrap chain is `tlkshare -> TLK -> synckey (class key) -> item key ->
//! item plist`. TLK shares use SF-ECIES with the peer encryption key; synckeys
//! and item keys use AES-256-SIV with no AAD; items authenticate their record
//! metadata in key order.

use std::collections::BTreeMap;
use std::time::SystemTime;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::KeyInit as AeadKeyInit;
use aes_siv::siv::Aes256Siv;
use base64::Engine;
use p384::ecdh::diffie_hellman;
use p384::{PublicKey, SecretKey};
use plist::{Dictionary, Value};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::cloudkit::{FieldValue, Record};
use crate::error::{Error, Result};
use crate::model::{Algorithm, Entry, EntryKind, Passkey, Totp};
use crate::wire::Reader;

const AAD_EXCLUDED: &[&str] = &[
    "gen",
    "pcspublickey",
    "UUID",
    "data",
    "pcsservice",
    "pcspublicidentity",
    "parentkeyref",
    "uploadver",
    "wrappedkey",
    "encver",
];

/// Unwrap every TLK share addressed to this peer.
pub fn unwrap_tlkshares(
    records: &[Record],
    peer_id: &str,
    encryption: &SecretKey,
) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let (mut matched, mut archive_fail, mut ecies_fail, mut parse_fail) = (0, 0, 0, 0);
    for record in records {
        if record.text("receiver") != Some(peer_id) {
            continue;
        }
        matched += 1;
        let Some(wrapped) = record.text("wrappedkey") else {
            continue;
        };
        let Ok(wrapped) = base64_decode(wrapped) else {
            continue;
        };
        let fields = match expand_archive(&wrapped) {
            Ok(fields) => fields,
            Err(error) => {
                if std::env::var_os("APW_DEBUG").is_some() && archive_fail == 0 {
                    eprintln!("ckks: archive error: {error}");
                }
                archive_fail += 1;
                continue;
            }
        };
        let (Some(ephemeral), Some(ciphertext), Some(tag)) = (
            fields.get("SFEphemeralSenderPublicKeyExternaRepresentation"),
            fields.get("SFCiphertext"),
            fields.get("SFIESAuthenticationCode"),
        ) else {
            continue;
        };

        let ciphertext = if ciphertext.len() > 113 {
            &ciphertext[..ciphertext.len() - 113]
        } else {
            ciphertext.as_slice()
        };
        let Ok(plaintext) = ecies_decrypt(encryption, ephemeral, ciphertext, tag) else {
            ecies_fail += 1;
            continue;
        };
        match parse_serialized_key(&plaintext) {
            Ok((uuid, key)) => {
                out.insert(uuid, key);
            }
            Err(_) => parse_fail += 1,
        }
    }
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "ckks: {peer_id} matched {matched}, archive {archive_fail}, ecies {ecies_fail}, parse {parse_fail}, ok {}",
            out.len()
        );
    }
    out
}

/// Unwrap each synckey with its parent TLK.
pub fn unwrap_class_keys(
    records: &[Record],
    tlks: &BTreeMap<String, Vec<u8>>,
) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for record in records {
        let Some(parent) = record.reference("parentkeyref") else {
            continue;
        };
        let Some(tlk) = tlks.get(parent) else {
            continue;
        };
        let Some(wrapped) = record.text("wrappedkey") else {
            continue;
        };
        let Ok(wrapped) = base64_decode(wrapped) else {
            continue;
        };
        if let Ok(key) = siv_unwrap(tlk, &wrapped) {
            out.insert(record.name.clone(), key);
        }
    }
    out
}

/// Everything a later push needs to address and re-seal one decrypted item.
pub struct RecordInfo {
    pub record_type: String,
    pub etag: Option<String>,
    pub parent: Option<String>,
    pub zone: Option<String>,
    pub owner: Option<String>,
    pub bplist: Vec<u8>,
}

/// Decrypt one item record into its padded-stripped plaintext and parsed plist.
///
/// Returns `None` when the record is structurally incomplete or its key or
/// plaintext does not decrypt.
pub fn decrypt_one(
    record: &Record,
    class_keys: &BTreeMap<String, Vec<u8>>,
) -> Option<(Vec<u8>, plist::Value)> {
    let parent = record.reference("parentkeyref")?;
    let class_key = class_keys.get(parent)?;
    let data = record.bytes("data")?;
    let wrapped = base64_decode(record.text("wrappedkey")?).ok()?;
    let item_key = siv_unwrap(class_key, &wrapped).ok()?;
    let headers = item_headers(record);
    let plaintext = decrypt_item(&item_key, data, &headers).ok()?;
    let value = plist::from_bytes::<Value>(&plaintext).ok()?;
    Some((plaintext, value))
}

/// Decrypted items plus the number that could not be decrypted.
pub struct Decrypted {
    pub values: Vec<(String, Value)>,
    /// Per-record information, keyed by CloudKit record name, for every item
    /// that decrypted.
    pub records: BTreeMap<String, RecordInfo>,
    /// Items whose class key was missing or whose key/plaintext failed to
    /// decrypt. Structural skips (`no_parent`, `no_data`, `no_wrapped`) are not
    /// counted as loss.
    pub lost: usize,
}

/// Decrypt every item whose class key is known.
pub fn decrypt_items(records: &[Record], class_keys: &BTreeMap<String, Vec<u8>>) -> Decrypted {
    let mut out = Vec::new();
    let mut records_out = BTreeMap::new();
    let (mut no_parent, mut no_key, mut no_data, mut no_wrapped, mut bad_key, mut bad_plain) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for record in records {
        let Some(parent) = record.reference("parentkeyref") else {
            no_parent += 1;
            continue;
        };
        let Some(class_key) = class_keys.get(parent) else {
            no_key += 1;
            continue;
        };
        if record.bytes("data").is_none() {
            no_data += 1;
            continue;
        }
        let Some(wrapped) = record.text("wrappedkey") else {
            no_wrapped += 1;
            continue;
        };
        let Some((_, value)) = decrypt_one(record, class_keys) else {
            // Classify the failure for the counters: a key that does not
            // unwrap is `bad_key`; anything else that got this far is
            // `bad_plain`.
            let bad_key_record = base64_decode(wrapped)
                .ok()
                .is_none_or(|wrapped| siv_unwrap(class_key, &wrapped).is_err());
            if bad_key_record {
                bad_key += 1;
            } else {
                bad_plain += 1;
            }
            continue;
        };
        records_out.insert(
            record.name.clone(),
            RecordInfo {
                record_type: record.record_type.clone(),
                etag: record.etag.clone(),
                parent: Some(parent.to_string()),
                zone: record.zone.clone(),
                owner: record.owner.clone(),
                bplist: plist_bytes(&value).unwrap_or_default(),
            },
        );
        out.push((record.name.clone(), value));
    }
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "ckks: items {} ok {}, no-parent {no_parent}, no-class-key {no_key}, no-data {no_data}, no-wrapped {no_wrapped}, bad-key {bad_key}, bad-plain {bad_plain}",
            records.len(),
            out.len()
        );
    }
    Decrypted {
        values: out,
        records: records_out,
        lost: no_key + bad_key + bad_plain,
    }
}

/// Split a `fetchRecoverableTlkshares` response into TLK share records and the
/// synckey records carried alongside them.
pub fn shares_from_response(data: &[u8]) -> Result<(Vec<Record>, Vec<Record>)> {
    let mut reader = Reader::new(data);
    let mut shares = Vec::new();
    let mut synckeys = Vec::new();
    while let Some(field) = reader.next()? {
        if field.number != 1 {
            continue;
        }
        let mut share = field.message()?;
        while let Some(item) = share.next()? {
            match item.number {
                2 => {
                    let mut view = item.message()?;
                    while let Some(entry) = view.next()? {
                        if matches!(entry.number, 1 | 2 | 3 | 5) {
                            if let Some(record) = record_wrapper(entry.bytes()?)? {
                                synckeys.push(record);
                            }
                        }
                    }
                }
                3 => {
                    if let Some(record) = record_wrapper(item.bytes()?)? {
                        shares.push(record);
                    }
                }
                _ => {}
            }
        }
    }
    Ok((shares, synckeys))
}

fn record_wrapper(data: &[u8]) -> Result<Option<Record>> {
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        if field.number == 2 {
            return Ok(Some(crate::cloudkit::parse_record(field.bytes()?)?));
        }
    }
    Ok(None)
}

/// Map a decrypted item plist to a vault entry.
pub fn entry_from_plist(record_name: &str, value: &Value) -> Option<Entry> {
    entry_from_plist_kind(record_name, value, None)
}

/// Build an entry, forcing the kind for records whose access group does not
/// name it. Wi-Fi items use the generic `apple` access group.
pub fn entry_from_plist_kind(
    record_name: &str,
    value: &Value,
    forced: Option<EntryKind>,
) -> Option<Entry> {
    let dict = value.as_dictionary()?;
    // A negative item records "never save for this site"; it is not a login.
    if dict
        .get("nega")
        .and_then(|value| {
            value
                .as_boolean()
                .or_else(|| value.as_signed_integer().map(|number| number != 0))
        })
        .unwrap_or(false)
    {
        return None;
    }
    // A tombstone is the keychain's deletion marker; it has no secret to show.
    let tomb = dict.get("tomb").and_then(|value| {
        value
            .as_signed_integer()
            .or_else(|| value.as_unsigned_integer().map(|number| number as i64))
    });
    if tomb.is_some_and(|tomb| tomb != 0) {
        return None;
    }
    let agrp = string(dict, "agrp").unwrap_or_default();
    let is_metadata = agrp == "com.apple.password-manager";
    let mut srvr = text(dict, "srvr");
    let mut acct = text(dict, "acct");
    let labl = text(dict, "labl");
    let data = dict.get("v_Data");

    // Older metadata records carry the join key only in the label.
    if is_metadata && (srvr.is_none() || acct.is_none()) {
        if let Some((label_srvr, label_acct)) = metadata_label(labl.as_deref()) {
            srvr = srvr.or(Some(label_srvr));
            acct = acct.or(Some(label_acct));
        }
    }

    let metadata = data
        .and_then(Value::as_data)
        .filter(|bytes| bytes.starts_with(b"bplist00"))
        .and_then(|bytes| plist::from_bytes::<Value>(bytes).ok())
        .and_then(|value| value.as_dictionary().cloned());

    let label_title = labl.filter(|label| {
        !label
            .to_lowercase()
            .starts_with("password manager metadata")
    });
    let title = metadata
        .as_ref()
        .and_then(|meta| text(meta, "customTitle").or_else(|| text(meta, "title")))
        .or(label_title)
        .or_else(|| srvr.clone());
    let notes = metadata
        .as_ref()
        .and_then(|meta| text(meta, "notes"))
        .or_else(|| string(dict, "notes"));

    let kind = forced.unwrap_or_else(|| {
        if agrp.contains("webauthn") {
            EntryKind::Passkey
        } else if agrp.contains("credit-cards") {
            EntryKind::Card
        } else if agrp.contains("wifi") {
            EntryKind::Wifi
        } else if srvr.is_some() {
            EntryKind::Login
        } else if agrp.contains("password-manager") || notes.is_some() {
            EntryKind::Note
        } else {
            EntryKind::Other
        }
    });

    let password = data.and_then(|value| match value {
        Value::String(text) => Some(text.clone()),
        Value::Data(bytes) => std::str::from_utf8(bytes).ok().map(str::to_string),
        _ => None,
    });

    let totp = metadata
        .as_ref()
        .and_then(|meta| meta.get("totp"))
        .and_then(Value::as_dictionary)
        .and_then(totp_from_dict);

    let passkey =
        (kind == EntryKind::Passkey).then(|| passkey_from_dict(dict, srvr.clone(), acct.clone()));

    let url = srvr.as_ref().map(|domain| format!("https://{domain}"));
    let sites = if kind == EntryKind::Wifi {
        acct.iter().cloned().collect()
    } else {
        srvr.iter().cloned().collect()
    };

    Some(Entry {
        id: record_name.to_string(),
        kind,
        agrp: Some(agrp),
        title,
        url,
        sites,
        username: acct,
        password: if matches!(kind, EntryKind::Login | EntryKind::Wifi) {
            password
        } else {
            None
        },
        notes,
        totp,
        passkey,
        group: None,
        updated_at: None,
        record: None,
    })
}

/// A passkey entry plus the material a CXF export needs, read straight from
/// the decrypted item plist.
fn passkey_from_dict(
    dict: &Dictionary,
    relying_party: Option<String>,
    username: Option<String>,
) -> Passkey {
    let (user_handle, user_name, user_display_name) = dict
        .get("atag")
        .and_then(Value::as_data)
        .map(passkey_atag)
        .unwrap_or_default();
    Passkey {
        relying_party,
        username: username.clone(),
        created_at: None,
        credential_id: data(dict, "alis"),
        private_key: data(dict, "v_Data"),
        user_handle,
        user_name: user_name.or(username),
        user_display_name,
    }
}

fn data(dict: &Dictionary, key: &str) -> Vec<u8> {
    dict.get(key)
        .and_then(Value::as_data)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// Decode the definite-length CBOR map Apple stores in `atag`. Only the three
/// members the exporter needs are read; an odd value just stops the walk.
pub(crate) fn passkey_atag(data: &[u8]) -> (Vec<u8>, Option<String>, Option<String>) {
    let mut out = (Vec::new(), None, None);
    let Some((major, count, mut rest)) = cbor_head(data) else {
        return out;
    };
    if major != 5 {
        return out;
    }
    for _ in 0..count {
        let Some((key_major, key_len, next)) = cbor_head(rest) else {
            break;
        };
        if key_major != 3 || next.len() < key_len {
            break;
        }
        let Ok(key) = std::str::from_utf8(&next[..key_len]) else {
            break;
        };
        rest = &next[key_len..];
        let Some((value_major, value_len, next)) = cbor_head(rest) else {
            break;
        };
        if next.len() < value_len {
            break;
        }
        let value = &next[..value_len];
        rest = &next[value_len..];
        match (key, value_major) {
            ("id", 2) => out.0 = value.to_vec(),
            ("name", 3) => out.1 = std::str::from_utf8(value).ok().map(str::to_string),
            ("displayName", 3) => out.2 = std::str::from_utf8(value).ok().map(str::to_string),
            _ => {}
        }
    }
    out
}

fn cbor_head(data: &[u8]) -> Option<(u8, usize, &[u8])> {
    let (&head, rest) = data.split_first()?;
    let major = head >> 5;
    let additional = head & 0x1f;
    let (length, rest) = match additional {
        value @ 0..=23 => (value as usize, rest),
        24 => {
            let (&value, rest) = rest.split_first()?;
            (value as usize, rest)
        }
        25 => {
            if rest.len() < 2 {
                return None;
            }
            (u16::from_be_bytes([rest[0], rest[1]]) as usize, &rest[2..])
        }
        26 => {
            if rest.len() < 4 {
                return None;
            }
            (
                u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize,
                &rest[4..],
            )
        }
        _ => return None,
    };
    Some((major, length, rest))
}

fn totp_from_dict(dict: &Dictionary) -> Option<Totp> {
    let secret = dict.get("secret")?;
    let secret = match secret {
        Value::Data(bytes) => data_encoding::BASE32_NOPAD.encode(bytes),
        Value::String(text) => text.clone(),
        _ => return None,
    };
    let algorithm = match dict.get("algorithm").and_then(Value::as_unsigned_integer) {
        Some(1) => Algorithm::Sha256,
        Some(2) => Algorithm::Sha512,
        _ => Algorithm::Sha1,
    };
    Some(Totp {
        secret,
        algorithm,
        digits: dict
            .get("digits")
            .and_then(Value::as_unsigned_integer)
            .unwrap_or(6) as u32,
        period: dict
            .get("period")
            .and_then(Value::as_unsigned_integer)
            .unwrap_or(30),
        issuer: string(dict, "issuer"),
        account_name: string(dict, "accountName"),
    })
}

fn item_headers(record: &Record) -> Vec<Vec<u8>> {
    aad_values(&record.name, &record.fields)
}

/// Build the ordered AAD values for an item record.
///
/// All names are collected into one `BTreeMap` and emitted in sorted key
/// order. `wrappedkey` carries the parent class key record name, not the
/// base64-wrapped item key.
pub(crate) fn aad_values(record_name: &str, fields: &BTreeMap<String, FieldValue>) -> Vec<Vec<u8>> {
    let mut aad = BTreeMap::new();
    aad.insert("UUID".to_string(), record_name.as_bytes().to_vec());
    aad.insert(
        "encver".to_string(),
        le8(field_int(fields, "encver").unwrap_or(2) as u64),
    );
    aad.insert(
        "gen".to_string(),
        le8(field_int(fields, "gen").unwrap_or(0) as u64),
    );
    if let Some(FieldValue::Reference(parent)) = fields.get("parentkeyref") {
        aad.insert("wrappedkey".to_string(), parent.as_bytes().to_vec());
    }
    if let Some(service) = field_int(fields, "pcsservice") {
        aad.insert("pcsservice".to_string(), le8(service as u64));
    }
    for name in ["pcspublickey", "pcspublicidentity"] {
        if let Some(FieldValue::Bytes(bytes)) = fields.get(name) {
            aad.insert(name.to_string(), bytes.clone());
        }
    }

    for (name, value) in fields {
        if AAD_EXCLUDED.contains(&name.as_str()) || name.starts_with("server_") {
            continue;
        }
        let bytes = match value {
            FieldValue::Text(text) => text.as_bytes().to_vec(),
            FieldValue::Bytes(bytes) => bytes.clone(),
            FieldValue::Int(number) => le8(*number as u64),
            FieldValue::Double(number) => le8(*number as i64 as u64),
            FieldValue::Date(seconds) => {
                let text = chrono::DateTime::from_timestamp(*seconds, 0)
                    .map(|date| date.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_default();
                text.into_bytes()
            }
            FieldValue::Reference(_) => continue,
        };
        aad.insert(name.clone(), bytes);
    }

    aad.into_values().collect()
}

fn field_int(fields: &BTreeMap<String, FieldValue>, name: &str) -> Option<i64> {
    match fields.get(name) {
        Some(FieldValue::Int(value) | FieldValue::Date(value)) => Some(*value),
        _ => None,
    }
}

fn decrypt_item(item_key: &[u8], data: &[u8], headers: &[Vec<u8>]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(Error::Message("item data is too short".into()));
    }
    let iv = &data[..16];
    let ciphertext = &data[16..];
    let mut values: Vec<&[u8]> = Vec::with_capacity(headers.len() + 1);
    values.push(iv);
    values.extend(headers.iter().map(Vec::as_slice));
    let plaintext = siv_unwrap_with(item_key, ciphertext, &values)?;
    Ok(strip_padding(&plaintext))
}

fn strip_padding(data: &[u8]) -> Vec<u8> {
    let mut end = data.len();
    while end > 0 {
        end -= 1;
        match data[end] {
            0x00 => continue,
            0x80 => return data[..end].to_vec(),
            _ => return data.to_vec(),
        }
    }
    data.to_vec()
}

/// A sealed keychain item: the record `data` blob (`iv || ciphertext`) and the
/// base64 class-key-wrapped item key.
pub struct SealedItem {
    pub data: Vec<u8>,
    pub wrappedkey: String,
}

/// Generate a fresh 64-byte item key.
pub fn random_item_key() -> [u8; 64] {
    random_bytes::<64>()
}

/// Seal a binary plist as a keychain item.
///
/// `aad` is the ordered AAD value list from [`aad_values`]. The IV is generated
/// here and becomes the first AAD value. The plaintext is padded with `0x80`
/// followed by zeros to a whole number of 20-byte blocks (at least two).
pub fn seal_item(
    item_key: &[u8],
    class_key: &[u8],
    aad: &[Vec<u8>],
    bplist: &[u8],
) -> Result<SealedItem> {
    if item_key.len() != 64 {
        return Err(Error::Message(format!(
            "item key must be 64 bytes, got {}",
            item_key.len()
        )));
    }
    if class_key.len() != 64 {
        return Err(Error::Message(format!(
            "class key must be 64 bytes, got {}",
            class_key.len()
        )));
    }

    let wrappedkey =
        base64::engine::general_purpose::STANDARD.encode(siv_wrap(class_key, item_key)?);

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let mut plaintext = bplist.to_vec();
    plaintext.push(0x80);
    let blocks = plaintext.len().div_ceil(20).max(2);
    plaintext.resize(blocks * 20, 0);

    let mut headers: Vec<&[u8]> = Vec::with_capacity(aad.len() + 1);
    headers.push(&iv);
    headers.extend(aad.iter().map(Vec::as_slice));
    let ciphertext = siv_wrap_with(item_key, &plaintext, &headers)?;

    let mut data = Vec::with_capacity(16 + ciphertext.len());
    data.extend_from_slice(&iv);
    data.extend_from_slice(&ciphertext);

    Ok(SealedItem { data, wrappedkey })
}

/// Serialize a plist value to binary plist bytes.
pub fn plist_bytes(value: &plist::Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, value)?;
    Ok(bytes)
}

/// The decrypted password-manager metadata dictionary carried in `v_Data`, as
/// binary plist bytes. Returns `None` for anything that is not a
/// `com.apple.password-manager` metadata item with a bplist `v_Data`.
pub fn metadata_bytes(value: &plist::Value) -> Option<Vec<u8>> {
    let dict = value.as_dictionary()?;
    // A sidecar keeps its access group when it moves to Recently Deleted;
    // the rest of the payload is unchanged.
    let agrp = dict
        .get("agrp")
        .and_then(Value::as_string)
        .unwrap_or_default();
    let agrp = agrp.strip_suffix("-recently-deleted").unwrap_or(agrp);
    if agrp != "com.apple.password-manager" {
        return None;
    }
    let data = dict.get("v_Data").and_then(Value::as_data)?;
    if !data.starts_with(b"bplist00") {
        return None;
    }
    let parsed = plist::from_bytes::<Value>(data).ok()?;
    parsed.as_dictionary()?;
    plist_bytes(&parsed).ok()
}

/// Build a create-only personal login item plist.
pub fn new_login_plist(site: &str, username: &str, password: &[u8]) -> plist::Value {
    let mut dict = Dictionary::new();
    dict.insert("labl".into(), Value::String(format!("{site} ({username})")));
    dict.insert("acct".into(), Value::String(username.into()));
    dict.insert("srvr".into(), Value::String(site.into()));
    dict.insert("ptcl".into(), Value::String("htps".into()));
    dict.insert("atyp".into(), Value::String("form".into()));
    dict.insert("v_Data".into(), Value::Data(password.to_vec()));
    dict.insert("cdat".into(), now_date());
    dict.insert("mdat".into(), now_date());
    dict.insert("agrp".into(), Value::String("com.apple.cfnetwork".into()));
    dict.insert("pdmn".into(), Value::String("ak".into()));
    dict.insert("path".into(), Value::String(String::new()));
    dict.insert("desc".into(), Value::String("Web form password".into()));
    dict.insert("sdmn".into(), Value::String(String::new()));
    dict.insert("port".into(), Value::from(0i64));
    dict.insert("tomb".into(), Value::from(0i64));
    dict.insert("sha1".into(), Value::Data(random_bytes::<20>().to_vec()));
    dict.insert("musr".into(), Value::Data(Vec::new()));
    dict.insert("class".into(), Value::String("inet".into()));
    Value::Dictionary(dict)
}

/// Build a create-only Wi-Fi item plist.
///
/// Apple stores Wi-Fi credentials as a generic password in the `WiFi` zone
/// with the access group `apple` and the service name `AirPort`. The key set
/// matches a live account record exactly; no sidecar exists for these.
pub fn new_wifi_plist(ssid: &str, password: &[u8]) -> plist::Value {
    let mut dict = Dictionary::new();
    dict.insert("acct".into(), Value::String(ssid.into()));
    dict.insert("agrp".into(), Value::String("apple".into()));
    dict.insert("cdat".into(), now_date());
    dict.insert("class".into(), Value::String("genp".into()));
    dict.insert(
        "desc".into(),
        Value::String("AirPort network password".into()),
    );
    dict.insert("labl".into(), Value::String(ssid.into()));
    dict.insert("mdat".into(), now_date());
    dict.insert("musr".into(), Value::Data(Vec::new()));
    dict.insert("pdmn".into(), Value::String("ck".into()));
    dict.insert("sha1".into(), Value::Data(random_bytes::<20>().to_vec()));
    dict.insert("svce".into(), Value::String("AirPort".into()));
    dict.insert("tomb".into(), Value::from(0i64));
    dict.insert("v_Data".into(), Value::Data(password.to_vec()));
    Value::Dictionary(dict)
}

/// Build a create-only note item plist.
///
/// Apple writes a note as a login-shaped `inet` stub whose site is a fresh
/// UUID. The label and server are `<uuid> ()` and the secret is empty; the
/// title and body live in the sidecar metadata record.
pub fn new_note_item_plist(site_uuid: &str) -> plist::Value {
    let mut dict = Dictionary::new();
    dict.insert("acct".into(), Value::String(String::new()));
    dict.insert("agrp".into(), Value::String("com.apple.cfnetwork".into()));
    dict.insert("atyp".into(), Value::String("form".into()));
    dict.insert("cdat".into(), now_date());
    dict.insert("class".into(), Value::String("inet".into()));
    dict.insert("desc".into(), Value::String("Web form password".into()));
    dict.insert("labl".into(), Value::String(format!("{site_uuid} ()")));
    dict.insert("mdat".into(), now_date());
    dict.insert("musr".into(), Value::Data(Vec::new()));
    dict.insert("path".into(), Value::String(String::new()));
    dict.insert("pdmn".into(), Value::String("ak".into()));
    dict.insert("port".into(), Value::from(0i64));
    dict.insert("ptcl".into(), Value::String("htps".into()));
    dict.insert("sdmn".into(), Value::String(String::new()));
    dict.insert("sha1".into(), Value::Data(random_bytes::<20>().to_vec()));
    dict.insert("srvr".into(), Value::String(site_uuid.into()));
    dict.insert("tomb".into(), Value::from(0i64));
    dict.insert("v_Data".into(), Value::Data(Vec::new()));
    Value::Dictionary(dict)
}

/// Write a one-time-code dictionary into password-manager metadata.
///
/// The shape matches what Apple writes for a login with an authenticator:
/// raw base32-decoded secret bytes, `algorithm` as 0/1/2, and `_initialDate`
/// pinned to the Unix epoch so the counter is plain TOTP time.
pub fn set_metadata_totp(
    metadata: &mut Dictionary,
    spec: &crate::totp::TotpSpec,
    now: chrono::DateTime<chrono::Utc>,
) {
    // `now` keeps callers on one clock with the surrounding metadata writes;
    // Apple pins `_initialDate` to the epoch rather than the creation time.
    let _ = now;
    let mut totp = Dictionary::new();
    totp.insert("secret".into(), Value::Data(spec.secret.clone()));
    totp.insert("digits".into(), Value::from(u64::from(spec.digits)));
    totp.insert("period".into(), Value::from(u64::from(spec.period)));
    totp.insert("algorithm".into(), Value::from(u64::from(spec.algorithm)));
    totp.insert(
        "_initialDate".into(),
        Value::Date(plist::Date::from(std::time::UNIX_EPOCH)),
    );
    if let Some(issuer) = &spec.issuer {
        totp.insert("issuer".into(), Value::String(issuer.clone()));
    }
    if let Some(account) = &spec.account_name {
        totp.insert("accountName".into(), Value::String(account.clone()));
    }
    if let Some(url) = &spec.original_url {
        totp.insert("originalURL".into(), Value::String(url.clone()));
    }
    metadata.insert("totp".into(), Value::Dictionary(totp));
}

/// A fresh, empty password-manager metadata dictionary.
pub fn new_metadata_dict() -> Dictionary {
    Dictionary::new()
}

/// Build a create-only password-manager metadata item plist. `metadata` is
/// serialized as binary plist into `v_Data`.
pub fn new_metadata_plist(site: &str, username: &str, metadata: &Dictionary) -> plist::Value {
    let mut dict = Dictionary::new();
    dict.insert(
        "labl".into(),
        Value::String(format!("Password Manager Metadata: {site} ({username})")),
    );
    dict.insert("acct".into(), Value::String(username.into()));
    dict.insert("srvr".into(), Value::String(site.into()));
    let data = plist_bytes(&Value::Dictionary(metadata.clone())).unwrap_or_default();
    dict.insert("v_Data".into(), Value::Data(data));
    dict.insert("atyp".into(), Value::String("form".into()));
    dict.insert("path".into(), Value::String(String::new()));
    dict.insert("type".into(), Value::from(1_835_626_085i64));
    dict.insert(
        "desc".into(),
        Value::String("Password Manager Metadata".into()),
    );
    dict.insert("sdmn".into(), Value::String(String::new()));
    dict.insert("cdat".into(), now_date());
    dict.insert("mdat".into(), now_date());
    dict.insert("pdmn".into(), Value::String("ak".into()));
    dict.insert("ptcl".into(), Value::String("htps".into()));
    dict.insert(
        "agrp".into(),
        Value::String("com.apple.password-manager".into()),
    );
    dict.insert("port".into(), Value::from(0i64));
    dict.insert("tomb".into(), Value::from(0i64));
    dict.insert("sha1".into(), Value::Data(random_bytes::<20>().to_vec()));
    dict.insert("musr".into(), Value::Data(Vec::new()));
    dict.insert("class".into(), Value::String("inet".into()));
    Value::Dictionary(dict)
}

/// Metadata text fields (`title`, `notes`) are plist data holding UTF-8 bytes.
pub fn set_metadata_text(metadata: &mut Dictionary, key: &str, value: &str) {
    metadata.insert(key.into(), Value::Data(value.as_bytes().to_vec()));
}

/// Append a password-change history entry to `s_hi`, keeping existing entries.
pub fn append_password_change(
    metadata: &mut Dictionary,
    new_password: &str,
    old_password: &str,
    now: chrono::DateTime<chrono::Utc>,
) {
    let mut change = Dictionary::new();
    change.insert("d".into(), date_value(now));
    change.insert("p".into(), Value::String(new_password.into()));
    change.insert("op".into(), Value::String(old_password.into()));
    change.insert("id".into(), Value::String(uuid_v4()));
    change.insert("t".into(), Value::String("pwch".into()));

    let mut history = match metadata.remove("s_hi") {
        Some(Value::Array(entries)) => entries,
        _ => Vec::new(),
    };
    history.push(Value::Dictionary(change));
    metadata.insert("s_hi".into(), Value::Array(history));
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn now_date() -> Value {
    Value::Date(plist::Date::from(SystemTime::now()))
}

fn date_value(now: chrono::DateTime<chrono::Utc>) -> Value {
    Value::Date(plist::Date::from(SystemTime::from(now)))
}

fn uuid_v4() -> String {
    let mut bytes = random_bytes::<16>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
    .to_uppercase()
}

fn siv_unwrap(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    siv_unwrap_with(key, ciphertext, &[])
}

fn siv_wrap(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    siv_wrap_with(key, plaintext, &[])
}

fn siv_wrap_with(key: &[u8], plaintext: &[u8], headers: &[&[u8]]) -> Result<Vec<u8>> {
    let mut cipher =
        Aes256Siv::new_from_slice(key).map_err(|_| Error::Message("invalid AES-SIV key".into()))?;
    cipher
        .encrypt(headers.iter().copied(), plaintext)
        .map_err(|_| Error::Message("AES-SIV encrypt failed".into()))
}

fn siv_unwrap_with(key: &[u8], ciphertext: &[u8], headers: &[&[u8]]) -> Result<Vec<u8>> {
    let mut cipher =
        Aes256Siv::new_from_slice(key).map_err(|_| Error::Message("invalid AES-SIV key".into()))?;
    cipher
        .decrypt(headers.iter().copied(), ciphertext)
        .map_err(|_| Error::Message("AES-SIV decrypt failed".into()))
}

fn ecies_decrypt(
    key: &SecretKey,
    ephemeral: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let public = PublicKey::from_sec1_bytes(ephemeral)
        .map_err(|error| Error::Message(format!("invalid ephemeral P-384 key: {error}")))?;
    let shared = diffie_hellman(key.to_nonzero_scalar(), public.as_affine());
    let secret = shared.raw_secret_bytes();
    let derived = x963_kdf(secret.as_slice(), ephemeral, 48);
    use aes_gcm::aead::consts::U16;
    use aes_gcm::aead::generic_array::GenericArray;

    type Aes256Gcm16 = aes_gcm::AesGcm<aes::Aes256, U16>;
    let cipher = Aes256Gcm16::new_from_slice(&derived[..32])
        .map_err(|_| Error::Message("invalid ECIES key".into()))?;
    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(tag);
    cipher
        .decrypt(
            GenericArray::<u8, U16>::from_slice(&derived[32..48]),
            Payload {
                msg: &combined,
                aad: &[],
            },
        )
        .map_err(|_| Error::Message("ECIES decrypt failed".into()))
}

fn x963_kdf(secret: &[u8], shared_info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 1u32;
    while out.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(counter.to_be_bytes());
        hasher.update(shared_info);
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

fn parse_serialized_key(data: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut reader = Reader::new(data);
    let mut uuid = String::new();
    let mut key = Vec::new();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => uuid = field.string()?.to_string(),
            4 => key = field.bytes()?.to_vec(),
            _ => {}
        }
    }
    if uuid.is_empty() || key.is_empty() {
        return Err(Error::Message("TLK share has no serialized key".into()));
    }
    Ok((uuid, key))
}

/// Expand an NSKeyedArchiver plist into the string-keyed objects it wraps.
fn expand_archive(data: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let value: Value = plist::from_bytes(data)?;
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::Message("archive is not a dictionary".into()))?;
    let objects = dict
        .get("$objects")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Message("archive has no objects".into()))?;
    let top = dict
        .get("$top")
        .and_then(Value::as_dictionary)
        .ok_or_else(|| Error::Message("archive has no top".into()))?;

    if top.get("root").is_none() {
        let mut out = BTreeMap::new();
        for (name, value) in top {
            if let Some(bytes) = archive_bytes(resolve(objects, value)?) {
                out.insert(name.clone(), bytes);
            }
        }
        return Ok(out);
    }

    let root = resolve(objects, top.get("root").expect("checked"))?;
    let root = root
        .as_dictionary()
        .ok_or_else(|| Error::Message("archive root is not a dictionary".into()))?;

    let mut out = BTreeMap::new();
    if let (Some(keys), Some(values)) = (
        root.get("NS.keys").and_then(Value::as_array),
        root.get("NS.objects").and_then(Value::as_array),
    ) {
        for (key, value) in keys.iter().zip(values) {
            let name = resolve(objects, key)?
                .as_string()
                .ok_or_else(|| Error::Message("archive key is not a string".into()))?;
            if let Some(bytes) = archive_bytes(resolve(objects, value)?) {
                out.insert(name.to_string(), bytes);
            }
        }
        return Ok(out);
    }

    for (name, value) in root {
        if let Some(bytes) = archive_bytes(value) {
            out.insert(name.clone(), bytes);
        }
    }
    Ok(out)
}

fn resolve<'a>(objects: &'a [Value], value: &'a Value) -> Result<&'a Value> {
    match value {
        Value::Uid(uid) => objects
            .get(uid.get() as usize)
            .ok_or_else(|| Error::Message("archive reference is out of range".into())),
        other => Ok(other),
    }
}

fn archive_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Data(bytes) => Some(bytes.clone()),
        Value::Dictionary(dict) => dict
            .get("NS.data")
            .and_then(Value::as_data)
            .map(<[u8]>::to_vec),
        _ => None,
    }
}

/// Metadata strings are sometimes stored as UTF-8 data rather than a plist
/// string.
/// Split `Password Manager Metadata: <srvr> (<acct>)` into its join key.
fn metadata_label(label: Option<&str>) -> Option<(String, String)> {
    let label = label?;
    let label = label
        .strip_prefix("Password Manager Metadata:")
        .or_else(|| label.strip_prefix("Password Manager Metadata: "))
        .map(str::trim)
        .unwrap_or(label.trim());
    let (srvr, acct) = label.rsplit_once(" (")?;
    let acct = acct.strip_suffix(')')?;
    if srvr.is_empty() || acct.is_empty() {
        return None;
    }
    Some((srvr.to_string(), acct.to_string()))
}

#[cfg(test)]
mod label_tests {
    use super::metadata_label;

    #[test]
    fn parses_the_metadata_label() {
        assert_eq!(
            metadata_label(Some(
                "Password Manager Metadata: accounts.google.com (me@gmail.com)"
            )),
            Some(("accounts.google.com".into(), "me@gmail.com".into()))
        );
    }

    #[test]
    fn rejects_other_labels() {
        assert_eq!(metadata_label(Some("Google")), None);
        assert_eq!(metadata_label(None), None);
    }
}

fn text(dict: &Dictionary, key: &str) -> Option<String> {
    match dict.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Data(bytes) => String::from_utf8(bytes.clone()).ok(),
        _ => None,
    }
}

fn string(dict: &Dictionary, key: &str) -> Option<String> {
    dict.get(key).and_then(Value::as_string).map(str::to_string)
}

fn le8(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Message(format!("invalid base64 in CKKS record: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siv_round_trip() {
        let key = [4u8; 64];
        let ciphertext = {
            let mut cipher = Aes256Siv::new_from_slice(&key).unwrap();
            cipher
                .encrypt([b"iv".as_slice()], b"password".as_slice())
                .unwrap()
        };
        let plaintext = siv_unwrap_with(&key, &ciphertext, &[b"iv"]).unwrap();
        assert_eq!(plaintext, b"password");
    }

    #[test]
    fn strips_iso_padding() {
        assert_eq!(strip_padding(b"secret\x80\x00\x00"), b"secret");
        assert_eq!(strip_padding(b"secret"), b"secret");
    }

    #[test]
    fn a_tombstone_plist_is_not_an_entry() {
        let mut item = new_login_plist("example.com", "alice", b"secret")
            .as_dictionary()
            .cloned()
            .expect("dictionary");
        item.insert("tomb".into(), Value::from(1i64));

        assert!(entry_from_plist("item-1", &Value::Dictionary(item.clone())).is_none());

        item.insert("tomb".into(), Value::from(0i64));
        assert!(entry_from_plist("item-1", &Value::Dictionary(item)).is_some());
    }

    #[test]
    fn expands_an_archive() {
        let mut root = Dictionary::new();
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for index in 0..2 {
            keys.push(Value::Uid(plist::Uid::new(index + 1)));
            values.push(Value::Uid(plist::Uid::new(3)));
        }
        root.insert("NS.keys".into(), Value::Array(keys));
        root.insert("NS.objects".into(), Value::Array(values));

        let mut data = Dictionary::new();
        data.insert("NS.data".into(), Value::Data(vec![1, 2, 3]));

        let objects = vec![
            Value::String("$null".into()),
            Value::String("SFCiphertext".into()),
            Value::String("SFIESAuthenticationCode".into()),
            Value::Dictionary(data),
            Value::Dictionary(root),
        ];
        let mut top = Dictionary::new();
        top.insert("root".into(), Value::Uid(plist::Uid::new(4)));
        let mut archive = Dictionary::new();
        archive.insert("$objects".into(), Value::Array(objects));
        archive.insert("$top".into(), Value::Dictionary(top));
        archive.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));

        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &Value::Dictionary(archive)).unwrap();
        let expanded = expand_archive(&bytes).unwrap();
        assert_eq!(expanded.get("SFCiphertext"), Some(&vec![1, 2, 3]));
    }

    fn item_record(name: &str, fields: BTreeMap<String, FieldValue>) -> Record {
        Record {
            name: name.into(),
            zone: None,
            owner: None,
            etag: None,
            record_type: "item".into(),
            fields,
            plugin_fields: Vec::new(),
            protection_info: None,
            permission: None,
            pcs_key: None,
            share_info: None,
            share_id: None,
            stable_url: None,
        }
    }

    fn sealed_record(
        record_name: &str,
        parent: &str,
        value: &plist::Value,
    ) -> (Record, [u8; 64], [u8; 64]) {
        let item_key = random_item_key();
        let class_key = [9u8; 64];
        let mut fields: BTreeMap<String, FieldValue> = [
            ("gen".to_string(), FieldValue::Int(0)),
            ("encver".to_string(), FieldValue::Int(2)),
            (
                "parentkeyref".to_string(),
                FieldValue::Reference(parent.into()),
            ),
            (
                "uploadver".to_string(),
                FieldValue::Text("iphone 21.6.0 (19H384)".into()),
            ),
            (
                "acct".to_string(),
                FieldValue::Text("me@example.com".into()),
            ),
        ]
        .into_iter()
        .collect();

        let aad = aad_values(record_name, &fields);
        let bplist = plist_bytes(value).unwrap();
        let sealed = seal_item(&item_key, &class_key, &aad, &bplist).unwrap();
        fields.insert("wrappedkey".into(), FieldValue::Text(sealed.wrappedkey));
        fields.insert("data".into(), FieldValue::Bytes(sealed.data));

        (item_record(record_name, fields), item_key, class_key)
    }

    fn open(record: &Record, item_key: &[u8]) -> Result<plist::Value> {
        let headers = item_headers(record);
        let data = record.bytes("data").expect("data field");
        let plaintext = decrypt_item(item_key, data, &headers)?;
        Ok(plist::from_bytes(&plaintext)?)
    }

    #[test]
    fn aad_values_follow_sorted_field_order() {
        let fields: BTreeMap<String, FieldValue> = [
            (
                "acct".to_string(),
                FieldValue::Text("me@example.com".into()),
            ),
            ("cdat".to_string(), FieldValue::Date(1_700_000_000)),
            ("encver".to_string(), FieldValue::Int(2)),
            ("gen".to_string(), FieldValue::Int(3)),
            (
                "parentkeyref".to_string(),
                FieldValue::Reference("class-key".into()),
            ),
            ("labl".to_string(), FieldValue::Text("Example".into())),
            ("pcsservice".to_string(), FieldValue::Int(7)),
        ]
        .into_iter()
        .collect();

        let expected = vec![
            b"item-1".to_vec(),
            b"me@example.com".to_vec(),
            b"2023-11-14T22:13:20Z".to_vec(),
            2u64.to_le_bytes().to_vec(),
            3u64.to_le_bytes().to_vec(),
            b"Example".to_vec(),
            7u64.to_le_bytes().to_vec(),
            b"class-key".to_vec(),
        ];
        assert_eq!(aad_values("item-1", &fields), expected);

        // Insertion order must not matter: the output is key-sorted.
        let shuffled: BTreeMap<String, FieldValue> = fields
            .iter()
            .rev()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(aad_values("item-1", &shuffled), expected);
    }

    #[test]
    fn seals_and_decrypts_plists() {
        let values = [
            plist::Value::Dictionary(Dictionary::new()),
            plist::Value::String("x".repeat(56)),
        ];
        for value in values {
            let (record, item_key, class_key) = sealed_record("item-1", "class-key", &value);
            assert_eq!(open(&record, &item_key).unwrap(), value);

            let wrapped = base64_decode(record.text("wrappedkey").unwrap()).unwrap();
            assert_eq!(siv_unwrap(&class_key, &wrapped).unwrap(), item_key);
        }
    }

    #[test]
    fn padding_adds_a_block() {
        let value = plist::Value::String("x".repeat(56));
        let bplist = plist_bytes(&value).unwrap();
        assert!(
            (90..=110).contains(&bplist.len()),
            "expected a ~100-byte plist, got {}",
            bplist.len()
        );
        assert_ne!((bplist.len() + 1) % 20, 0);

        let (record, item_key, _) = sealed_record("item-1", "class-key", &value);
        let data = record.bytes("data").unwrap();
        let padded = data.len() - 16 - 16;
        assert_eq!(padded % 20, 0);
        assert!(padded > bplist.len() + 1);
        assert_eq!(open(&record, &item_key).unwrap(), value);
    }

    #[test]
    fn tampering_breaks_decryption() {
        let value = plist::Value::String("secret".into());
        let (record, item_key, _) = sealed_record("item-1", "class-key", &value);

        let mut flipped = record.clone();
        if let Some(FieldValue::Bytes(data)) = flipped.fields.get_mut("data") {
            data[20] ^= 0x01;
        }
        assert!(open(&flipped, &item_key).is_err());

        let mut reparented = record.clone();
        reparented
            .fields
            .insert("parentkeyref".into(), FieldValue::Reference("other".into()));
        assert!(open(&reparented, &item_key).is_err());

        assert_eq!(open(&record, &item_key).unwrap(), value);
    }

    #[test]
    fn appends_password_change_history() {
        let mut metadata = new_metadata_dict();
        let mut existing = Dictionary::new();
        existing.insert("p".into(), Value::String("old".into()));
        existing.insert("t".into(), Value::String("pwcr".into()));
        metadata.insert(
            "s_hi".into(),
            Value::Array(vec![Value::Dictionary(existing.clone())]),
        );

        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        append_password_change(&mut metadata, "new", "old", now);

        let history = metadata.get("s_hi").and_then(Value::as_array).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], Value::Dictionary(existing));

        let change = history[1].as_dictionary().unwrap();
        assert_eq!(change.get("p").and_then(Value::as_string), Some("new"));
        assert_eq!(change.get("op").and_then(Value::as_string), Some("old"));
        assert_eq!(change.get("t").and_then(Value::as_string), Some("pwch"));
        assert_eq!(change.get("d"), Some(&date_value(now)));
        let id = change.get("id").and_then(Value::as_string).unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id, id.to_uppercase());

        let mut fresh = new_metadata_dict();
        append_password_change(&mut fresh, "first", "", now);
        assert_eq!(
            fresh.get("s_hi").and_then(Value::as_array).unwrap().len(),
            1
        );
    }

    fn key_set(value: &plist::Value) -> std::collections::BTreeSet<String> {
        value.as_dictionary().unwrap().keys().cloned().collect()
    }

    #[test]
    fn login_plist_has_the_expected_keys() {
        let value = new_login_plist("example.com", "me", b"hunter2");
        let expected: std::collections::BTreeSet<String> = [
            "labl", "acct", "srvr", "ptcl", "atyp", "v_Data", "cdat", "mdat", "agrp", "pdmn",
            "path", "desc", "sdmn", "port", "tomb", "sha1", "musr", "class",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(key_set(&value), expected);
    }

    #[test]
    fn metadata_plist_has_the_expected_keys() {
        let metadata = new_metadata_dict();
        let value = new_metadata_plist("example.com", "me", &metadata);
        let expected: std::collections::BTreeSet<String> = [
            "labl", "acct", "srvr", "v_Data", "atyp", "path", "type", "desc", "sdmn", "cdat",
            "mdat", "pdmn", "ptcl", "agrp", "port", "tomb", "sha1", "musr", "class",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(key_set(&value), expected);
    }

    #[test]
    fn wifi_plist_has_the_observed_keys() {
        let value = new_wifi_plist("HomeNet", b"hunter2");
        let expected: std::collections::BTreeSet<String> = [
            "acct", "agrp", "cdat", "class", "desc", "labl", "mdat", "musr", "pdmn", "sha1",
            "svce", "tomb", "v_Data",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(key_set(&value), expected);

        let dict = value.as_dictionary().unwrap();
        assert_eq!(dict.get("svce").and_then(Value::as_string), Some("AirPort"));
        assert_eq!(dict.get("class").and_then(Value::as_string), Some("genp"));
        assert_eq!(dict.get("acct").and_then(Value::as_string), Some("HomeNet"));
        assert_eq!(dict.get("labl").and_then(Value::as_string), Some("HomeNet"));
        assert_eq!(
            dict.get("v_Data").and_then(Value::as_data),
            Some(b"hunter2".as_slice())
        );
    }

    #[test]
    fn note_plist_is_a_stub_with_a_matching_site() {
        let site = "6F1C2A4E-0B7D-4C3A-9E55-1234567890AB";
        let value = new_note_item_plist(site);
        let expected: std::collections::BTreeSet<String> = [
            "acct", "agrp", "atyp", "cdat", "class", "desc", "labl", "mdat", "musr", "path",
            "pdmn", "port", "ptcl", "sdmn", "sha1", "srvr", "tomb", "v_Data",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(key_set(&value), expected);

        let dict = value.as_dictionary().unwrap();
        assert_eq!(dict.get("srvr").and_then(Value::as_string), Some(site));
        let label = dict.get("labl").and_then(Value::as_string).unwrap();
        assert_eq!(label, format!("{site} ()"));
        assert_eq!(
            dict.get("v_Data").and_then(Value::as_data).map(<[u8]>::len),
            Some(0)
        );
    }

    #[test]
    fn totp_metadata_round_trips_through_the_reader() {
        let spec = crate::totp::TotpSpec {
            secret: b"Hello!\xde\xad\xbe\xef".to_vec(),
            digits: 8,
            period: 60,
            algorithm: 1,
            issuer: Some("Example".into()),
            account_name: Some("alice".into()),
            original_url: Some("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP".into()),
        };
        let mut metadata = new_metadata_dict();
        set_metadata_totp(&mut metadata, &spec, chrono::Utc::now());

        let dict = metadata
            .get("totp")
            .and_then(Value::as_dictionary)
            .expect("totp dictionary");
        let parsed = totp_from_dict(dict).expect("reads back");
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period, 60);
        assert_eq!(parsed.algorithm, Algorithm::Sha256);
        assert_eq!(parsed.issuer.as_deref(), Some("Example"));
        assert_eq!(parsed.account_name.as_deref(), Some("alice"));
        assert!(dict.get("_initialDate").is_some());
        assert_eq!(
            dict.get("originalURL").and_then(Value::as_string),
            Some("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP")
        );
    }
}

#[cfg(test)]
mod trash_metadata_tests {
    use super::{metadata_bytes, plist_bytes};
    use plist::{Dictionary, Value};

    #[test]
    fn reads_metadata_from_a_trashed_sidecar() {
        let mut metadata = Dictionary::new();
        metadata.insert("title".into(), Value::Data(b"Stored name".to_vec()));
        let inner = plist_bytes(&Value::Dictionary(metadata)).unwrap();

        let mut outer = Dictionary::new();
        outer.insert(
            "agrp".into(),
            Value::String("com.apple.password-manager-recently-deleted".into()),
        );
        outer.insert("v_Data".into(), Value::Data(inner));

        assert!(metadata_bytes(&Value::Dictionary(outer)).is_some());
    }
}
