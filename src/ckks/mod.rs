//! CKKS record decryption.
//!
//! The unwrap chain is `tlkshare -> TLK -> synckey (class key) -> item key ->
//! item plist`. TLK shares use SF-ECIES with the peer encryption key; synckeys
//! and item keys use AES-256-SIV with no AAD; items authenticate their record
//! metadata in key order.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::KeyInit as AeadKeyInit;
use aes_siv::siv::Aes256Siv;
use base64::Engine;
use p384::ecdh::diffie_hellman;
use p384::{PublicKey, SecretKey};
use plist::{Dictionary, Value};
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

/// Decrypt every item whose class key is known.
pub fn decrypt_items(
    records: &[Record],
    class_keys: &BTreeMap<String, Vec<u8>>,
) -> Vec<(String, Value)> {
    let mut out = Vec::new();
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
        let Some(data) = record.bytes("data") else {
            no_data += 1;
            continue;
        };
        let Some(wrapped) = record.text("wrappedkey") else {
            no_wrapped += 1;
            continue;
        };
        let Ok(wrapped) = base64_decode(wrapped) else {
            bad_key += 1;
            continue;
        };
        let Ok(item_key) = siv_unwrap(class_key, &wrapped) else {
            bad_key += 1;
            continue;
        };
        let headers = item_headers(record);
        match decrypt_item(&item_key, data, &headers)
            .ok()
            .and_then(|plaintext| plist::from_bytes::<Value>(&plaintext).ok())
        {
            Some(value) => out.push((record.name.clone(), value)),
            None => bad_plain += 1,
        }
    }
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "ckks: items {} ok {}, no-parent {no_parent}, no-class-key {no_key}, no-data {no_data}, no-wrapped {no_wrapped}, bad-key {bad_key}, bad-plain {bad_plain}",
            records.len(),
            out.len()
        );
    }
    out
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
    let agrp = string(dict, "agrp").unwrap_or_default();
    let srvr = string(dict, "srvr");
    let acct = string(dict, "acct");
    let labl = string(dict, "labl");
    let data = dict.get("v_Data");

    let metadata = data
        .and_then(Value::as_data)
        .filter(|bytes| bytes.starts_with(b"bplist00"))
        .and_then(|bytes| plist::from_bytes::<Value>(bytes).ok())
        .and_then(|value| value.as_dictionary().cloned());

    let title = metadata
        .as_ref()
        .and_then(|meta| text(meta, "customTitle").or_else(|| text(meta, "title")))
        .or(labl)
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

    let passkey = (kind == EntryKind::Passkey).then(|| Passkey {
        relying_party: srvr.clone(),
        username: acct.clone(),
        created_at: None,
    });

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
    })
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
    let mut aad = BTreeMap::new();
    aad.insert("UUID".to_string(), record.name.as_bytes().to_vec());
    aad.insert(
        "encver".to_string(),
        le8(record.int("encver").unwrap_or(2) as u64),
    );
    aad.insert(
        "gen".to_string(),
        le8(record.int("gen").unwrap_or(0) as u64),
    );
    if let Some(parent) = record.reference("parentkeyref") {
        aad.insert("wrappedkey".to_string(), parent.as_bytes().to_vec());
    }
    if let Some(service) = record.int("pcsservice") {
        aad.insert("pcsservice".to_string(), le8(service as u64));
    }
    for name in ["pcspublickey", "pcspublicidentity"] {
        if let Some(bytes) = record.bytes(name) {
            aad.insert(name.to_string(), bytes.to_vec());
        }
    }

    for (name, value) in &record.fields {
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

fn siv_unwrap(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    siv_unwrap_with(key, ciphertext, &[])
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
}
