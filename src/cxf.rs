//! Credential Exchange Format (CXF) 1.0 parsing for `apw passkey import`.
//!
//! The file is parsed into typed structs that ignore unknown fields, then every
//! passkey credential is validated into a [`Candidate`]. A bad credential is a
//! skipped row, never a parse error: only an unreadable file, invalid JSON, or
//! an unsupported major version fails the whole import.

use std::collections::BTreeMap;

use base64::Engine;
use chrono::{DateTime, Utc};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, PrivateKeyInfo};
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// One passkey credential that passed validation.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub username: String,
    pub user_display_name: String,
    pub user_handle: Vec<u8>,
    pub key: PasskeyKey,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

/// A P-256 private key split into the two forms the item stores: the
/// uncompressed public point and the private scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyKey {
    pub point: [u8; 65],
    pub scalar: [u8; 32],
}

/// A credential that was not imported, with a reason fit for the output table.
#[derive(Debug, Clone)]
pub struct Skipped {
    pub rp_id: String,
    pub username: String,
    pub reason: String,
}

/// Everything one export yielded: accepted passkeys, per-type counts of
/// credentials this command does not handle, and per-credential skips.
#[derive(Debug, Default)]
pub struct Parsed {
    pub passkeys: Vec<Candidate>,
    pub unsupported: BTreeMap<String, usize>,
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Default, Deserialize)]
struct Export {
    #[serde(default)]
    version: Version,
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Debug, Default, Deserialize)]
struct Version {
    #[serde(default)]
    major: u32,
}

#[derive(Debug, Default, Deserialize)]
struct Account {
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    #[serde(default)]
    creation_at: Option<u64>,
    #[serde(default)]
    modified_at: Option<u64>,
    #[serde(default)]
    credentials: Vec<Credential>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Credential {
    #[serde(rename = "type", default)]
    credential_type: String,
    #[serde(default)]
    credential_id: String,
    #[serde(default)]
    rp_id: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    user_display_name: String,
    #[serde(default)]
    user_handle: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    fido2_extensions: Option<serde_json::Map<String, Value>>,
}

/// Parse and validate a CXF export. File-level problems are errors; individual
/// credentials that fail validation become [`Parsed::skipped`] rows.
pub fn parse(text: &str) -> Result<Parsed> {
    let export: Export = serde_json::from_str(text)
        .map_err(|error| Error::Invalid(format!("not a CXF file: {error}")))?;
    if export.version.major != 1 {
        return Err(Error::Invalid(format!(
            "CXF major version {} is not supported",
            export.version.major
        )));
    }

    let mut parsed = Parsed::default();
    for account in export.accounts {
        for item in account.items {
            let created_at = item.creation_at.and_then(unix_time);
            let modified_at = item.modified_at.and_then(unix_time);
            for credential in item.credentials {
                if credential.credential_type != "passkey" {
                    *parsed
                        .unsupported
                        .entry(credential.credential_type)
                        .or_default() += 1;
                    continue;
                }
                match candidate(&credential, created_at, modified_at) {
                    Ok(candidate) => parsed.passkeys.push(candidate),
                    Err(reason) => parsed.skipped.push(Skipped {
                        rp_id: credential.rp_id,
                        username: credential.username,
                        reason,
                    }),
                }
            }
        }
    }
    Ok(parsed)
}

fn unix_time(seconds: u64) -> Option<DateTime<Utc>> {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
}

fn candidate(
    credential: &Credential,
    created_at: Option<DateTime<Utc>>,
    modified_at: Option<DateTime<Utc>>,
) -> std::result::Result<Candidate, String> {
    if has_unstorable_extensions(&credential.fido2_extensions) {
        return Err("carries fido2 extensions apw cannot store".into());
    }

    let credential_id = decode_b64url(&credential.credential_id, "credentialId")?;
    if credential_id.is_empty() || credential_id.len() > 1023 {
        return Err("credentialId must be 1 to 1023 bytes".into());
    }
    if credential.rp_id.is_empty() {
        return Err("rpId is empty".into());
    }
    let user_handle = decode_b64url(&credential.user_handle, "userHandle")?;
    if user_handle.len() > 64 {
        return Err("userHandle exceeds 64 bytes".into());
    }
    let key_der = decode_b64url(&credential.key, "key")?;
    let key = PasskeyKey::parse(&key_der)?;

    Ok(Candidate {
        credential_id,
        rp_id: credential.rp_id.clone(),
        username: credential.username.clone(),
        user_display_name: credential.user_display_name.clone(),
        user_handle,
        key,
        created_at,
        modified_at,
    })
}

/// PRF, credBlob, and largeBlob payloads live inside the extensions object.
/// Storing the passkey without them would silently break the credential, and
/// `payments: true` marks a credential this command has no shape for.
fn has_unstorable_extensions(extensions: &Option<serde_json::Map<String, Value>>) -> bool {
    let Some(extensions) = extensions else {
        return false;
    };
    extensions.contains_key("hmacCredentials")
        || extensions.contains_key("credBlob")
        || extensions.contains_key("largeBlob")
        || extensions.get("payments").and_then(Value::as_bool) == Some(true)
}

fn decode_b64url(value: &str, field: &str) -> std::result::Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|error| format!("invalid base64url {field}: {error}"))
}

impl PasskeyKey {
    /// Parse a PKCS#8 P-256 private key. A public-key-only document, another
    /// curve, or an embedded public point that disagrees with the scalar is
    /// refused.
    pub fn parse(der: &[u8]) -> std::result::Result<Self, String> {
        let secret = SecretKey::from_pkcs8_der(der).map_err(|error| {
            if PublicKey::from_public_key_der(der).is_ok() {
                "key is a public key; a private scalar is required".to_string()
            } else {
                format!("key is not a PKCS#8 P-256 private key: {error}")
            }
        })?;
        let encoded = secret.public_key().to_encoded_point(false);
        let point: [u8; 65] = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| "key point is not a 65-byte uncompressed point".to_string())?;
        if let Some(embedded) = embedded_point(der) {
            if embedded != point {
                return Err("key public point does not match its private scalar".into());
            }
        }
        Ok(Self {
            point,
            scalar: secret.to_bytes().into(),
        })
    }
}

/// The public point a PKCS#8 document carries, if any: the optional top-level
/// `publicKey` field first, then the inner ECPrivateKey's `[1] publicKey`.
fn embedded_point(der: &[u8]) -> Option<Vec<u8>> {
    let info = PrivateKeyInfo::try_from(der).ok()?;
    if let Some(public) = info.public_key {
        if let Ok(public) = PublicKey::from_public_key_der(public) {
            let point = public.to_encoded_point(false);
            if point.as_bytes().len() == 65 {
                return Some(point.as_bytes().to_vec());
            }
        }
        if public.len() == 65 && public.first() == Some(&0x04) {
            return Some(public.to_vec());
        }
    }
    ec_private_point(info.private_key)
}

fn ec_private_point(inner: &[u8]) -> Option<Vec<u8>> {
    let (tag, value, _) = read_tlv(inner)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = value;
    while !rest.is_empty() {
        let (tag, value, next) = read_tlv(rest)?;
        if tag == 0xA1 {
            let (bit_tag, bits, _) = read_tlv(value)?;
            if bit_tag == 0x03 && bits.len() == 66 && bits[0] == 0 && bits[1] == 0x04 {
                return Some(bits[1..].to_vec());
            }
        }
        rest = next;
    }
    None
}

fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first & 0x80 == 0 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if !(1..=4).contains(&count) || rest.len() < count {
            return None;
        }
        let mut length = 0usize;
        for byte in &rest[..count] {
            length = (length << 8) | *byte as usize;
        }
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    fn key_der() -> (p256::SecretKey, Vec<u8>, String) {
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        let der = key.to_pkcs8_der().unwrap();
        let point = key.public_key().to_encoded_point(false);
        (
            key,
            der.as_bytes().to_vec(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.as_bytes()),
        )
    }

    #[test]
    fn pkcs8_round_trips_to_point_and_scalar() {
        let (key, der, _) = key_der();

        let parsed = PasskeyKey::parse(&der).unwrap();

        assert_eq!(parsed.scalar.as_slice(), key.to_bytes().as_slice());
        assert_eq!(
            parsed.point.as_slice(),
            key.public_key().to_encoded_point(false).as_bytes()
        );
        assert_eq!(parsed.point[0], 0x04);
        assert_eq!(parsed.point.len(), 65);
        assert_eq!(parsed.scalar.len(), 32);
    }

    #[test]
    fn a_public_key_only_document_is_refused() {
        use p256::pkcs8::EncodePublicKey;

        let (key, _, _) = key_der();
        let public = key.public_key().to_public_key_der().unwrap();

        let error = PasskeyKey::parse(public.as_bytes()).unwrap_err();

        assert!(error.contains("public key"), "{error}");
    }

    #[test]
    fn a_key_on_another_curve_is_refused() {
        use p384::pkcs8::EncodePrivateKey;

        let key = p384::SecretKey::random(&mut rand::thread_rng());
        let der = key.to_pkcs8_der().unwrap();

        let error = PasskeyKey::parse(der.as_bytes()).unwrap_err();

        assert!(error.contains("P-256"), "{error}");
    }

    #[test]
    fn a_passkey_credential_parses() {
        let (key, _, point_b64) = key_der();
        let der = key.to_pkcs8_der().unwrap();
        let file = serde_json::json!({
            "version": {"major": 1, "minor": 0},
            "exporterRpId": "webauthn.io",
            "exporterDisplayName": "webauthn.io",
            "timestamp": 1,
            "accounts": [{
                "id": "YWNjb3VudA",
                "username": "alice",
                "email": "alice@example.com",
                "collections": [],
                "items": [{
                    "id": "aXRlbQ",
                    "creationAt": 1_700_000_000,
                    "modifiedAt": 1_700_000_100,
                    "title": "webauthn.io",
                    "credentials": [{
                        "type": "passkey",
                        "credentialId": "Y3JlZGVudGlhbA",
                        "rpId": "webauthn.io",
                        "username": "alice",
                        "userDisplayName": "Alice",
                        "userHandle": "dXNlcg",
                        "key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der.as_bytes()),
                    }]
                }]
            }]
        })
        .to_string();

        let parsed = parse(&file).unwrap();

        assert_eq!(parsed.passkeys.len(), 1);
        assert!(parsed.skipped.is_empty());
        let candidate = &parsed.passkeys[0];
        assert_eq!(candidate.credential_id, b"credential");
        assert_eq!(candidate.rp_id, "webauthn.io");
        assert_eq!(candidate.username, "alice");
        assert_eq!(candidate.user_handle, b"user");
        assert_eq!(
            candidate.key.point,
            key.public_key().to_encoded_point(false).as_bytes()
        );
        assert!(candidate.created_at.is_some());
        assert!(candidate.modified_at.is_some());
        assert!(point_b64.len() > 80);
    }

    #[test]
    fn other_credential_types_are_counted_by_type() {
        let file = serde_json::json!({
            "version": {"major": 1, "minor": 0},
            "accounts": [{
                "items": [{
                    "title": "x",
                    "credentials": [
                        {"type": "basic-auth", "credentialId": "a"},
                        {"type": "basic-auth", "credentialId": "b"}
                    ]
                }]
            }]
        })
        .to_string();

        let parsed = parse(&file).unwrap();

        assert_eq!(parsed.unsupported.get("basic-auth"), Some(&2));
        assert!(parsed.passkeys.is_empty());
        assert!(parsed.skipped.is_empty());
    }

    #[test]
    fn unstoreable_extensions_skip_only_that_passkey() {
        let (key, _, _) = key_der();
        let der = key.to_pkcs8_der().unwrap();
        let file = serde_json::json!({
            "version": {"major": 1},
            "accounts": [{"items": [{"title": "x", "credentials": [{
                "type": "passkey",
                "credentialId": "Y3JlZGVudGlhbA",
                "rpId": "webauthn.io",
                "username": "alice",
                "userDisplayName": "Alice",
                "userHandle": "dXNlcg",
                "key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der.as_bytes()),
                "fido2Extensions": {"hmacCredentials": {"a": 1}}
            }]}]}]
        })
        .to_string();

        let parsed = parse(&file).unwrap();

        assert!(parsed.passkeys.is_empty());
        assert_eq!(
            parsed.skipped[0].reason,
            "carries fido2 extensions apw cannot store"
        );
    }

    #[test]
    fn a_bad_base64_value_is_a_skipped_row() {
        let (key, _, _) = key_der();
        let der = key.to_pkcs8_der().unwrap();
        let file = serde_json::json!({
            "version": {"major": 1},
            "accounts": [{"items": [{"title": "x", "credentials": [{
                "type": "passkey",
                "credentialId": "!!!",
                "rpId": "webauthn.io",
                "username": "alice",
                "userDisplayName": "Alice",
                "userHandle": "dXNlcg",
                "key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der.as_bytes()),
            }]}]}]
        })
        .to_string();

        let parsed = parse(&file).unwrap();

        assert!(parsed.passkeys.is_empty());
        assert_eq!(parsed.skipped.len(), 1);
        assert!(
            parsed.skipped[0]
                .reason
                .starts_with("invalid base64url credentialId: "),
            "{}",
            parsed.skipped[0].reason
        );
    }

    #[test]
    fn a_wrong_major_version_is_a_file_error() {
        let error = parse(r#"{"version": {"major": 2, "minor": 0}}"#).unwrap_err();

        assert_eq!(
            error.to_string(),
            "CXF major version 2 is not supported",
            "{error}"
        );
    }

    #[test]
    fn invalid_json_names_the_problem() {
        let error = parse("{").unwrap_err();

        assert!(error.to_string().starts_with("not a CXF file: "), "{error}");
    }
}
