//! The shared-keychain item protobuf.
//!
//! A record in a CloudKit shared group carries one of these messages: either an
//! internet password or a private key, with the rest of the item encrypted
//! inside `data` or `keyMaterial`.

use crate::error::Result;
use crate::wire::{Field, Reader, Writer};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SharedItem {
    pub internet_password: Option<SharedPassword>,
    pub private_key: Option<SharedPrivateKey>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SharedPassword {
    pub access_group: String,
    pub account: String,
    pub server: String,
    pub protocol: String,
    pub path: String,
    pub authentication_type: String,
    pub label: String,
    pub comment: String,
    pub item_description: String,
    pub data: Vec<u8>,
    pub notes: Vec<u8>,
    pub creation_date: f64,
    pub modification_date: f64,
    pub port: i32,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SharedPrivateKey {
    pub access_group: String,
    pub label: String,
    pub view_hint: String,
    pub key_class: i32,
    pub key_material: Vec<u8>,
    pub application_label: Vec<u8>,
    pub creation_date: f64,
    pub modification_date: f64,
}

pub fn decode_item(data: &[u8]) -> Result<SharedItem> {
    let mut item = SharedItem::default();
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        match field.number {
            2 => item.private_key = Some(decode_private_key(field)?),
            3 => item.internet_password = Some(decode_password(field)?),
            _ => {}
        }
    }
    Ok(item)
}

fn decode_password(field: Field<'_>) -> Result<SharedPassword> {
    let mut password = SharedPassword::default();
    let mut reader = field.message()?;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => password.access_group = field.string()?.to_string(),
            2 => password.modification_date = double(field)?,
            3 => password.creation_date = double(field)?,
            4 => password.account = field.string()?.to_string(),
            5 => password.protocol = field.string()?.to_string(),
            6 => password.server = field.string()?.to_string(),
            7 => password.port = field.varint()? as i32,
            8 => password.authentication_type = field.string()?.to_string(),
            9 => password.data = field.bytes()?.to_vec(),
            10 => password.path = field.string()?.to_string(),
            11 => password.comment = field.string()?.to_string(),
            12 => password.label = field.string()?.to_string(),
            16 => password.notes = field.bytes()?.to_vec(),
            24 => password.item_description = field.string()?.to_string(),
            _ => {}
        }
    }
    Ok(password)
}

fn decode_private_key(field: Field<'_>) -> Result<SharedPrivateKey> {
    let mut key = SharedPrivateKey::default();
    let mut reader = field.message()?;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => key.access_group = field.string()?.to_string(),
            4 => key.label = field.string()?.to_string(),
            5 => key.application_label = field.bytes()?.to_vec(),
            6 => key.key_material = field.bytes()?.to_vec(),
            9 => key.creation_date = double(field)?,
            10 => key.modification_date = double(field)?,
            15 => key.view_hint = field.string()?.to_string(),
            16 => key.key_class = field.varint()? as i32,
            _ => {}
        }
    }
    Ok(key)
}

/// Dates are protobuf doubles; the wire codec keeps the raw 8 bytes as a u64.
fn double(field: Field<'_>) -> Result<f64> {
    Ok(f64::from_bits(field.varint()?))
}

/// Encode a `SharingItem`, the payload of a group's item record.
///
/// The field numbers mirror [`decode_item`]; dates keep their raw f64 bits.
pub fn encode_item(item: &SharedItem) -> Vec<u8> {
    let mut out = Writer::new();
    if let Some(key) = &item.private_key {
        out.bytes(2, &encode_private_key(key));
    }
    if let Some(password) = &item.internet_password {
        out.bytes(3, &encode_password(password));
    }
    out.finish()
}

/// Encode a `SharingInternetPassword`.
///
/// Empty strings are written rather than dropped, because Apple's writer sends
/// them (`path` and `securityDomain` are empty on every shared login) and the
/// decoder reads either shape back as the same value.
pub fn encode_password(pw: &SharedPassword) -> Vec<u8> {
    let mut out = Writer::new();
    out.string(1, &pw.access_group);
    out.fixed64(2, pw.modification_date.to_bits());
    out.fixed64(3, pw.creation_date.to_bits());
    out.string(4, &pw.account);
    out.string(5, &pw.protocol);
    out.string(6, &pw.server);
    out.int64(7, i64::from(pw.port));
    out.string(8, &pw.authentication_type);
    out.bytes(9, &pw.data);
    out.string(10, &pw.path);
    out.string(11, &pw.comment);
    out.string(12, &pw.label);
    out.bytes(16, &pw.notes);
    out.string(24, &pw.item_description);
    out.finish()
}

fn encode_private_key(key: &SharedPrivateKey) -> Vec<u8> {
    let mut out = Writer::new();
    out.string(1, &key.access_group);
    out.string(4, &key.label);
    out.bytes(5, &key.application_label);
    out.bytes(6, &key.key_material);
    out.fixed64(9, key.creation_date.to_bits());
    out.fixed64(10, key.modification_date.to_bits());
    out.string(15, &key.view_hint);
    out.int64(16, i64::from(key.key_class));
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    #[test]
    fn decodes_internet_password() {
        let mut password = Writer::new();
        password
            .string(1, "group.example")
            .string(4, "alice")
            .string(6, "example.com")
            .bytes(9, b"hunter2")
            .bytes(16, b"note")
            .int64(7, 8443)
            .fixed64(2, 700.0f64.to_bits())
            .fixed64(3, 600.0f64.to_bits());
        let mut item = Writer::new();
        item.message(3, &password);

        let decoded = decode_item(item.as_slice()).unwrap();
        let password = decoded.internet_password.unwrap();
        assert_eq!(password.access_group, "group.example");
        assert_eq!(password.account, "alice");
        assert_eq!(password.server, "example.com");
        assert_eq!(password.data, b"hunter2".to_vec());
        assert_eq!(password.notes, b"note".to_vec());
        assert_eq!(password.port, 8443);
        assert_eq!(password.modification_date, 700.0);
        assert_eq!(password.creation_date, 600.0);
        assert!(decoded.private_key.is_none());
    }

    #[test]
    fn decodes_private_key() {
        let mut key = Writer::new();
        key.string(4, "login key")
            .bytes(5, b"app label")
            .bytes(6, b"key material")
            .int64(16, 42);
        let mut item = Writer::new();
        item.message(2, &key);

        let decoded = decode_item(item.as_slice()).unwrap();
        let key = decoded.private_key.unwrap();
        assert_eq!(key.label, "login key");
        assert_eq!(key.application_label, b"app label".to_vec());
        assert_eq!(key.key_material, b"key material".to_vec());
        assert_eq!(key.key_class, 42);
        assert!(decoded.internet_password.is_none());
    }

    #[test]
    fn empty_message_has_no_items() {
        let decoded = decode_item(&[]).unwrap();
        assert!(decoded.internet_password.is_none());
        assert!(decoded.private_key.is_none());
    }

    #[test]
    fn ignores_unknown_fields() {
        let mut password = Writer::new();
        password.string(4, "alice");
        let mut item = Writer::new();
        item.message(3, &password)
            .string(99, "ignore me")
            .uint64(100, 1);

        let decoded = decode_item(item.as_slice()).unwrap();
        assert_eq!(decoded.internet_password.unwrap().account, "alice");
        assert!(decoded.private_key.is_none());
    }

    #[test]
    fn an_encoded_password_round_trips() {
        let password = SharedPassword {
            access_group: "com.apple.cfnetwork".into(),
            account: "alice@example.com".into(),
            server: "example.com".into(),
            protocol: "htps".into(),
            path: "/login".into(),
            authentication_type: "form".into(),
            label: "example.com (alice@example.com)".into(),
            comment: "a comment".into(),
            item_description: "Web form password".into(),
            data: b"hunter2\x00\xff".to_vec(),
            notes: "多因素 note".as_bytes().to_vec(),
            creation_date: 700_123_456.25,
            modification_date: 700_999_999.5,
            port: 8443,
        };
        let encoded = encode_password(&password);
        let mut item = Writer::new();
        item.bytes(3, &encoded);

        let decoded = decode_item(item.as_slice()).unwrap();
        assert_eq!(decoded.internet_password.as_ref(), Some(&password));
        assert!(decoded.private_key.is_none());
        assert_eq!(
            decoded
                .internet_password
                .unwrap()
                .modification_date
                .to_bits(),
            700_999_999.5f64.to_bits(),
            "dates keep their exact bits"
        );
    }

    #[test]
    fn an_encoded_item_round_trips_both_kinds() {
        let item = SharedItem {
            internet_password: None,
            private_key: Some(SharedPrivateKey {
                access_group: "com.apple.cfnetwork".into(),
                label: "passkey".into(),
                view_hint: "hint".into(),
                key_class: 7,
                key_material: vec![1, 2, 3],
                application_label: b"example.com".to_vec(),
                creation_date: 10.5,
                modification_date: 11.5,
            }),
        };
        let decoded = decode_item(&encode_item(&item)).unwrap();
        assert_eq!(decoded, item);

        let both = SharedItem {
            internet_password: Some(SharedPassword::default()),
            private_key: Some(SharedPrivateKey::default()),
        };
        let decoded = decode_item(&encode_item(&both)).unwrap();
        assert_eq!(decoded, both);
    }

    #[test]
    fn empty_strings_stay_decodable() {
        let password = SharedPassword {
            data: b"secret".to_vec(),
            ..SharedPassword::default()
        };
        let decoded = decode_item(&encode_item(&SharedItem {
            internet_password: Some(password.clone()),
            private_key: None,
        }))
        .unwrap();
        let decoded = decoded.internet_password.unwrap();
        assert_eq!(decoded.access_group, "");
        assert_eq!(decoded.server, "");
        assert_eq!(decoded.account, "");
        assert_eq!(decoded.notes, Vec::<u8>::new());
        assert_eq!(decoded.port, 0);
        assert_eq!(decoded.data, b"secret".to_vec());
        assert_eq!(decoded, password);
    }

    #[test]
    fn rejects_wrong_wire_type() {
        let mut password = Writer::new();
        password.uint64(4, 1);
        let mut item = Writer::new();
        item.message(3, &password);

        let error = decode_item(item.as_slice()).unwrap_err();
        assert!(error.to_string().contains("field 4"), "{error}");
    }
}
