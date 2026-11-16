//! The shared-keychain item protobuf.
//!
//! A record in a CloudKit shared group carries one of these messages: either an
//! internet password or a private key, with the rest of the item encrypted
//! inside `data` or `keyMaterial`.

use crate::error::Result;
use crate::wire::{Field, Reader};

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
    fn rejects_wrong_wire_type() {
        let mut password = Writer::new();
        password.uint64(4, 1);
        let mut item = Writer::new();
        item.message(3, &password);

        let error = decode_item(item.as_slice()).unwrap_err();
        assert!(error.to_string().contains("field 4"), "{error}");
    }
}
