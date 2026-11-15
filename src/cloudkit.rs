//! CloudKit gateway client.
//!
//! The GSA `cloudKitToken` authenticates the protobuf CloudKitDaemon gateway,
//! not the JSON web services API. Requests are a gzip-compressed
//! `RequestOperation` with a varint length prefix; the token travels in the
//! `x-cloudkit-authtoken` header.

use std::collections::BTreeMap;

use base64::Engine;
use rand::RngCore;
use sha1::{Digest, Sha1};

use crate::auth::anisette::Identity;
use crate::error::{Error, Result};
use crate::model::Session;
use crate::wire::{self, Reader, Writer};

pub const CONTAINER: &str = "com.apple.security.keychain";
pub const BUNDLE_RECORDS: &str = "com.apple.securityd";
pub const BUNDLE_CUTTLEFISH: &str = "com.apple.security.cuttlefish";

const GATEWAY: &str = "https://gateway.icloud.com";
const CK_APP_INIT: &str = "/setup/setup/ck/v1/ckAppInit";
const RECORD_SYNC: &str = "/ckdatabase/api/client/record/sync";
const CODE_INVOKE: &str = "/ckcoderouter/api/client/code/invoke";

const OP_RECORD_SYNC: u64 = 213;
const OP_FUNCTION_INVOKE: u64 = 1101;

#[derive(Debug, Clone)]
pub enum FieldValue {
    Bytes(Vec<u8>),
    Int(i64),
    Double(f64),
    Date(i64),
    Text(String),
    Reference(String),
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub record_type: String,
    pub fields: BTreeMap<String, FieldValue>,
}

impl Record {
    pub fn bytes(&self, field: &str) -> Option<&[u8]> {
        match self.fields.get(field) {
            Some(FieldValue::Bytes(value)) => Some(value),
            _ => None,
        }
    }

    pub fn text(&self, field: &str) -> Option<&str> {
        match self.fields.get(field) {
            Some(FieldValue::Text(value)) => Some(value),
            _ => None,
        }
    }

    pub fn int(&self, field: &str) -> Option<i64> {
        match self.fields.get(field) {
            Some(FieldValue::Int(value)) | Some(FieldValue::Date(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn reference(&self, field: &str) -> Option<&str> {
        match self.fields.get(field) {
            Some(FieldValue::Reference(value)) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Changes {
    pub records: Vec<Record>,
    pub token: Option<Vec<u8>>,
    pub status: i32,
}

#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub code: i32,
    pub description: Option<String>,
    pub changes: Option<Changes>,
    pub result: Option<Vec<u8>>,
}

impl Outcome {
    pub fn ok(&self) -> bool {
        self.code == 1
    }

    pub fn check(self) -> Result<Self> {
        if self.ok() {
            return Ok(self);
        }
        let description = self
            .description
            .unwrap_or_else(|| format!("CloudKit operation failed with code {}", self.code));
        Err(Error::Message(description))
    }
}

pub struct Gateway {
    http: reqwest::Client,
    user_id: String,
    token: String,
    identity: Identity,
    device: Device,
}

struct Device {
    name: String,
    hardware: String,
    software: String,
    library: String,
}

impl Gateway {
    /// Register this client for the keychain container and return the gateway.
    pub async fn bootstrap(session: &Session, identity: &Identity) -> Result<Self> {
        let http = reqwest::Client::new();
        let url = format!("{GATEWAY}{CK_APP_INIT}?container={CONTAINER}");
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", session.dsid, session.mme_auth_token))
        );

        let mut request = http
            .post(url)
            .header("authorization", authorization)
            .header("accept", "application/json")
            .header("user-agent", "CloudKit/1970 (19H384)")
            .header("x-cloudkit-containerid", CONTAINER)
            .header("x-cloudkit-bundleid", BUNDLE_RECORDS)
            .header("x-cloudkit-databasescope", "Private")
            .header("x-cloudkit-environment", "Production")
            .header("x-mme-client-info", &identity.client_info);

        for (name, value) in &identity.headers {
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(Error::Message(format!(
                "CloudKit registration failed with {status}: {}",
                body.trim()
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| Error::Message(format!("invalid CloudKit registration: {error}")))?;
        let user_id = json
            .get("cloudKitUserId")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error::Message("CloudKit registration returned no user id".into()))?
            .to_string();

        Ok(Self {
            http,
            user_id,
            token: session.cloudkit_token.clone(),
            identity: identity.clone(),
            device: Device::new(),
        })
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Read one page of record changes from a private zone.
    pub async fn record_sync(&self, zone: &str, token: Option<&[u8]>) -> Result<Changes> {
        let mut request = Writer::new();
        if let Some(token) = token {
            request.bytes(1, token);
        }
        request.message(2, &self.zone_identifier(zone));
        request.uint64(4, 500);

        let outcome = self
            .call(RECORD_SYNC, BUNDLE_RECORDS, OP_RECORD_SYNC, &request, None)
            .await?;
        let outcome = outcome.check()?;
        Ok(outcome.changes.unwrap_or_default())
    }

    /// Invoke a Cuttlefish function and return its serialized result.
    pub async fn invoke(&self, name: &str, parameters: &[u8]) -> Result<Vec<u8>> {
        let mut request = Writer::new();
        request.string(1, "Cuttlefish");
        request.string(2, name);
        request.bytes(3, parameters);

        let hint = format!("Cuttlefish/{name}");
        let outcome = self
            .call(
                CODE_INVOKE,
                BUNDLE_CUTTLEFISH,
                OP_FUNCTION_INVOKE,
                &request,
                Some(&hint),
            )
            .await?;
        let outcome = outcome.check()?;
        outcome
            .result
            .ok_or_else(|| Error::Message(format!("{name} returned no result")))
    }

    fn zone_identifier(&self, zone: &str) -> Writer {
        let mut identifier = Writer::new();
        identifier.string(1, zone);
        identifier.uint64(2, 6);

        let mut owner = Writer::new();
        owner.string(1, &self.user_id);
        owner.uint64(2, 7);

        let mut zone_id = Writer::new();
        zone_id.message(1, &identifier);
        zone_id.message(2, &owner);
        zone_id
    }

    async fn call(
        &self,
        path: &str,
        bundle: &str,
        operation: u64,
        request: &Writer,
        routing_hint: Option<&str>,
    ) -> Result<Outcome> {
        let header = self.header(bundle);
        let mut operation_message = Writer::new();
        operation_message.string(1, &uppercase_uuid());
        operation_message.uint64(2, operation);
        operation_message.boolean(4, true);

        let mut envelope = Writer::new();
        envelope.message(1, &header);
        envelope.message(2, &operation_message);
        envelope.message(operation as u32, request);

        let body = wire::gzip(&wire::encode_delimited(&envelope.finish()))?;
        let operation_id = hex16();
        let group_id = hex16();

        let mut http = self
            .http
            .post(format!("{GATEWAY}{path}"))
            .header("accept", "application/x-protobuf")
            .header("accept-encoding", "gzip")
            .header("accept-language", "en-US,en;q=0.9")
            .header("cache-control", "no-transform")
            .header("content-encoding", "gzip")
            .header(
                "content-type",
                "application/x-protobuf; desc=\"https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc\"; messageType=RequestOperation; delimited=true",
            )
            .header("user-agent", "CloudKit/1970 (19H384)")
            .header("x-apple-c2-metric-triggers", "0")
            .header("x-apple-operation-group-id", &group_id)
            .header("x-apple-operation-id", &operation_id)
            .header("x-apple-request-uuid", uppercase_uuid())
            .header("x-cloudkit-bundleid", bundle)
            .header("x-cloudkit-containerid", CONTAINER)
            .header("x-cloudkit-databasescope", "Private")
            .header("x-cloudkit-duetpreclearedmode", "None")
            .header("x-cloudkit-environment", "Production")
            .header("x-mme-client-info", &self.identity.client_info)
            .header("x-cloudkit-userid", &self.user_id)
            .header("x-cloudkit-authtoken", &self.token)
            .body(body);

        if let Some(hint) = routing_hint {
            http = http.header("x-cloudkit-functionroutinghint", hint);
        }
        for (name, value) in &self.identity.headers {
            http = http.header(name, value);
        }

        let response = http.send().await?;
        let status = response.status();
        let body = response.bytes().await?.to_vec();
        if !status.is_success() {
            return Err(Error::Message(format!(
                "CloudKit gateway returned {status}"
            )));
        }

        let body = wire::maybe_gunzip(body)?;
        let frames = wire::decode_delimited(&body)?;
        let frame = frames
            .first()
            .ok_or_else(|| Error::Message("CloudKit gateway returned an empty body".into()))?;
        parse_outcome(frame)
    }

    fn header(&self, bundle: &str) -> Writer {
        let mut identifier = Writer::new();
        identifier.string(1, &self.device.name);
        identifier.uint64(2, 2);

        let mut header = Writer::new();
        header.string(2, CONTAINER);
        header.string(3, bundle);
        header.message(7, &identifier);
        header.string(8, &self.device.software);
        header.string(9, &self.device.hardware);
        header.string(10, &self.device.library);
        header.string(11, "1970");
        header.string(18, "5.0");
        header.uint64(19, 1);
        header.string(21, "apw");
        header.uint64(23, 1);
        header.uint64(25, 1);
        header.uint64(29, 0);
        header.string(32, &lower_sha1(&self.device.name));
        header.uint64(34, 0);
        header.uint64(35, 1);
        header
    }
}

impl Device {
    fn new() -> Self {
        Self {
            name: uppercase_uuid(),
            hardware: "MacBookPro18,3".into(),
            software: "13.4.1".into(),
            library: "CloudKitDaemon".into(),
        }
    }
}

fn parse_outcome(frame: &[u8]) -> Result<Outcome> {
    let mut reader = Reader::new(frame);
    let mut outcome = Outcome::default();
    while let Some(field) = reader.next()? {
        match field.number {
            3 => {
                let mut result = field.message()?;
                while let Some(item) = result.next()? {
                    match item.number {
                        1 => outcome.code = item.varint()? as i32,
                        2 => outcome.description = parse_error(item.message()?)?,
                        _ => {}
                    }
                }
            }
            203 => {
                outcome.changes = Some(parse_zone_changes(field.bytes()?)?);
            }
            213 => {
                outcome.changes = Some(parse_changes(field.bytes()?)?);
            }
            1101 => {
                let mut response = field.message()?;
                while let Some(item) = response.next()? {
                    if item.number == 1 {
                        outcome.result = Some(item.bytes()?.to_vec());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(outcome)
}

fn parse_error(mut reader: Reader<'_>) -> Result<Option<String>> {
    while let Some(field) = reader.next()? {
        if field.number == 4 {
            return Ok(Some(field.string()?.to_string()));
        }
    }
    Ok(None)
}

fn parse_changes(data: &[u8]) -> Result<Changes> {
    let mut reader = Reader::new(data);
    let mut changes = Changes::default();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                let mut change = field.message()?;
                while let Some(item) = change.next()? {
                    if item.number == 5 {
                        changes.records.push(parse_record(item.bytes()?)?);
                    }
                }
            }
            2 => changes.token = Some(field.bytes()?.to_vec()),
            4 => changes.status = field.varint()? as i32,
            _ => {}
        }
    }
    Ok(changes)
}

fn parse_zone_changes(_data: &[u8]) -> Result<Changes> {
    Ok(Changes::default())
}

pub fn parse_record(data: &[u8]) -> Result<Record> {
    let mut reader = Reader::new(data);
    let mut record = Record {
        name: String::new(),
        record_type: String::new(),
        fields: BTreeMap::new(),
    };
    while let Some(field) = reader.next()? {
        match field.number {
            2 => record.name = parse_identifier(field.message()?)?,
            3 => record.record_type = parse_type(field.message()?)?,
            7 => {
                let (name, value) = parse_record_field(field.message()?)?;
                record.fields.insert(name, value);
            }
            _ => {}
        }
    }
    Ok(record)
}

fn parse_identifier(mut reader: Reader<'_>) -> Result<String> {
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            let mut identifier = field.message()?;
            while let Some(item) = identifier.next()? {
                if item.number == 1 {
                    return Ok(item.string()?.to_string());
                }
            }
        }
    }
    Err(Error::Message("record has no identifier".into()))
}

fn parse_type(mut reader: Reader<'_>) -> Result<String> {
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            return Ok(field.string()?.to_string());
        }
    }
    Err(Error::Message("record has no type".into()))
}

fn parse_record_field(mut reader: Reader<'_>) -> Result<(String, FieldValue)> {
    let mut name = String::new();
    let mut value = FieldValue::Bytes(Vec::new());
    while let Some(field) = reader.next()? {
        match field.number {
            1 => name = field.string()?.to_string(),
            2 => value = parse_value(field.message()?)?,
            _ => {}
        }
    }
    Ok((name, value))
}

fn parse_value(mut reader: Reader<'_>) -> Result<FieldValue> {
    while let Some(field) = reader.next()? {
        match field.number {
            2 => return Ok(FieldValue::Bytes(field.bytes()?.to_vec())),
            4 => return Ok(FieldValue::Int(field.varint()? as i64)),
            5 => return Ok(FieldValue::Double(f64::from_bits(field.varint()?))),
            6 => {
                let mut date = field.message()?;
                while let Some(item) = date.next()? {
                    if item.number == 1 {
                        return Ok(FieldValue::Date(item.varint()? as i64));
                    }
                }
            }
            7 => return Ok(FieldValue::Text(field.string()?.to_string())),
            9 => {
                let mut reference = field.message()?;
                while let Some(item) = reference.next()? {
                    if item.number == 2 {
                        return Ok(FieldValue::Reference(parse_identifier(item.message()?)?));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(FieldValue::Bytes(Vec::new()))
}

fn hex16() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    data_encoding::HEXUPPER.encode(&bytes)
}

fn uppercase_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = data_encoding::HEXUPPER.encode(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn lower_sha1(value: &str) -> String {
    let digest = Sha1::digest(value.as_bytes());
    data_encoding::HEXLOWER.encode(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_bytes(text: &str) -> Vec<u8> {
        let mut value = Writer::new();
        value.string(7, text);
        value.finish()
    }

    #[test]
    fn parses_a_record_change() {
        let mut name = Writer::new();
        name.string(1, "item-1");
        let mut identifier = Writer::new();
        identifier.message(1, &name);
        let mut record_type = Writer::new();
        record_type.string(1, "item");
        let mut field = Writer::new();
        field.string(1, "srvr");
        field.message(2, &{
            let mut value = Writer::new();
            value.string(7, "example.com");
            value
        });
        let mut record = Writer::new();
        record.message(2, &identifier);
        record.message(3, &record_type);
        record.message(7, &field);

        let mut change = Writer::new();
        change.message(5, &record);
        let mut response = Writer::new();
        response.message(1, &change);
        response.bytes(2, b"token");
        response.uint64(4, 3);

        let parsed = parse_changes(response.as_slice()).unwrap();
        assert_eq!(parsed.status, 3);
        assert_eq!(parsed.token.as_deref(), Some(b"token".as_slice()));
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].name, "item-1");
        assert_eq!(parsed.records[0].record_type, "item");
        assert_eq!(parsed.records[0].text("srvr"), Some("example.com"));
        assert_eq!(value_bytes("x").len(), 3);
    }

    #[test]
    fn parses_a_success_result() {
        let mut result = Writer::new();
        result.uint64(1, 1);
        let mut response = Writer::new();
        response.message(3, &result);
        let outcome = parse_outcome(response.as_slice()).unwrap();
        assert!(outcome.ok());
    }

    #[test]
    fn parses_an_error_description() {
        let mut error = Writer::new();
        error.string(4, "zone not found");
        let mut result = Writer::new();
        result.uint64(1, 3);
        result.message(2, &error);
        let mut response = Writer::new();
        response.message(3, &result);
        let outcome = parse_outcome(response.as_slice()).unwrap();
        assert!(!outcome.ok());
        assert_eq!(outcome.description.as_deref(), Some("zone not found"));
    }

    #[test]
    fn uuids_are_shaped() {
        let uuid = uppercase_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|c| *c == '-').count(), 4);
        assert_eq!(hex16().len(), 32);
    }
}
