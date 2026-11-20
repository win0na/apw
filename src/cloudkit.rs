//! CloudKit gateway client.
//!
//! The GSA `cloudKitToken` authenticates the protobuf CloudKitDaemon gateway,
//! not the JSON web services API. Requests are a gzip-compressed
//! `RequestOperation` with a varint length prefix; the token travels in the
//! `x-cloudkit-authtoken` header.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use rand::RngCore;
use sha1::{Digest, Sha1};

use crate::auth::anisette::Identity;
use crate::error::{Error, Result};
use crate::model::Session;
use crate::wire::{self, Reader, Writer};

pub const CONTAINER: &str = "com.apple.security.keychain";
/// Groups live in their own CloudKit container.
pub const SHARED_CONTAINER: &str = "com.apple.security.shared.keychain";
pub const BUNDLE_RECORDS: &str = "com.apple.securityd";
pub const BUNDLE_SHARING: &str = "com.apple.security.kcsharing";
pub const BUNDLE_CUTTLEFISH: &str = "com.apple.security.cuttlefish";

const GATEWAY: &str = "https://gateway.icloud.com";
const CK_APP_INIT: &str = "/setup/setup/ck/v1/ckAppInit";
const RECORD_SYNC: &str = "/ckdatabase/api/client/record/sync";
const RECORD_SAVE: &str = "/ckdatabase/api/client/record/save";
const RECORD_DELETE: &str = "/ckdatabase/api/client/record/delete";
const RECORD_RETRIEVE: &str = "/ckdatabase/api/client/record/retrieve";
const ZONE_SYNC: &str = "/ckdatabase/api/client/zone/sync";
const ZONE_RETRIEVE: &str = "/ckdatabase/api/client/zone/retrieve";
const ZONE_SAVE: &str = "/ckdatabase/api/client/zone/save";
const ZONE_DELETE: &str = "/ckdatabase/api/client/zone/delete";
const CODE_INVOKE: &str = "/ckcoderouter/api/client/code/invoke";

const OP_RECORD_SYNC: u64 = 213;
const OP_RECORD_SAVE: u64 = 210;
const OP_RECORD_DELETE: u64 = 214;
const OP_RECORD_RETRIEVE: u64 = 211;
const OP_ZONE_SYNC: u64 = 203;
const OP_ZONE_RETRIEVE: u64 = 201;
const OP_ZONE_SAVE: u64 = 200;
const OP_ZONE_DELETE: u64 = 202;
const OP_FUNCTION_INVOKE: u64 = 1101;

/// Save semantics understood by `RecordSaveRequest.saveSemantics`.
pub const SAVE_CREATE: u32 = 2;
pub const SAVE_UPDATE: u32 = 3;

/// `Record.Field.Value.type` for a string field.
pub const STRING_TYPE: u64 = 3;
/// `Record.Field.Value.type` for an int64 field.
pub const INT_TYPE: u64 = 7;
/// `Record.Field.Value.type` for an encrypted bytes field.
pub const ENCRYPTED_BYTES_TYPE: u64 = 20;

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
    /// The zone the record's identifier names, when the response carried it.
    pub zone: Option<String>,
    /// The zone owner, usually the iCloud user id.
    pub owner: Option<String>,
    pub etag: Option<String>,
    pub record_type: String,
    pub fields: BTreeMap<String, FieldValue>,
    /// `pluginFields` (record field 12), in the order the server sent them.
    pub plugin_fields: Vec<(String, FieldValue)>,
    pub protection_info: Option<Vec<u8>>,
    /// `permission` (record field 15).
    pub permission: Option<u32>,
    pub pcs_key: Option<Vec<u8>>,
    pub share_info: Option<ShareInfo>,
    /// `stableUrl` (record field 22), carried by a share record.
    pub stable_url: Option<StableUrl>,
}

/// A record to write to CloudKit.
///
/// `etag` is only meaningful for updates, and `semantics` selects create or
/// update ([`SAVE_CREATE`] / [`SAVE_UPDATE`]). Fields listed in `delete_fields`
/// are removed from the stored record when the save merges.
#[derive(Debug, Clone)]
pub struct OutgoingRecord {
    pub name: String,
    pub record_type: String,
    pub etag: Option<String>,
    pub semantics: u32,
    pub fields: Vec<OutgoingField>,
    /// `pluginFields` (record field 12).
    pub plugin_fields: Vec<OutgoingField>,
    pub delete_fields: Vec<String>,
    /// Raw `ShareInfo` message bytes (record field 16), echoed verbatim from
    /// [`ShareInfo::raw`] so a re-save keeps the share intact.
    pub share_info: Option<Vec<u8>>,
    /// Raw `StableUrl` message bytes (record field 22).
    pub stable_url: Option<Vec<u8>>,
    /// `pcsKey` (record field 24).
    pub pcs_key: Option<Vec<u8>>,
    /// `zoneProtectionInfoTag` (save request field 7): the tag of the zone
    /// protection the server must still hold.
    pub zone_protection_tag: Option<String>,
    /// `recordProtectionInfoTag` (save request field 8).
    pub record_protection_tag: Option<String>,
}

/// A zone to create or update with `zone/save`.
///
/// `protection_info` and `record_protection_info` are whole `ProtectionInfo`
/// messages (`1: der`, `2: tag`), because the zone protection carries a tag
/// and the record protection is saved untagged.
#[derive(Debug, Clone, Default)]
pub struct OutgoingZone {
    pub name: String,
    pub etag: Option<String>,
    pub protection_info: Option<Vec<u8>>,
    pub record_protection_info: Option<Vec<u8>>,
}

/// One `Record.Field`.
#[derive(Debug, Clone)]
pub struct OutgoingField {
    pub name: String,
    pub value: FieldValue,
    /// Encrypted bytes are written with `type = 20` and `isEncrypted = true`,
    /// which CloudKit wraps in the zone key.
    pub encrypted: bool,
    /// An encrypted string is `type = 3` (STRING) with the ciphertext in
    /// `bytesValue`, not `type = 20`. CloudKit rejects the wrong one.
    pub encrypted_string: bool,
    /// An encrypted integer is `type = 7` (INT64) with the ciphertext in
    /// `bytesValue`. Used by a shared item's `type` field.
    pub encrypted_int: bool,
}

/// A `ProtectionInfo` message: a DER encoded key plus its tag.
///
/// Deref exposes the DER bytes so callers that only want the key can use
/// `Option::as_deref`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectionInfoBytes {
    /// `protectionInfo` / `der`, the DER encoded key.
    pub der: Vec<u8>,
    /// `protectionInfoTag`, an uppercase hex SHA-1.
    pub tag: Option<String>,
}

impl std::ops::Deref for ProtectionInfoBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.der
    }
}

impl ProtectionInfoBytes {
    /// A protection info carrying the uppercase hex SHA-1 tag CloudKit uses to
    /// pin a zone protection.
    pub fn tagged(der: Vec<u8>) -> Self {
        let tag = data_encoding::HEXUPPER.encode(&Sha1::digest(&der));
        Self {
            der,
            tag: Some(tag),
        }
    }

    /// A protection info without a tag, the shape record protections use.
    pub fn untagged(der: Vec<u8>) -> Self {
        Self { der, tag: None }
    }

    /// The `ProtectionInfo` message: `1: der`, `2: tag` when present.
    pub fn message(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.bytes(1, &self.der);
        if let Some(tag) = &self.tag {
            writer.string(2, tag);
        }
        writer.finish()
    }
}

/// The zone-wide share record's `shareInfo` (`CKDPShare`).
///
/// `raw` holds the whole message as received. The writers send it back
/// untouched, so fields this crate does not model survive a re-save.
#[derive(Debug, Clone, Default)]
pub struct ShareInfo {
    pub raw: Vec<u8>,
    /// `identifier`, the raw `ShareIdentifier` message.
    pub identifier: Option<Vec<u8>>,
    pub etag: Option<String>,
    pub public_access: i32,
    pub invited_pcs: Option<ProtectionInfoBytes>,
    pub self_added_pcs: Option<ProtectionInfoBytes>,
    pub participants: Vec<Participant>,
    pub short_token_routing_key: Option<String>,
    pub add_potential_match: Vec<Participant>,
    pub invited_key_to_removes: Vec<Vec<u8>>,
    pub publisher_model: bool,
    pub annonymous_public_access: bool,
    pub displayed_hostname: Option<String>,
    pub publisher_model_type: i32,
    pub participant_self_removal_behavior: i32,
    pub deny_access_requests: bool,
    /// `requestingAccess`, the raw (empty) message.
    pub requesting_access: Option<Vec<u8>>,
    /// `blockedAccess`, the raw (empty) message.
    pub blocked_access: Option<Vec<u8>>,
    pub crypto_requirements_signing_key: Option<Vec<u8>>,
    pub allow_anyone_to_resolve_share: bool,
    /// `pcsInvitedKeysToRemove`, the raw (empty) message.
    pub pcs_invited_keys_to_remove: Option<Vec<u8>>,
    /// `pcsAddedKeysToRemove`, the raw (empty) message.
    pub pcs_added_keys_to_remove: Option<Vec<u8>>,
    pub short_token_hash: Option<Vec<u8>>,
    pub origin: Option<String>,
}

/// `ShareInfo.Participant.contactInformation`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactInformation {
    pub email_address: Option<String>,
    pub container_scoped_user_id: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub canonical_phone_number: Option<String>,
}

/// `ShareInfo.Participant`.
#[derive(Debug, Clone, Default)]
pub struct Participant {
    /// `participantId`, the raw `Identifier` message.
    pub participant_id: Option<Vec<u8>>,
    /// `userId`, the name inside the `Identifier` message.
    pub user_id: Option<String>,
    pub contact: Option<ContactInformation>,
    pub state: i32,
    pub participant_type: i32,
    pub permission: i32,
    /// `publicKey`, the DER bytes inside its `ProtectionInfo` wrapper.
    pub public_key: Option<Vec<u8>>,
    pub protection_info: Option<ProtectionInfoBytes>,
    /// `protectionInfoPublicKey`, the raw bytes.
    pub protection_info_public_key: Option<ProtectionInfoBytes>,
    pub public_key_version: i32,
}

/// A share record's `stableUrl`.
#[derive(Debug, Clone, Default)]
pub struct StableUrl {
    pub raw: Vec<u8>,
    pub routing_key: Option<String>,
    pub short_token_hash: Option<Vec<u8>>,
    pub protected_full_token: Option<Vec<u8>>,
    pub encrypted_public_sharing_key: Option<Vec<u8>>,
    pub displayed_hostname: Option<String>,
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

/// CloudKit database scope. Shared zones live in the shared database.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Private,
    Shared,
}

impl Scope {
    fn header(self) -> &'static str {
        match self {
            Scope::Private => "PRIVATE",
            Scope::Shared => "SHARED",
        }
    }

    fn value(self) -> u64 {
        match self {
            Scope::Private => 1,
            Scope::Shared => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZoneInfo {
    pub name: String,
    pub owner: String,
    pub change_type: i32,
}

#[derive(Debug, Clone)]
pub struct ZoneChanges {
    pub zones: Vec<ZoneInfo>,
    pub token: Option<Vec<u8>>,
    pub status: i32,
}

/// One zone and its PCS protection blobs.
#[derive(Debug, Clone)]
pub struct Zone {
    pub name: String,
    pub owner: String,
    pub protection_info: Option<Vec<u8>>,
    pub record_protection_info: Option<Vec<u8>>,
    /// The tags the server sent with each protection, when it sent one.
    pub protection_info_tag: Option<String>,
    pub record_protection_info_tag: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Changes {
    pub records: Vec<Record>,
    /// The per-change etag, aligned with `records`. A record change without an
    /// etag keeps its `None` slot.
    pub change_etags: Vec<Option<String>>,
    pub token: Option<Vec<u8>>,
    pub status: i32,
}

#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// The operation result code (`SUCCESS` is 1).
    pub code: i32,
    /// The error description sent with a failed result.
    pub description: Option<String>,
    /// `result.error.clientError.type`, the specific client error code.
    pub client_code: Option<i32>,
    /// `result.error.serverError.type`, the specific server error code.
    pub server_code: Option<i32>,
    pub changes: Option<Changes>,
    pub zone_changes: Option<ZoneChanges>,
    pub zone: Option<Zone>,
    /// The record returned by a save (`serverFields`) or retrieve.
    pub record: Option<Record>,
    /// `recordRetrieveResponse.clientVersionETagMatch`.
    pub etag_match: Option<bool>,
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
        let code = self.client_code.or(self.server_code).unwrap_or(self.code);
        let description = self
            .description
            .unwrap_or_else(|| format!("CloudKit operation failed with code {code}"));
        Err(Error::CloudKit {
            code,
            description: Some(description),
        })
    }
}

pub struct Gateway {
    http: reqwest::Client,
    user_id: String,
    token: String,
    identity: Identity,
    device: Device,
    container: String,
    bundle: String,
    scope: Scope,
}

struct Device {
    name: String,
    hardware: String,
    software: String,
    library: String,
}

impl Gateway {
    /// Register this client for the keychain container and return the gateway.
    pub async fn bootstrap(
        session: &Session,
        identity: &Identity,
        container: &str,
        scope: Scope,
    ) -> Result<Self> {
        Self::bootstrap_with_bundle(session, identity, container, scope, BUNDLE_RECORDS).await
    }

    /// Some containers only answer when the bundle id matches the client that
    /// owns them: password groups use `com.apple.security.kcsharing`.
    pub async fn bootstrap_with_bundle(
        session: &Session,
        identity: &Identity,
        container: &str,
        scope: Scope,
        bundle: &str,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| {
                Error::Message(format!("cannot create the CloudKit HTTP client: {error}"))
            })?;
        let url = format!("{GATEWAY}{CK_APP_INIT}?container={container}");
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
            .header("x-cloudkit-containerid", container)
            .header("x-cloudkit-bundleid", bundle)
            .header("x-cloudkit-databasescope", scope.header())
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

        if std::env::var_os("APW_DEBUG").is_some() {
            eprintln!("ckinit {scope:?}: {body}");
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
            container: container.to_string(),
            bundle: bundle.to_string(),
            scope,
        })
    }

    pub fn bundle(&self) -> &str {
        &self.bundle
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Read one page of record changes from a zone.
    pub async fn record_sync(
        &self,
        zone: &str,
        owner: Option<&str>,
        token: Option<&[u8]>,
    ) -> Result<Changes> {
        let mut request = Writer::new();
        if let Some(token) = token {
            request.bytes(1, token);
        }
        request.message(2, &self.zone_identifier(zone, owner));
        request.uint64(4, 500);

        let outcome = self
            .call(RECORD_SYNC, &self.bundle, OP_RECORD_SYNC, &request, None)
            .await?;
        let outcome = outcome.check()?;
        Ok(outcome.changes.unwrap_or_default())
    }

    /// Save one record, returning the server etag when the response carries it.
    pub async fn save_record(
        &self,
        zone: &str,
        owner: Option<&str>,
        record: &OutgoingRecord,
    ) -> Result<Option<String>> {
        let owner = owner.unwrap_or(&self.user_id);
        let request = save_request(record, zone, owner);

        let outcome = self
            .call(RECORD_SAVE, &self.bundle, OP_RECORD_SAVE, &request, None)
            .await?;
        let outcome = outcome.check()?;
        Ok(outcome.record.and_then(|record| record.etag))
    }

    /// Delete one record by name.
    pub async fn delete_record(&self, zone: &str, owner: Option<&str>, name: &str) -> Result<()> {
        let owner = owner.unwrap_or(&self.user_id);
        let mut request = Writer::new();
        request.message(1, &record_identifier(zone, owner, name));

        self.call(
            RECORD_DELETE,
            &self.bundle,
            OP_RECORD_DELETE,
            &request,
            None,
        )
        .await?
        .check()?;
        Ok(())
    }

    /// Retrieve one record, optionally conditional on a known etag.
    ///
    /// The boolean is `clientVersionETagMatch`; it is true when no etag was
    /// supplied and the response omits the flag.
    pub async fn retrieve_record(
        &self,
        zone: &str,
        owner: Option<&str>,
        name: &str,
        etag: Option<&str>,
    ) -> Result<(Record, bool)> {
        let owner = owner.unwrap_or(&self.user_id);
        let mut request = Writer::new();
        request.message(1, &record_identifier(zone, owner, name));
        if let Some(etag) = etag {
            request.string(4, etag);
        }

        let outcome = self
            .call(
                RECORD_RETRIEVE,
                &self.bundle,
                OP_RECORD_RETRIEVE,
                &request,
                None,
            )
            .await?
            .check()?;
        let record = outcome
            .record
            .ok_or_else(|| Error::Message("record retrieve returned no record".into()))?;
        let matched = outcome.etag_match.unwrap_or(etag.is_none());
        Ok((record, matched))
    }

    /// List changed zones in one database scope.
    pub async fn zone_changes(&self, token: Option<&[u8]>) -> Result<ZoneChanges> {
        let mut request = Writer::new();
        if let Some(token) = token {
            request.bytes(1, token);
        }
        request.uint64(2, 200);

        let outcome = self
            .call(ZONE_SYNC, &self.bundle, OP_ZONE_SYNC, &request, None)
            .await?;
        let outcome = outcome.check()?;
        outcome
            .zone_changes
            .ok_or_else(|| Error::Message("zone sync returned no zones".into()))
    }

    /// Retrieve one zone and its PCS protection blobs.
    pub async fn zone_retrieve(&self, zone: &str, owner: &str) -> Result<Zone> {
        let mut request = Writer::new();
        request.message(1, &self.zone_identifier(zone, Some(owner)));

        let outcome = self
            .call(
                ZONE_RETRIEVE,
                &self.bundle,
                OP_ZONE_RETRIEVE,
                &request,
                None,
            )
            .await?;
        let outcome = outcome.check()?;
        outcome
            .zone
            .ok_or_else(|| Error::Message("zone retrieve returned no zone".into()))
    }

    /// Create or update one zone. The server answers with an empty result, so
    /// success means the zone now carries the protections that were sent.
    pub async fn save_zone(&self, zone: &OutgoingZone) -> Result<()> {
        let request = zone_save_request(zone, &self.user_id);
        self.call(ZONE_SAVE, &self.bundle, OP_ZONE_SAVE, &request, None)
            .await?
            .check()?;
        Ok(())
    }

    /// Delete one zone the user owns.
    pub async fn delete_zone(&self, zone: &str) -> Result<()> {
        let request = zone_delete_request(zone, &self.user_id);
        self.call(ZONE_DELETE, &self.bundle, OP_ZONE_DELETE, &request, None)
            .await?
            .check()?;
        Ok(())
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

    fn zone_identifier(&self, zone: &str, owner_id: Option<&str>) -> Writer {
        zone_identifier_writer(zone, owner_id.unwrap_or(&self.user_id))
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
            .header("x-cloudkit-containerid", &self.container)
            .header("x-cloudkit-databasescope", self.scope.header())
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
            let decoded = wire::maybe_gunzip(body.clone()).unwrap_or(body);
            let preview = String::from_utf8_lossy(&decoded[..decoded.len().min(400)]);
            return Err(Error::Message(format!(
                "CloudKit gateway returned {status}: {preview}"
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
        header.string(2, &self.container);
        header.string(3, bundle);
        header.message(7, &identifier);
        header.string(8, &self.device.software);
        header.string(9, &self.device.hardware);
        header.string(10, &self.device.library);
        header.string(11, "1970");
        header.string(18, "5.0");
        header.uint64(19, 1);
        header.string(21, "apw");
        header.string(22, &self.device.name);
        header.uint64(23, self.scope.value());
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

/// `RecordZoneIdentifier { 1: { 1: zone, 2: RECORD_ZONE }, 2: { 1: owner,
/// 2: USER } }`.
pub(crate) fn zone_identifier_writer(zone: &str, owner: &str) -> Writer {
    let mut identifier = Writer::new();
    identifier.string(1, zone);
    identifier.uint64(2, 6);

    let mut owner_identifier = Writer::new();
    owner_identifier.string(1, owner);
    owner_identifier.uint64(2, 7);

    let mut zone_id = Writer::new();
    zone_id.message(1, &identifier);
    zone_id.message(2, &owner_identifier);
    zone_id
}

/// `ZoneSaveRequest { 1: Zone { 1: identifier, 2: etag, 3: protectionInfo,
/// 6: recordProtectionInfo } }`.
pub(crate) fn zone_message(zone: &OutgoingZone, owner: &str) -> Writer {
    let mut message = Writer::new();
    message.message(1, &zone_identifier_writer(&zone.name, owner));
    if let Some(etag) = &zone.etag {
        message.string(2, etag);
    }
    if let Some(info) = &zone.protection_info {
        message.bytes(3, info);
    }
    if let Some(info) = &zone.record_protection_info {
        message.bytes(6, info);
    }
    message
}

pub(crate) fn zone_save_request(zone: &OutgoingZone, owner: &str) -> Writer {
    let mut request = Writer::new();
    request.message(1, &zone_message(zone, owner));
    request
}

/// `ZoneDeleteRequest { 1: identifier, 2: 0 }`.
fn zone_delete_request(zone: &str, owner: &str) -> Writer {
    let mut request = Writer::new();
    request.message(1, &zone_identifier_writer(zone, owner));
    request.uint64(2, 0);
    request
}

/// `RecordIdentifier { value: Identifier { name, RECORD }, zoneIdentifier }`.
fn record_identifier(zone: &str, owner: &str, name: &str) -> Writer {
    let mut identifier = Writer::new();
    identifier.string(1, name);
    identifier.uint64(2, 1);

    let mut record = Writer::new();
    record.message(1, &identifier);
    record.message(2, &zone_identifier_writer(zone, owner));
    record
}

/// `Record.Field.Value` with an explicit type code. References carry only the
/// target record name, so `zone` and `owner` complete the reference.
fn value_message(
    value: &FieldValue,
    encrypted: bool,
    encrypted_string: bool,
    encrypted_int: bool,
    zone: &str,
    owner: &str,
) -> Writer {
    let mut out = Writer::new();
    let field_type = |code: u64| {
        if encrypted_string {
            STRING_TYPE
        } else if encrypted_int {
            INT_TYPE
        } else if encrypted {
            ENCRYPTED_BYTES_TYPE
        } else {
            code
        }
    };
    match value {
        FieldValue::Bytes(bytes) => {
            out.uint64(1, field_type(1));
            out.bytes(2, bytes);
        }
        FieldValue::Date(seconds) => {
            out.uint64(1, field_type(2));
            let mut date = Writer::new();
            date.fixed64(1, (*seconds as f64).to_bits());
            out.message(6, &date);
        }
        FieldValue::Text(text) => {
            out.uint64(1, field_type(3));
            out.string(7, text);
        }
        FieldValue::Reference(name) => {
            out.uint64(1, field_type(5));
            let mut reference = Writer::new();
            reference.uint64(1, 3);
            reference.message(2, &record_identifier(zone, owner, name));
            out.message(9, &reference);
        }
        FieldValue::Int(number) => {
            out.uint64(1, field_type(7));
            out.int64(4, *number);
        }
        FieldValue::Double(number) => {
            out.uint64(1, field_type(8));
            out.fixed64(5, number.to_bits());
        }
    }
    if encrypted {
        out.boolean(13, true);
    }
    out
}

fn record_field_writer(field: &OutgoingField, zone: &str, owner: &str) -> Writer {
    let mut identifier = Writer::new();
    identifier.string(1, &field.name);

    let mut out = Writer::new();
    out.message(1, &identifier);
    out.message(
        2,
        &value_message(
            &field.value,
            field.encrypted,
            field.encrypted_string,
            field.encrypted_int,
            zone,
            owner,
        ),
    );
    out
}

pub(crate) fn save_request(record: &OutgoingRecord, zone: &str, owner: &str) -> Writer {
    let mut record_message = Writer::new();
    if let Some(etag) = &record.etag {
        record_message.string(1, etag);
    }
    record_message.message(2, &record_identifier(zone, owner, &record.name));

    let mut record_type = Writer::new();
    record_type.string(1, &record.record_type);
    record_message.message(3, &record_type);

    for field in &record.fields {
        record_message.message(7, &record_field_writer(field, zone, owner));
    }
    for field in &record.plugin_fields {
        record_message.message(12, &record_field_writer(field, zone, owner));
    }
    if let Some(share_info) = &record.share_info {
        record_message.bytes(16, share_info);
    }
    if let Some(stable_url) = &record.stable_url {
        record_message.bytes(22, stable_url);
    }
    if let Some(pcs_key) = &record.pcs_key {
        record_message.bytes(24, pcs_key);
    }

    let mut request = Writer::new();
    request.message(1, &record_message);
    request.boolean(2, true);
    for name in &record.delete_fields {
        request.string(3, name);
    }
    request.uint64(6, u64::from(record.semantics));
    if let Some(tag) = &record.zone_protection_tag {
        request.string(7, tag);
    }
    if let Some(tag) = &record.record_protection_tag {
        request.string(8, tag);
    }
    request
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
                        2 => {
                            let (client, server, description) =
                                parse_result_error(item.message()?)?;
                            outcome.client_code = client;
                            outcome.server_code = server;
                            outcome.description = description;
                        }
                        _ => {}
                    }
                }
            }
            210 => outcome.record = parse_save_response(field.bytes()?)?,
            211 => {
                let (record, etag_match) = parse_retrieve_response(field.bytes()?)?;
                outcome.record = record;
                outcome.etag_match = etag_match;
            }
            214 => {}
            200 | 202 => {}
            203 => {
                outcome.zone_changes = Some(parse_zone_changes(field.bytes()?)?);
            }
            201 => {
                outcome.zone = Some(parse_zone_retrieve(field.bytes()?)?);
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

fn parse_result_error(
    mut reader: Reader<'_>,
) -> Result<(Option<i32>, Option<i32>, Option<String>)> {
    let mut client = None;
    let mut server = None;
    let mut description = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => client = parse_error_code(field.message()?)?,
            2 => server = parse_error_code(field.message()?)?,
            4 => description = Some(field.string()?.to_string()),
            _ => {}
        }
    }
    Ok((client, server, description))
}

/// Read the `type` enum out of a client or server error message.
fn parse_error_code(mut reader: Reader<'_>) -> Result<Option<i32>> {
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            return Ok(Some(field.varint()? as i32));
        }
    }
    Ok(None)
}

fn parse_save_response(data: &[u8]) -> Result<Option<Record>> {
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        if field.number == 4 {
            return Ok(Some(parse_record(field.bytes()?)?));
        }
    }
    Ok(None)
}

fn parse_retrieve_response(data: &[u8]) -> Result<(Option<Record>, Option<bool>)> {
    let mut reader = Reader::new(data);
    let mut record = None;
    let mut etag_match = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => record = Some(parse_record(field.bytes()?)?),
            2 => etag_match = Some(field.varint()? != 0),
            _ => {}
        }
    }
    Ok((record, etag_match))
}

fn parse_changes(data: &[u8]) -> Result<Changes> {
    let mut reader = Reader::new(data);
    let mut changes = Changes::default();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                let mut change = field.message()?;
                let mut record = None;
                let mut etag = None;
                while let Some(item) = change.next()? {
                    match item.number {
                        2 => etag = Some(item.string()?.to_string()),
                        5 => record = Some(parse_record(item.bytes()?)?),
                        _ => {}
                    }
                }
                if let Some(record) = record {
                    changes.records.push(record);
                    changes.change_etags.push(etag);
                }
            }
            2 => changes.token = Some(field.bytes()?.to_vec()),
            4 => changes.status = field.varint()? as i32,
            _ => {}
        }
    }
    Ok(changes)
}

fn parse_zone_changes(data: &[u8]) -> Result<ZoneChanges> {
    let mut reader = Reader::new(data);
    let mut changes = ZoneChanges {
        zones: Vec::new(),
        token: None,
        status: 0,
    };
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                let mut zone = field.message()?;
                let mut info = ZoneInfo {
                    name: String::new(),
                    owner: String::new(),
                    change_type: 0,
                };
                while let Some(item) = zone.next()? {
                    match item.number {
                        1 => {
                            let (name, owner) = parse_zone_identifier(item.message()?)?;
                            info.name = name;
                            info.owner = owner;
                        }
                        2 => info.change_type = item.varint()? as i32,
                        _ => {}
                    }
                }
                changes.zones.push(info);
            }
            2 => changes.token = Some(field.bytes()?.to_vec()),
            3 => changes.status = field.varint()? as i32,
            _ => {}
        }
    }
    Ok(changes)
}

fn parse_zone_identifier(mut reader: Reader<'_>) -> Result<(String, String)> {
    let mut name = String::new();
    let mut owner = String::new();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => name = parse_identifier_name(field.message()?)?,
            2 => owner = parse_identifier_name(field.message()?)?,
            _ => {}
        }
    }
    Ok((name, owner))
}

fn parse_identifier_name(mut reader: Reader<'_>) -> Result<String> {
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            return Ok(field.string()?.to_string());
        }
    }
    Ok(String::new())
}

fn parse_zone_retrieve(data: &[u8]) -> Result<Zone> {
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        if field.number != 1 {
            continue;
        }
        let mut summary = field.message()?;
        while let Some(item) = summary.next()? {
            if item.number == 1 {
                return parse_zone(item.message()?);
            }
        }
    }
    Err(Error::Message("zone retrieve has no target zone".into()))
}

fn parse_zone(mut reader: Reader<'_>) -> Result<Zone> {
    let mut zone = Zone {
        name: String::new(),
        owner: String::new(),
        protection_info: None,
        record_protection_info: None,
        protection_info_tag: None,
        record_protection_info_tag: None,
    };
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                let (name, owner) = parse_zone_identifier(field.message()?)?;
                zone.name = name;
                zone.owner = owner;
            }
            3 => {
                let info = parse_protection_info(field.message()?)?;
                zone.protection_info = info.as_ref().map(|info| info.der.clone());
                zone.protection_info_tag = info.and_then(|info| info.tag);
            }
            6 => {
                let info = parse_protection_info(field.message()?)?;
                zone.record_protection_info = info.as_ref().map(|info| info.der.clone());
                zone.record_protection_info_tag = info.and_then(|info| info.tag);
            }
            _ => {}
        }
    }
    Ok(zone)
}

fn parse_protection_info(mut reader: Reader<'_>) -> Result<Option<ProtectionInfoBytes>> {
    let mut info = ProtectionInfoBytes::default();
    let mut seen = false;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                info.der = field.bytes()?.to_vec();
                seen = true;
            }
            2 => info.tag = Some(field.string()?.to_string()),
            _ => {}
        }
    }
    Ok(seen.then_some(info))
}

pub fn parse_record(data: &[u8]) -> Result<Record> {
    let mut reader = Reader::new(data);
    let mut record = Record {
        name: String::new(),
        zone: None,
        owner: None,
        etag: None,
        record_type: String::new(),
        fields: BTreeMap::new(),
        plugin_fields: Vec::new(),
        protection_info: None,
        permission: None,
        pcs_key: None,
        share_info: None,
        stable_url: None,
    };
    while let Some(field) = reader.next()? {
        match field.number {
            1 => record.etag = Some(field.string()?.to_string()),
            2 => {
                let (name, zone, owner) = parse_record_identifier(field.message()?)?;
                record.name = name;
                record.zone = zone;
                record.owner = owner;
            }
            3 => record.record_type = parse_type(field.message()?)?,
            7 => {
                let (name, value) = parse_record_field(field.message()?)?;
                record.fields.insert(name, value);
            }
            12 => {
                let (name, value) = parse_record_field(field.message()?)?;
                record.plugin_fields.push((name, value));
            }
            13 => {
                record.protection_info =
                    parse_protection_info(field.message()?)?.map(|info| info.der);
            }
            15 => record.permission = Some(field.varint()? as u32),
            16 => {
                let data = field.bytes()?;
                record.share_info = Some(parse_share_info(data).unwrap_or_else(|error| {
                    debug_warning(&format!("shareInfo left unparsed: {error}"));
                    ShareInfo {
                        raw: data.to_vec(),
                        ..ShareInfo::default()
                    }
                }));
            }
            22 => {
                let data = field.bytes()?;
                record.stable_url = Some(parse_stable_url(data).unwrap_or_else(|error| {
                    debug_warning(&format!("stableUrl left unparsed: {error}"));
                    StableUrl {
                        raw: data.to_vec(),
                        ..StableUrl::default()
                    }
                }));
            }
            24 => record.pcs_key = Some(field.bytes()?.to_vec()),
            _ => {}
        }
    }
    Ok(record)
}

/// A malformed optional submessage keeps its raw bytes and only warns under
/// `APW_DEBUG`; it must not fail the whole record.
fn debug_warning(message: &str) {
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!("cloudkit: {message}");
    }
}

fn parse_share_info(data: &[u8]) -> Result<ShareInfo> {
    let mut share = ShareInfo {
        raw: data.to_vec(),
        ..ShareInfo::default()
    };
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        match field.number {
            1 => share.identifier = Some(field.bytes()?.to_vec()),
            2 => share.etag = Some(field.string()?.to_string()),
            3 => share.public_access = field.varint()? as i32,
            4 => share.invited_pcs = Some(parse_protection_info_bytes(field.message()?)?),
            5 => share.self_added_pcs = Some(parse_protection_info_bytes(field.message()?)?),
            6 => share.participants.push(parse_participant(field.bytes()?)?),
            7 => share.short_token_routing_key = Some(field.string()?.to_string()),
            8 => share
                .add_potential_match
                .push(parse_participant(field.bytes()?)?),
            9 => share.invited_key_to_removes.push(field.bytes()?.to_vec()),
            10 => share.publisher_model = field.varint()? != 0,
            11 => share.annonymous_public_access = field.varint()? != 0,
            12 => share.displayed_hostname = Some(field.string()?.to_string()),
            13 => share.publisher_model_type = field.varint()? as i32,
            14 => share.participant_self_removal_behavior = field.varint()? as i32,
            15 => share.deny_access_requests = field.varint()? != 0,
            18 => share.requesting_access = Some(field.bytes()?.to_vec()),
            19 => share.blocked_access = Some(field.bytes()?.to_vec()),
            20 => share.crypto_requirements_signing_key = Some(field.bytes()?.to_vec()),
            21 => share.allow_anyone_to_resolve_share = field.varint()? != 0,
            22 => share.pcs_invited_keys_to_remove = Some(field.bytes()?.to_vec()),
            23 => share.pcs_added_keys_to_remove = Some(field.bytes()?.to_vec()),
            101 => share.short_token_hash = Some(field.bytes()?.to_vec()),
            102 => share.origin = Some(field.string()?.to_string()),
            _ => {}
        }
    }
    Ok(share)
}

fn parse_participant(data: &[u8]) -> Result<Participant> {
    let mut participant = Participant::default();
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        match field.number {
            1 => participant.participant_id = Some(field.bytes()?.to_vec()),
            2 => {
                let name = parse_identifier_name(field.message()?)?;
                if !name.is_empty() {
                    participant.user_id = Some(name);
                }
            }
            3 => participant.contact = Some(parse_contact_information(field.message()?)?),
            4 => participant.state = field.varint()? as i32,
            5 => participant.participant_type = field.varint()? as i32,
            6 => participant.permission = field.varint()? as i32,
            9 => participant.public_key = Some(public_key_bytes(field.bytes()?)),
            11 => {
                participant.protection_info = Some(parse_protection_info_bytes(field.message()?)?);
            }
            14 => participant.public_key_version = field.varint()? as i32,
            19 => {
                participant.protection_info_public_key = Some(ProtectionInfoBytes {
                    der: field.bytes()?.to_vec(),
                    tag: None,
                });
            }
            _ => {}
        }
    }
    Ok(participant)
}

/// `publicKey` is a `ProtectionInfo` message in the proto, but older shapes
/// carry the raw key. Return the DER bytes in both cases.
fn public_key_bytes(raw: &[u8]) -> Vec<u8> {
    let mut reader = Reader::new(raw);
    if let Ok(Some(field)) = reader.next() {
        if field.number == 1 {
            if let Ok(der) = field.bytes() {
                return der.to_vec();
            }
        }
    }
    raw.to_vec()
}

fn parse_contact_information(mut reader: Reader<'_>) -> Result<ContactInformation> {
    let mut contact = ContactInformation::default();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => contact.email_address = Some(field.string()?.to_string()),
            2 => contact.container_scoped_user_id = Some(field.string()?.to_string()),
            3 => contact.first_name = Some(field.string()?.to_string()),
            4 => contact.last_name = Some(field.string()?.to_string()),
            5 => contact.phone_number = Some(field.string()?.to_string()),
            6 => contact.canonical_phone_number = Some(field.string()?.to_string()),
            _ => {}
        }
    }
    Ok(contact)
}

fn parse_protection_info_bytes(mut reader: Reader<'_>) -> Result<ProtectionInfoBytes> {
    let mut info = ProtectionInfoBytes::default();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => info.der = field.bytes()?.to_vec(),
            2 => info.tag = Some(field.string()?.to_string()),
            _ => {}
        }
    }
    Ok(info)
}

fn parse_stable_url(data: &[u8]) -> Result<StableUrl> {
    let mut url = StableUrl {
        raw: data.to_vec(),
        ..StableUrl::default()
    };
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        match field.number {
            1 => url.routing_key = Some(field.string()?.to_string()),
            2 => url.short_token_hash = Some(field.bytes()?.to_vec()),
            3 => url.protected_full_token = Some(field.bytes()?.to_vec()),
            4 => url.encrypted_public_sharing_key = Some(field.bytes()?.to_vec()),
            5 => url.displayed_hostname = Some(field.string()?.to_string()),
            _ => {}
        }
    }
    Ok(url)
}

/// Parse a `RecordIdentifier`:
/// `1: value { 1: name }, 2: zoneIdentifier { 1: { 1: zone }, 2: { 1: owner } }`.
fn parse_record_identifier(
    mut reader: Reader<'_>,
) -> Result<(String, Option<String>, Option<String>)> {
    let mut name = String::new();
    let mut zone = None;
    let mut owner = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => name = parse_identifier_name(field.message()?)?,
            2 => {
                let mut zone_identifier = field.message()?;
                while let Some(item) = zone_identifier.next()? {
                    match item.number {
                        1 => {
                            let value = parse_identifier_name(item.message()?)?;
                            if !value.is_empty() {
                                zone = Some(value);
                            }
                        }
                        2 => {
                            let value = parse_identifier_name(item.message()?)?;
                            if !value.is_empty() {
                                owner = Some(value);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if name.is_empty() {
        return Err(Error::Message("record has no identifier".into()));
    }
    Ok((name, zone, owner))
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
            1 => {
                // The name is normally a string, but some responses wrap it in
                // a one-field message.
                name = match field.string() {
                    Ok(text) if !text.starts_with('\n') => text.to_string(),
                    _ => {
                        let mut inner = field.message()?;
                        let mut text = String::new();
                        while let Some(item) = inner.next()? {
                            if item.number == 1 {
                                text = item.string()?.to_string();
                            }
                        }
                        text
                    }
                };
            }
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
                        return Ok(FieldValue::Date(f64::from_bits(item.varint()?) as i64));
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

/// A fresh dashed uppercase UUID v4, as CloudKit names records and participants.
pub(crate) fn uppercase_uuid() -> String {
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

    fn fields_of(data: &[u8]) -> Vec<wire::Field<'_>> {
        Reader::new(data).fields().unwrap()
    }

    fn field<'a>(fields: &[wire::Field<'a>], number: u32) -> wire::Field<'a> {
        *fields.iter().find(|f| f.number == number).unwrap()
    }

    fn record_value<'a>(record_fields: &[wire::Field<'a>], name: &str) -> &'a [u8] {
        record_field_value(record_fields, 7, name)
    }

    fn record_field_value<'a>(
        record_fields: &[wire::Field<'a>],
        number: u32,
        name: &str,
    ) -> &'a [u8] {
        record_fields
            .iter()
            .filter(|f| f.number == number)
            .find_map(|f| {
                let parts = fields_of(f.bytes().ok()?);
                let identifier = fields_of(field(&parts, 1).bytes().ok()?);
                if field(&identifier, 1).string().ok()? == name {
                    Some(field(&parts, 2).bytes().ok()?)
                } else {
                    None
                }
            })
            .unwrap()
    }

    fn plain(name: &str, value: FieldValue) -> OutgoingField {
        OutgoingField {
            name: name.into(),
            value,
            encrypted: false,
            encrypted_string: false,
            encrypted_int: false,
        }
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
        change.string(2, "etag-1");
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
        assert_eq!(parsed.change_etags, vec![Some("etag-1".to_string())]);
        assert_eq!(value_bytes("x").len(), 3);
    }

    #[test]
    fn encodes_a_save_request() {
        let record = OutgoingRecord {
            name: "item-1".into(),
            record_type: "item".into(),
            etag: Some("etag-1".into()),
            semantics: SAVE_UPDATE,
            fields: vec![
                plain("data", FieldValue::Bytes(vec![1, 2, 3])),
                plain("srvr", FieldValue::Text("example.com".into())),
                plain("count", FieldValue::Int(42)),
                plain("ratio", FieldValue::Double(3.5)),
                plain("parent", FieldValue::Reference("parent-1".into())),
                plain("when", FieldValue::Date(1_700_000_000)),
            ],
            plugin_fields: Vec::new(),
            delete_fields: vec!["obsolete".into()],
            share_info: None,
            stable_url: None,
            pcs_key: None,
            zone_protection_tag: None,
            record_protection_tag: None,
        };
        let request = save_request(&record, "zone-1", "owner-1");
        let top = fields_of(request.as_slice());

        assert_eq!(field(&top, 6).varint().unwrap(), 3);
        assert_eq!(field(&top, 2).varint().unwrap(), 1);
        let deleted: Vec<&str> = top
            .iter()
            .filter(|f| f.number == 3)
            .map(|f| f.string().unwrap())
            .collect();
        assert_eq!(deleted, vec!["obsolete"]);

        let record_fields = fields_of(field(&top, 1).bytes().unwrap());
        assert_eq!(
            field(&record_fields, 1).string().unwrap(),
            "etag-1",
            "record etag"
        );

        let identifier = field(&record_fields, 2).message().unwrap();
        assert_eq!(parse_identifier(identifier).unwrap(), "item-1");
        let record_identifier_fields = fields_of(field(&record_fields, 2).bytes().unwrap());
        assert_eq!(
            parse_zone_identifier(field(&record_identifier_fields, 2).message().unwrap()).unwrap(),
            ("zone-1".to_string(), "owner-1".to_string())
        );

        let record_type = fields_of(field(&record_fields, 3).bytes().unwrap());
        assert_eq!(field(&record_type, 1).string().unwrap(), "item");

        let data = fields_of(record_value(&record_fields, "data"));
        assert_eq!(field(&data, 1).varint().unwrap(), 1, "bytes type");
        assert_eq!(field(&data, 2).bytes().unwrap(), &[1, 2, 3]);

        let text = fields_of(record_value(&record_fields, "srvr"));
        assert_eq!(field(&text, 1).varint().unwrap(), 3, "string type");
        assert_eq!(field(&text, 7).string().unwrap(), "example.com");

        let count = fields_of(record_value(&record_fields, "count"));
        assert_eq!(field(&count, 1).varint().unwrap(), 7, "int64 type");
        assert_eq!(field(&count, 4).varint().unwrap(), 42);

        let ratio = fields_of(record_value(&record_fields, "ratio"));
        assert_eq!(field(&ratio, 1).varint().unwrap(), 8, "double type");
        assert_eq!(field(&ratio, 5).varint().unwrap(), 3.5f64.to_bits());

        let when = fields_of(record_value(&record_fields, "when"));
        assert_eq!(field(&when, 1).varint().unwrap(), 2, "date type");
        let date = fields_of(field(&when, 6).bytes().unwrap());
        assert_eq!(
            field(&date, 1).varint().unwrap(),
            (1_700_000_000f64).to_bits()
        );

        let reference = fields_of(record_value(&record_fields, "parent"));
        assert_eq!(field(&reference, 1).varint().unwrap(), 5, "reference type");
        let reference = fields_of(field(&reference, 9).bytes().unwrap());
        assert_eq!(
            field(&reference, 1).varint().unwrap(),
            3,
            "validating reference"
        );
        let target = field(&reference, 2).message().unwrap();
        assert_eq!(parse_identifier(target).unwrap(), "parent-1");
        let target_fields = fields_of(field(&reference, 2).bytes().unwrap());
        assert_eq!(
            parse_zone_identifier(field(&target_fields, 2).message().unwrap()).unwrap(),
            ("zone-1".to_string(), "owner-1".to_string())
        );
    }

    #[test]
    fn encodes_a_date_as_a_double() {
        let record = OutgoingRecord {
            name: "item-1".into(),
            record_type: "item".into(),
            etag: None,
            semantics: SAVE_CREATE,
            fields: vec![plain("when", FieldValue::Date(1_700_000_000))],
            plugin_fields: Vec::new(),
            delete_fields: Vec::new(),
            share_info: None,
            stable_url: None,
            pcs_key: None,
            zone_protection_tag: None,
            record_protection_tag: None,
        };
        let request = save_request(&record, "zone-1", "owner-1");
        let top = fields_of(request.as_slice());
        let record_fields = fields_of(field(&top, 1).bytes().unwrap());

        let when = fields_of(record_value(&record_fields, "when"));
        let date_value = field(&when, 6);
        let date = fields_of(date_value.bytes().unwrap());
        let time = field(&date, 1);
        assert!(
            matches!(time.value, wire::Value::Fixed64(_)),
            "date time must be a fixed64 double, got {:?}",
            time.value
        );
        assert_eq!(time.varint().unwrap(), (1_700_000_000f64).to_bits());

        let parsed = parse_record(field(&top, 1).bytes().unwrap()).unwrap();
        assert_eq!(parsed.int("when"), Some(1_700_000_000));
    }

    fn protection(der: &[u8], tag: &str) -> Writer {
        let mut info = Writer::new();
        info.bytes(1, der);
        info.string(2, tag);
        info
    }

    #[test]
    fn encodes_a_zone_save_and_delete_request() {
        let zone_der = vec![0x61, 0x03, 0x30, 0x01, 0x00];
        let record_der = vec![0x61, 0x03, 0x30, 0x01, 0x01];
        let zone_protection = ProtectionInfoBytes::tagged(zone_der.clone());
        assert_eq!(zone_protection.tag.as_deref().map(str::len), Some(40));
        let zone = OutgoingZone {
            name: "group-1234".into(),
            etag: Some("zone-etag".into()),
            protection_info: Some(zone_protection.message()),
            record_protection_info: Some(
                ProtectionInfoBytes::untagged(record_der.clone()).message(),
            ),
        };

        let request = zone_save_request(&zone, "owner-1");
        let top = fields_of(request.as_slice());
        let message = fields_of(field(&top, 1).bytes().unwrap());
        assert_eq!(
            parse_zone_identifier(field(&message, 1).message().unwrap()).unwrap(),
            ("group-1234".to_string(), "owner-1".to_string())
        );
        assert_eq!(field(&message, 2).string().unwrap(), "zone-etag");

        let protection = fields_of(field(&message, 3).bytes().unwrap());
        assert_eq!(field(&protection, 1).bytes().unwrap(), zone_der);
        assert_eq!(
            field(&protection, 2).string().unwrap(),
            zone_protection.tag.clone().unwrap()
        );

        let record_protection = fields_of(field(&message, 6).bytes().unwrap());
        assert_eq!(field(&record_protection, 1).bytes().unwrap(), record_der);
        assert!(
            record_protection.iter().all(|item| item.number != 2),
            "record protections are saved untagged"
        );

        let delete = zone_delete_request("group-1234", "owner-1");
        let top = fields_of(delete.as_slice());
        assert_eq!(
            parse_zone_identifier(field(&top, 1).message().unwrap()).unwrap(),
            ("group-1234".to_string(), "owner-1".to_string())
        );
        assert_eq!(field(&top, 2).varint().unwrap(), 0);

        let mut frame = Writer::new();
        frame.message(200, &Writer::new());
        let mut result = Writer::new();
        result.uint64(1, 1);
        frame.message(3, &result);
        assert!(
            parse_outcome(frame.as_slice()).unwrap().ok(),
            "zone save code 1"
        );

        let mut frame = Writer::new();
        frame.message(202, &Writer::new());
        frame.message(3, &result);
        assert!(
            parse_outcome(frame.as_slice()).unwrap().ok(),
            "zone delete code 1"
        );
    }

    #[test]
    fn a_save_request_carries_the_zone_protection_tag() {
        let record = OutgoingRecord {
            name: "cloudkit.zoneshare".into(),
            record_type: "cloudkit.share".into(),
            etag: None,
            semantics: SAVE_UPDATE,
            fields: Vec::new(),
            plugin_fields: Vec::new(),
            delete_fields: Vec::new(),
            share_info: None,
            stable_url: None,
            pcs_key: Some(vec![1, 2, 3, 4]),
            zone_protection_tag: Some("ABCDEF".into()),
            record_protection_tag: Some("123456".into()),
        };
        let request = save_request(&record, "group-1", "owner-1");
        let top = fields_of(request.as_slice());

        assert_eq!(field(&top, 7).string().unwrap(), "ABCDEF");
        assert_eq!(field(&top, 8).string().unwrap(), "123456");
        let record_fields = fields_of(field(&top, 1).bytes().unwrap());
        assert_eq!(field(&record_fields, 24).bytes().unwrap(), &[1, 2, 3, 4]);
        assert_eq!(OP_ZONE_SAVE, 200);
        assert_eq!(OP_ZONE_DELETE, 202);
    }

    fn participant(name: &str, id: &[u8], public_key: &[u8]) -> Writer {
        let mut identifier = Writer::new();
        identifier.string(1, name);
        identifier.uint64(2, 7);

        let mut contact = Writer::new();
        contact.string(1, "ada@example.com");
        contact.string(2, "cuid-1");
        contact.string(3, "Ada");
        contact.string(4, "Lovelace");
        contact.string(5, "+15550100");
        contact.string(6, "+15550101");

        let mut participant = Writer::new();
        participant.bytes(1, id);
        participant.message(2, &identifier);
        participant.message(3, &contact);
        participant.uint64(4, 2);
        participant.uint64(5, 1);
        participant.uint64(6, 3);
        participant.message(9, &protection(public_key, "ABCD"));
        participant.message(11, &protection(&[9u8; 32], "EF01"));
        participant.uint64(14, 1);
        participant.bytes(19, public_key);
        participant
    }

    #[test]
    fn round_trips_a_share_record_through_a_save() {
        let mut share_identifier_value = Writer::new();
        share_identifier_value.string(1, "share-1");
        share_identifier_value.uint64(2, 1);
        let mut share_identifier = Writer::new();
        share_identifier.message(1, &share_identifier_value);

        let mut share = Writer::new();
        share.message(1, &share_identifier);
        share.string(2, "share-etag");
        share.uint64(3, 3);
        share.message(4, &protection(&[7u8; 32], "1111"));
        share.message(5, &protection(&[8u8; 32], "2222"));
        share.message(6, &participant("user-1", b"pid-1", &[1u8; 32]));
        share.message(6, &participant("user-2", b"pid-2", &[2u8; 32]));
        share.string(7, "routing-1");
        share.bytes(9, b"removed-key");
        share.uint64(10, 1);
        share.uint64(11, 0);
        share.string(12, "example.icloud.com");
        share.uint64(13, 4);
        share.uint64(14, 2);
        share.uint64(15, 1);
        share.bytes(20, b"signing-key");
        share.uint64(21, 1);
        share.bytes(101, &[3u8; 32]);
        share.string(102, "https://example.icloud.com");
        let share_bytes = share.finish();

        let mut stable = Writer::new();
        stable.string(1, "stable-routing");
        stable.bytes(2, &[4u8; 32]);
        stable.bytes(3, b"full-token");
        stable.bytes(4, b"public-sharing-key");
        stable.string(5, "example.icloud.com");
        let stable_bytes = stable.finish();

        let record = OutgoingRecord {
            name: "cloudkit.zoneshare".into(),
            record_type: "cloudkit.share".into(),
            etag: Some("record-etag".into()),
            semantics: SAVE_UPDATE,
            fields: vec![plain("displayName", FieldValue::Bytes(vec![5, 5, 5]))],
            plugin_fields: vec![
                plain("plugin-a", FieldValue::Text("value-a".into())),
                plain("plugin-b", FieldValue::Bytes(vec![6, 6])),
            ],
            delete_fields: Vec::new(),
            share_info: Some(share_bytes.clone()),
            stable_url: Some(stable_bytes.clone()),
            pcs_key: Some(vec![0xaa, 0xbb]),
            zone_protection_tag: None,
            record_protection_tag: None,
        };
        let request = save_request(&record, "group-1", "owner-1");
        let top = fields_of(request.as_slice());
        let record_fields = fields_of(field(&top, 1).bytes().unwrap());

        let plugin_b = fields_of(record_field_value(&record_fields, 12, "plugin-b"));
        assert_eq!(field(&plugin_b, 1).varint().unwrap(), 1, "plugin bytes");
        assert_eq!(field(&plugin_b, 2).bytes().unwrap(), &[6, 6]);

        let parsed = parse_record(field(&top, 1).bytes().unwrap()).unwrap();
        assert_eq!(parsed.name, "cloudkit.zoneshare");
        assert_eq!(parsed.record_type, "cloudkit.share");
        assert_eq!(parsed.etag.as_deref(), Some("record-etag"));
        assert_eq!(parsed.permission, None, "permission is not written");
        assert_eq!(parsed.pcs_key.as_deref(), Some([0xaa, 0xbb].as_slice()));

        assert_eq!(parsed.plugin_fields.len(), 2);
        assert_eq!(parsed.plugin_fields[0].0, "plugin-a");
        assert!(matches!(&parsed.plugin_fields[0].1, FieldValue::Text(text) if text == "value-a"));
        assert_eq!(parsed.plugin_fields[1].0, "plugin-b");
        assert!(matches!(
            &parsed.plugin_fields[1].1,
            FieldValue::Bytes(bytes) if bytes == &[6, 6]
        ));

        let share = parsed.share_info.expect("share info");
        assert_eq!(share.raw, share_bytes, "raw share bytes survive the trip");
        assert_eq!(
            share.identifier.as_deref(),
            Some(share_identifier.as_slice())
        );
        assert_eq!(share.etag.as_deref(), Some("share-etag"));
        assert_eq!(share.public_access, 3);
        let invited = share.invited_pcs.as_ref().expect("invited pcs");
        assert_eq!(invited.der, [7u8; 32]);
        assert_eq!(invited.tag.as_deref(), Some("1111"));
        let self_added = share.self_added_pcs.as_ref().expect("self added pcs");
        assert_eq!(self_added.der, [8u8; 32]);
        assert_eq!(self_added.tag.as_deref(), Some("2222"));
        assert_eq!(share.short_token_routing_key.as_deref(), Some("routing-1"));
        assert_eq!(share.invited_key_to_removes, vec![b"removed-key".to_vec()]);
        assert!(share.publisher_model);
        assert!(!share.annonymous_public_access);
        assert_eq!(
            share.displayed_hostname.as_deref(),
            Some("example.icloud.com")
        );
        assert_eq!(share.publisher_model_type, 4);
        assert_eq!(share.participant_self_removal_behavior, 2);
        assert!(share.deny_access_requests);
        assert_eq!(
            share.crypto_requirements_signing_key.as_deref(),
            Some(b"signing-key".as_slice())
        );
        assert!(share.allow_anyone_to_resolve_share);
        assert_eq!(
            share.short_token_hash.as_deref(),
            Some([3u8; 32].as_slice())
        );
        assert_eq!(share.origin.as_deref(), Some("https://example.icloud.com"));

        assert_eq!(share.participants.len(), 2);
        let first = &share.participants[0];
        assert_eq!(first.participant_id.as_deref(), Some(b"pid-1".as_slice()));
        assert_eq!(first.user_id.as_deref(), Some("user-1"));
        assert_eq!(first.state, 2);
        assert_eq!(first.participant_type, 1);
        assert_eq!(first.permission, 3);
        assert_eq!(first.public_key.as_deref(), Some([1u8; 32].as_slice()));
        let first_protection = first.protection_info.as_ref().expect("participant pcs");
        assert_eq!(first_protection.der, [9u8; 32]);
        assert_eq!(first_protection.tag.as_deref(), Some("EF01"));
        assert_eq!(
            first
                .protection_info_public_key
                .as_ref()
                .map(|info| &info.der),
            Some(&[1u8; 32].to_vec())
        );
        assert_eq!(first.public_key_version, 1);
        let contact = first.contact.as_ref().expect("contact");
        assert_eq!(contact.email_address.as_deref(), Some("ada@example.com"));
        assert_eq!(contact.container_scoped_user_id.as_deref(), Some("cuid-1"));
        assert_eq!(contact.first_name.as_deref(), Some("Ada"));
        assert_eq!(contact.last_name.as_deref(), Some("Lovelace"));
        assert_eq!(contact.phone_number.as_deref(), Some("+15550100"));
        assert_eq!(contact.canonical_phone_number.as_deref(), Some("+15550101"));
        assert_eq!(share.participants[1].user_id.as_deref(), Some("user-2"));

        let url = parsed.stable_url.expect("stable url");
        assert_eq!(url.raw, stable_bytes);
        assert_eq!(url.routing_key.as_deref(), Some("stable-routing"));
        assert_eq!(url.short_token_hash.as_deref(), Some([4u8; 32].as_slice()));
        assert_eq!(
            url.protected_full_token.as_deref(),
            Some(b"full-token".as_slice())
        );
        assert_eq!(
            url.encrypted_public_sharing_key.as_deref(),
            Some(b"public-sharing-key".as_slice())
        );
        assert_eq!(
            url.displayed_hostname.as_deref(),
            Some("example.icloud.com")
        );
    }

    #[test]
    fn a_display_name_only_record_has_no_share() {
        let mut name = Writer::new();
        name.string(1, "cloudkit.zoneshare");
        let mut identifier = Writer::new();
        identifier.message(1, &name);
        let mut record_type = Writer::new();
        record_type.string(1, "cloudkit.zoneshare");
        let mut field = Writer::new();
        field.string(1, "displayName");
        field.message(2, &{
            let mut value = Writer::new();
            value.bytes(2, b"sealed");
            value
        });
        let mut record = Writer::new();
        record.message(2, &identifier);
        record.message(3, &record_type);
        record.message(7, &field);

        let parsed = parse_record(record.as_slice()).unwrap();
        assert_eq!(parsed.name, "cloudkit.zoneshare");
        assert_eq!(parsed.bytes("displayName"), Some(b"sealed".as_slice()));
        assert!(parsed.share_info.is_none());
        assert!(parsed.stable_url.is_none());
        assert!(parsed.plugin_fields.is_empty());
        assert_eq!(parsed.permission, None);
        assert!(parsed.pcs_key.is_none());
    }

    #[test]
    fn a_malformed_share_info_keeps_the_raw_bytes() {
        let mut record_type = Writer::new();
        record_type.string(1, "cloudkit.zoneshare");
        // Field 1 claims five bytes but only one follows.
        let malformed = vec![0x0a, 0x05, 0x01];
        let mut record = Writer::new();
        record.message(3, &record_type);
        record.bytes(16, &malformed);

        let parsed = parse_record(record.as_slice()).unwrap();
        let share = parsed.share_info.expect("raw share is kept");
        assert_eq!(share.raw, malformed);
        assert!(share.participants.is_empty());
        assert!(share.invited_pcs.is_none());
        assert!(share.displayed_hostname.is_none());
    }

    #[test]
    fn parses_record_permission() {
        let mut record_type = Writer::new();
        record_type.string(1, "cloudkit.share");
        let mut record = Writer::new();
        record.message(3, &record_type);
        record.uint64(15, 2);

        let parsed = parse_record(record.as_slice()).unwrap();
        assert_eq!(parsed.permission, Some(2));
    }

    #[test]
    fn an_encrypted_field_is_bytes_type_twenty() {
        let record = OutgoingRecord {
            name: "item-1".into(),
            record_type: "item".into(),
            etag: None,
            semantics: SAVE_CREATE,
            fields: vec![OutgoingField {
                name: "payload".into(),
                value: FieldValue::Bytes(vec![1, 2, 3]),
                encrypted: true,
                encrypted_string: false,
                encrypted_int: false,
            }],
            plugin_fields: Vec::new(),
            delete_fields: Vec::new(),
            share_info: None,
            stable_url: None,
            pcs_key: None,
            zone_protection_tag: None,
            record_protection_tag: None,
        };
        let request = save_request(&record, "zone-1", "owner-1");
        let top = fields_of(request.as_slice());
        let record_fields = fields_of(field(&top, 1).bytes().unwrap());

        let value = fields_of(record_field_value(&record_fields, 7, "payload"));
        assert_eq!(field(&value, 1).varint().unwrap(), ENCRYPTED_BYTES_TYPE);
        assert_eq!(field(&value, 13).varint().unwrap(), 1, "isEncrypted");
        assert_eq!(field(&value, 2).bytes().unwrap(), &[1, 2, 3]);

        let parsed = parse_record(field(&top, 1).bytes().unwrap()).unwrap();
        assert_eq!(parsed.bytes("payload"), Some([1, 2, 3].as_slice()));
    }

    #[test]
    fn parses_a_save_response_etag() {
        let mut server_fields = Writer::new();
        server_fields.string(1, "etag-server");
        let mut save_response = Writer::new();
        save_response.message(4, &server_fields);

        let mut result = Writer::new();
        result.uint64(1, 1);
        let mut response = Writer::new();
        response.message(3, &result);
        response.message(210, &save_response);

        let outcome = parse_outcome(response.as_slice()).unwrap().check().unwrap();
        assert_eq!(outcome.record.unwrap().etag.as_deref(), Some("etag-server"));
    }

    #[test]
    fn parses_a_delete_result() {
        let mut result = Writer::new();
        result.uint64(1, 1);
        let mut response = Writer::new();
        response.message(3, &result);
        response.message(214, &Writer::new());

        let outcome = parse_outcome(response.as_slice()).unwrap().check().unwrap();
        assert!(outcome.record.is_none());
        assert!(outcome.etag_match.is_none());
    }

    #[test]
    fn surfaces_a_client_error() {
        let mut client = Writer::new();
        client.uint64(1, 60);
        let mut error = Writer::new();
        error.message(1, &client);
        error.string(4, "stale record update");

        let mut result = Writer::new();
        result.uint64(1, 3);
        result.message(2, &error);
        let mut response = Writer::new();
        response.message(3, &result);

        let outcome = parse_outcome(response.as_slice()).unwrap();
        assert_eq!(outcome.client_code, Some(60));
        let error = outcome.check().unwrap_err();
        match &error {
            Error::CloudKit { code, description } => {
                assert_eq!(*code, 60);
                assert!(description
                    .as_deref()
                    .unwrap()
                    .contains("stale record update"));
            }
            other => panic!("expected a CloudKit error, got {other:?}"),
        }
        let text = error.to_string();
        assert!(text.contains("stale record update"));
        assert!(text.contains("60"));
    }

    #[test]
    fn parses_a_retrieve_response_with_etag_mismatch() {
        let mut type_name = Writer::new();
        type_name.string(1, "item");
        let mut record = Writer::new();
        record.message(3, &type_name);

        let mut retrieve = Writer::new();
        retrieve.message(1, &record);
        retrieve.boolean(2, false);

        let mut result = Writer::new();
        result.uint64(1, 1);
        let mut response = Writer::new();
        response.message(3, &result);
        response.message(211, &retrieve);

        let outcome = parse_outcome(response.as_slice()).unwrap().check().unwrap();
        assert_eq!(outcome.etag_match, Some(false));
        assert_eq!(outcome.record.unwrap().record_type, "item");
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
