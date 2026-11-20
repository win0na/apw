//! Owner-side group creation.
//!
//! A group is a private CloudKit zone in the shared keychain container plus a
//! `cloudkit.zoneshare` record that carries the PCS keys. Apple creates the
//! zone with `zone/save`, then saves the share with the rolled zone embedded in
//! its `___zoneUpdateData` plugin field, so one record save rotates the zone
//! and record protections.
//!
//! This module only creates owner-only groups: the participant is this
//! account, there are no invitations, and no share URL is minted.

use aes::Aes128;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, Nonce};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::cloudkit::{
    self, FieldValue, Gateway, OutgoingField, OutgoingRecord, OutgoingZone, ProtectionInfoBytes,
    SAVE_UPDATE,
};
use crate::error::{Error, Result};
use crate::pcs::{
    self, create_protection, roll_protection, Decoded, ParticipantSpec, PcsKey, Protection,
    ProtectionSpec, ServiceKey,
};
use crate::wire::Writer;

/// The share record's name and CloudKit type.
pub const SHARE_RECORD: &str = "cloudkit.zoneshare";
const SHARE_TYPE: &str = "cloudkit.share";
/// The plugin field that carries the rolled `ZoneSaveRequest`.
const ZONE_UPDATE_FIELD: &str = "___zoneUpdateData";
const DISPLAYED_HOSTNAME: &str = "www.icloud.com";
/// `participantPublicKeyVersion` Apple writes for a PCS participant.
const PUBLIC_KEY_VERSION: u64 = 211;

/// The protections already on a zone, and the roll counts to advance from.
struct ZoneState {
    zone: Decoded,
    record: Decoded,
    zone_roll: u32,
    record_roll: u32,
}

/// The keys a first share needs, with the protections that carry them.
struct ShareKeys {
    participant_key: SecretKey,
    participant_protection: Protection,
    invited_key: SecretKey,
    invited_protection: Protection,
    self_ec: SecretKey,
    self_added_protection: Protection,
}

/// Create the zone so a share has something to attach to.
pub async fn create(
    gateway: &Gateway,
    service_keys: &[ServiceKey],
    zone: &str,
    name: &str,
) -> Result<()> {
    let service = service_keys.first().ok_or_else(|| {
        Error::Message(
            "no Manatee PCS service key; run `apw sync` and try again (the group zone is kept)"
                .into(),
        )
    })?;

    let state = match gateway.zone_retrieve(zone, gateway.user_id()).await {
        Ok(existing) => resume(&existing, service_keys)?,
        Err(error) if missing_zone(&error) => create_zone(gateway, service, zone).await?,
        Err(error) => return Err(error),
    };

    let keys = share_keys(service)?;

    // The zone roll adds one and the record roll adds two to the count the
    // server already holds.
    let (zone_protection, _) = roll_protection(
        &state.zone,
        &service.secret,
        vec![keys.invited_key.clone()],
        &service.secret,
        state.zone_roll + 1,
        Vec::new(),
        true,
    )?;
    // The record protection follows the zone identity that the rolled zone
    // protection still lists, so a reader can unwrap it.
    let zone_identity = state.zone.identities.first().ok_or_else(|| {
        Error::Message(format!(
            "zone {zone} has no zone identity to roll the record for"
        ))
    })?;
    let (record_protection, record_keys) = roll_protection(
        &state.record,
        zone_identity,
        Vec::new(),
        zone_identity,
        state.record_roll + 2,
        state.record.keys.clone(),
        false,
    )?;
    let record_key = record_keys
        .last()
        .ok_or_else(|| Error::Message("the rolled record protection has no key".into()))?;

    let zone_tag = ProtectionInfoBytes::tagged(zone_protection.encode()?)
        .tag
        .ok_or_else(|| Error::Message("the rolled zone protection has no tag".into()))?;
    let plugin = zone_update(
        zone,
        gateway.user_id(),
        &zone_protection,
        &record_protection,
    )?;

    let (token_hash, sharing_key, protected_token) = share_token(&keys.self_ec)?;
    let mut stable_url = Writer::new();
    stable_url.bytes(2, &token_hash);
    stable_url.bytes(3, &protected_token);
    stable_url.bytes(
        4,
        &record_key.encrypt(
            &sharing_key,
            format!("{zone}-{SHARE_RECORD}-encryptedPublicSharingKey").as_bytes(),
        )?,
    );
    stable_url.string(5, DISPLAYED_HOSTNAME);
    let stable_url = stable_url.finish();
    let record = OutgoingRecord {
        name: SHARE_RECORD.into(),
        record_type: SHARE_TYPE.into(),
        etag: None,
        semantics: SAVE_UPDATE,
        fields: vec![OutgoingField {
            name: "displayName".into(),
            value: FieldValue::Bytes(display_name(record_key, zone, name)?),
            encrypted: true,
            encrypted_string: true,
        }],
        plugin_fields: vec![OutgoingField {
            name: ZONE_UPDATE_FIELD.into(),
            value: FieldValue::Bytes(plugin),
            encrypted: false,
            encrypted_string: false,
        }],
        delete_fields: Vec::new(),
        share_info: Some(share_info(
            zone,
            gateway.user_id(),
            &keys,
            service,
            &token_hash,
        )),
        stable_url: Some(stable_url),
        pcs_key: Some(record_key.key_id()[..4].to_vec()),
        zone_protection_tag: Some(zone_tag),
        record_protection_tag: None,
    };
    gateway.save_record(zone, None, &record).await?;
    Ok(())
}

/// A zone that already exists: either the one this run is resuming or a zone
/// somebody else owns. Only a zone whose protection opens with our service key
/// is touched.
fn resume(zone: &cloudkit::Zone, service_keys: &[ServiceKey]) -> Result<ZoneState> {
    let der = zone.protection_info.as_deref().ok_or_else(|| {
        Error::Message(format!(
            "zone {} exists without a protection info; refusing to touch it",
            zone.name
        ))
    })?;
    let protection = Protection::parse(der)?;
    let decoded = service_keys
        .iter()
        .find_map(|key| {
            protection
                .decode(std::slice::from_ref(&key.secret), false)
                .ok()
        })
        .ok_or_else(|| {
            Error::Message(format!(
                "zone {} exists and its protection does not open with this account's keys; \
                 refusing to touch a group apw did not create",
                zone.name
            ))
        })?;
    let record_der = zone.record_protection_info.as_deref().ok_or_else(|| {
        Error::Message(format!(
            "zone {} has no record protection; refusing to touch it",
            zone.name
        ))
    })?;
    let record_protection = Protection::parse(record_der)?;
    let record = record_protection.decode(&decoded.identities, false)?;
    Ok(ZoneState {
        zone_roll: protection.roll_count()?,
        record_roll: record_protection.roll_count()?,
        zone: decoded,
        record,
    })
}

/// Save a fresh zone at roll count 1, then read back exactly what a later run
/// would resume from.
async fn create_zone(gateway: &Gateway, service: &ServiceKey, zone: &str) -> Result<ZoneState> {
    let zone_key = random_key();
    let (zone_protection, _) = create_protection(&ProtectionSpec {
        me: &service.secret,
        identities: vec![zone_key.clone()],
        access: Vec::new(),
        sign_with: Some(&service.secret),
        last: None,
        roll: 1,
        is_share: false,
        extra_keys: Vec::new(),
        participant: None,
    })?;
    let (record_protection, _) = create_protection(&ProtectionSpec {
        me: &zone_key,
        identities: Vec::new(),
        access: Vec::new(),
        sign_with: Some(&zone_key),
        last: None,
        roll: 1,
        is_share: false,
        extra_keys: Vec::new(),
        participant: None,
    })?;

    let zone_bytes = zone_protection.encode()?;
    let record_bytes = record_protection.encode()?;
    gateway
        .save_zone(&OutgoingZone {
            name: zone.to_string(),
            etag: None,
            protection_info: Some(ProtectionInfoBytes::tagged(zone_bytes).message()),
            record_protection_info: Some(ProtectionInfoBytes::untagged(record_bytes).message()),
        })
        .await?;

    let zone = Protection::parse(&zone_protection.encode()?)?
        .decode(std::slice::from_ref(&service.secret), false)?;
    let record =
        Protection::parse(&record_protection.encode()?)?.decode(&zone.identities, false)?;
    Ok(ZoneState {
        zone_roll: 1,
        record_roll: 1,
        zone,
        record,
    })
}

/// The participant and share protections of a first share.
///
/// The participant protection is wrapped for the service key we own, the
/// invited protection for the fresh participant key, and the self-added
/// protection for the invited key. Every protection that signs is signed by a
/// key we can hand to Apple's verifier: the service key for the participant and
/// the invited roll, the zone identity for the record.
fn share_keys(service: &ServiceKey) -> Result<ShareKeys> {
    let participant_key = random_key();
    let (participant_protection, _) = create_protection(&ProtectionSpec {
        me: &service.secret,
        identities: vec![participant_key.clone()],
        access: Vec::new(),
        sign_with: None,
        last: None,
        roll: 1,
        is_share: true,
        extra_keys: Vec::new(),
        // Attributes 8 and 9 name the sharing key and its signer; attribute 7
        // is the signer's signature over the protection digest.
        participant: Some(ParticipantSpec {
            share_key: compressed(&service.secret),
            sign_with: Some(&service.secret),
        }),
    })?;
    let invited_key = random_key();
    let (invited_protection, _) = create_protection(&ProtectionSpec {
        me: &participant_key,
        identities: vec![invited_key.clone()],
        access: Vec::new(),
        sign_with: Some(&service.secret),
        last: None,
        roll: 1,
        is_share: true,
        extra_keys: Vec::new(),
        participant: None,
    })?;

    let self_ec = random_key();
    let (self_added_protection, _) = create_protection(&ProtectionSpec {
        me: &invited_key,
        identities: vec![self_ec.clone()],
        access: vec![self_ec.clone()],
        sign_with: None,
        last: None,
        roll: 1,
        is_share: false,
        extra_keys: Vec::new(),
        participant: None,
    })?;

    Ok(ShareKeys {
        participant_key,
        participant_protection,
        invited_key,
        invited_protection,
        self_ec,
        self_added_protection,
    })
}

/// The `displayName` ciphertext: field 6 of Apple's encrypted-value message.
fn display_name(record_key: &PcsKey, zone: &str, name: &str) -> Result<Vec<u8>> {
    let mut plain = Writer::new();
    plain.string(6, name);
    let aad = format!("{zone}-{SHARE_RECORD}-displayName");
    pcs::encrypt_field(record_key, &plain.finish(), aad.as_bytes())
}

/// The serialized `ZoneSaveRequest` the plugin field carries.
pub(crate) fn zone_update(
    zone: &str,
    owner: &str,
    zone_protection: &Protection,
    record_protection: &Protection,
) -> Result<Vec<u8>> {
    // The plugin carries the Zone message itself, not a ZoneSaveRequest
    // envelope: CloudKit applies it before it looks up the protection tag the
    // record save names, so an extra wrapper is rejected with code 53.
    let message = cloudkit::zone_message(
        &OutgoingZone {
            name: zone.to_string(),
            etag: None,
            protection_info: Some(ProtectionInfoBytes::tagged(zone_protection.encode()?).message()),
            record_protection_info: Some(
                ProtectionInfoBytes::untagged(record_protection.encode()?).message(),
            ),
        },
        owner,
    );
    Ok(message.finish())
}

/// Build the `shareInfo` message for the zoneshare record.
///
/// Fields written: 1 identifier, 3 publicAccess, 4 invited PCS, 5 self-added
/// PCS, 6 the self participant, 12 displayed hostname, 13 publisher model type,
/// 14 participant self-removal behavior, 15 deny access requests, and 22/23 the
/// empty key-removal lists Apple sends.
fn share_info(
    zone: &str,
    owner: &str,
    keys: &ShareKeys,
    service: &ServiceKey,
    token_hash: &[u8],
) -> Vec<u8> {
    let mut share_id_value = Writer::new();
    share_id_value.string(1, SHARE_RECORD);
    share_id_value.uint64(2, 4); // SHARE
    let mut share_id = Writer::new();
    share_id.message(1, &share_id_value);
    share_id.message(2, &cloudkit::zone_identifier_writer(zone, owner));

    let mut out = Writer::new();
    out.message(1, &share_id);
    out.uint64(3, 1); // publicAccess
    out.message(4, &protection_only(&keys.invited_protection));
    out.message(5, &protection_only(&keys.self_added_protection));
    out.message(
        6,
        &self_participant(owner, keys, &compressed(&service.secret)),
    );
    out.string(12, DISPLAYED_HOSTNAME);
    out.uint64(13, 1); // publisherModelType
    out.uint64(14, 3); // participantSelfRemovalBehavior
    out.boolean(15, true); // denyAccessRequests
    out.message(22, &Writer::new());
    out.message(23, &Writer::new());
    // Field 101 is the short-token hash; the server derives the routing key
    // from it and stores a stable URL.
    out.bytes(101, token_hash);
    out.finish()
}

/// The participant that represents this account in the share.
fn self_participant(owner: &str, keys: &ShareKeys, service_public: &[u8]) -> Writer {
    let mut participant_id = Writer::new();
    participant_id.string(1, &cloudkit::uppercase_uuid());
    participant_id.uint64(2, 7); // USER

    let mut user = Writer::new();
    user.string(1, owner);
    user.uint64(2, 7); // USER

    let mut participant = Writer::new();
    participant.message(1, &participant_id);
    participant.message(2, &user);
    participant.message(3, &Writer::new()); // contactInformation
    participant.uint64(4, 2); // state: accepted
    participant.uint64(5, 1); // participantType: owner
    participant.uint64(6, 3); // permission
    participant.boolean(8, true); // createdInProcess
                                  // CloudKit and Apple's app store the raw X coordinate here, not the SEC1
                                  // compressed point used by key references.
    participant.message(9, &protection_only_bytes(&x_only(service_public))); // publicKey
    participant.message(11, &protection_only(&keys.participant_protection)); // protectionInfo
    participant.uint64(14, PUBLIC_KEY_VERSION);
    participant.boolean(15, false); // acceptedInProcess
    participant.boolean(18, false); // isOrgUser
    participant.bytes(19, &compressed(&keys.participant_key)); // protectionInfoPublicKey
    participant.uint64(20, 1); // keyHealth
    participant.boolean(23, false); // isAnnonymousInvitedParticipant
    participant.boolean(24, false); // isApprovedRequestor
    participant
}

fn protection_only(protection: &Protection) -> Writer {
    protection_only_bytes(&protection.encode().unwrap_or_default())
}

fn protection_only_bytes(der: &[u8]) -> Writer {
    let mut out = Writer::new();
    out.bytes(1, der);
    out
}

/// The short-token hash and stable URL for a fresh share.
///
/// The token is derived from the share EC key the same way Apple does it: the
/// 32-byte private scalar goes into a PCS key reference, that reference is
/// base64url-encoded into a full token, and the first 16 bytes of its SHA-256
/// become the short token. The server fills in the routing key.
fn share_token(self_ec: &SecretKey) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use base64::Engine;

    let mut reference = vec![0x30, 0x24, 0x02, 0x01, 0x01, 0x04, 0x20];
    reference.extend_from_slice(&self_ec.to_bytes());

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let full_token = format!(
        "{}{}",
        engine.encode([0x10, 0, 0]),
        engine.encode(&reference)
    );
    let digest = Sha256::digest(full_token.as_bytes());
    let sharing_token = &digest[..16];
    let short_token = engine.encode(sharing_token);
    let hash = Sha256::digest(short_token.as_bytes()).to_vec();

    // The protected full token is the token encrypted with its own short
    // token, nonce first. CloudKit refuses a share token without it.
    let nonce: [u8; 16] = rand::random();
    let cipher = AesGcm::<Aes128, U16, U16>::new_from_slice(sharing_token)
        .map_err(|_| Error::Message("invalid sharing token length".into()))?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), full_token.as_bytes())
        .map_err(|_| Error::Message("cannot protect the share token".into()))?;
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(&encrypted);

    Ok((hash, reference, protected))
}

fn compressed(key: &SecretKey) -> Vec<u8> {
    key.public_key().to_encoded_point(true).as_bytes().to_vec()
}

fn x_only(point: &[u8]) -> Vec<u8> {
    match point {
        [0x02 | 0x03, rest @ ..] if rest.len() == 32 => rest.to_vec(),
        other => other.to_vec(),
    }
}

fn random_key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

pub(crate) fn missing_zone(error: &Error) -> bool {
    // ZONE_NOT_FOUND and USER_DELETED_DATA_FOR_ZONE are the two answers that
    // mean "create it".
    matches!(error, Error::CloudKit { code, .. } if *code == 48 || *code == 59)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudkit::FieldValue;
    use crate::wire::{Reader, Value};

    fn fields(data: &[u8]) -> Vec<crate::wire::Field<'_>> {
        Reader::new(data).fields().unwrap()
    }

    fn field<'a>(fields: &[crate::wire::Field<'a>], number: u32) -> crate::wire::Field<'a> {
        *fields.iter().find(|field| field.number == number).unwrap()
    }

    fn test_service() -> ServiceKey {
        ServiceKey {
            secret: random_key(),
            signing: None,
        }
    }

    fn test_keys() -> ShareKeys {
        share_keys(&test_service()).unwrap()
    }

    #[test]
    fn the_plugin_field_holds_a_zone_save_request() {
        let keys = test_keys();
        let encoded = zone_update(
            "group-1234",
            "owner-1",
            &keys.invited_protection,
            &keys.self_added_protection,
        )
        .unwrap();

        let zone = fields(&encoded);
        let identifier = fields(field(&zone, 1).bytes().unwrap());
        let name = fields(field(&identifier, 1).bytes().unwrap());
        assert_eq!(field(&name, 1).string().unwrap(), "group-1234");
        let protection = fields(field(&zone, 3).bytes().unwrap());
        assert_eq!(
            field(&protection, 1).bytes().unwrap(),
            keys.invited_protection.encode().unwrap()
        );
        assert_eq!(
            field(&protection, 2).string().unwrap(),
            ProtectionInfoBytes::tagged(keys.invited_protection.encode().unwrap())
                .tag
                .unwrap()
        );
        let record_protection = fields(field(&zone, 6).bytes().unwrap());
        assert_eq!(
            field(&record_protection, 1).bytes().unwrap(),
            keys.self_added_protection.encode().unwrap()
        );
        assert!(record_protection.iter().all(|item| item.number != 2));
    }

    #[test]
    fn the_plugin_outgoing_field_is_unencrypted() {
        let keys = test_keys();
        let encoded = zone_update(
            "group-1234",
            "owner-1",
            &keys.invited_protection,
            &keys.self_added_protection,
        )
        .unwrap();
        let record = OutgoingRecord {
            name: SHARE_RECORD.into(),
            record_type: SHARE_TYPE.into(),
            etag: None,
            semantics: SAVE_UPDATE,
            fields: Vec::new(),
            plugin_fields: vec![OutgoingField {
                name: ZONE_UPDATE_FIELD.into(),
                value: FieldValue::Bytes(encoded.clone()),
                encrypted: false,
                encrypted_string: false,
            }],
            delete_fields: Vec::new(),
            share_info: None,
            stable_url: None,
            pcs_key: None,
            zone_protection_tag: None,
            record_protection_tag: None,
        };
        let request = crate::cloudkit::save_request(&record, "group-1234", "owner-1");
        let top = fields(request.as_slice());
        let record_fields = fields(field(&top, 1).bytes().unwrap());
        let plugin = record_fields
            .iter()
            .filter(|field| field.number == 12)
            .find_map(|field| {
                let parts = fields(field.bytes().ok()?);
                let identifier = fields(field_of(&parts, 1).bytes().ok()?);
                if field_of(&identifier, 1).string().ok()? != ZONE_UPDATE_FIELD {
                    return None;
                }
                let value = fields(field_of(&parts, 2).bytes().ok()?);
                Some(field_of(&value, 2).bytes().ok()?.to_vec())
            })
            .expect("plugin field");
        assert_eq!(plugin, encoded);
    }

    fn field_of<'a>(fields: &[crate::wire::Field<'a>], number: u32) -> crate::wire::Field<'a> {
        *fields.iter().find(|field| field.number == number).unwrap()
    }

    #[test]
    fn the_share_info_has_the_fields_apple_writes() {
        let service = test_service();
        let keys = test_keys();
        let (token_hash, _, _) = share_token(&keys.self_ec).unwrap();
        let share = share_info("group-1234", "owner-1", &keys, &service, &token_hash);
        let top = fields(&share);

        let identifier = fields(field(&top, 1).bytes().unwrap());
        let value = fields(field(&identifier, 1).bytes().unwrap());
        assert_eq!(field(&value, 1).string().unwrap(), SHARE_RECORD);
        assert_eq!(field(&value, 2).varint().unwrap(), 4, "share identifier");
        let zone_identifier = fields(field(&identifier, 2).bytes().unwrap());
        let zone_name = fields(field(&zone_identifier, 1).bytes().unwrap());
        let owner_name = fields(field(&zone_identifier, 2).bytes().unwrap());
        assert_eq!(field(&zone_name, 1).string().unwrap(), "group-1234");
        assert_eq!(field(&owner_name, 1).string().unwrap(), "owner-1");

        assert_eq!(field(&top, 3).varint().unwrap(), 1, "publicAccess");
        assert_eq!(
            field(&fields(field(&top, 4).bytes().unwrap()), 1)
                .bytes()
                .unwrap(),
            keys.invited_protection.encode().unwrap(),
            "invited PCS"
        );
        assert_eq!(
            field(&fields(field(&top, 5).bytes().unwrap()), 1)
                .bytes()
                .unwrap(),
            keys.self_added_protection.encode().unwrap(),
            "self-added PCS"
        );

        let participant = fields(field(&top, 6).bytes().unwrap());
        assert_eq!(
            field(&fields(field(&participant, 2).bytes().unwrap()), 1)
                .string()
                .unwrap(),
            "owner-1",
            "self participant names this account"
        );
        assert_eq!(field(&participant, 4).varint().unwrap(), 2, "accepted");
        assert_eq!(field(&participant, 5).varint().unwrap(), 1, "owner");
        assert_eq!(field(&participant, 6).varint().unwrap(), 3, "permission");
        assert_eq!(
            field(&participant, 14).varint().unwrap(),
            PUBLIC_KEY_VERSION
        );
        assert_eq!(
            field(&participant, 19).bytes().unwrap(),
            compressed(&keys.participant_key),
            "participant working key"
        );
        assert_eq!(
            field(&fields(field(&participant, 11).bytes().unwrap()), 1)
                .bytes()
                .unwrap(),
            keys.participant_protection.encode().unwrap(),
            "participant protection"
        );
        let public_key = field(&fields(field(&participant, 9).bytes().unwrap()), 1)
            .bytes()
            .unwrap();
        assert_eq!(
            public_key,
            &compressed(&service.secret)[1..],
            "participant public key is the service key's X coordinate"
        );
        assert_eq!(public_key.len(), 32);

        assert_eq!(field(&top, 12).string().unwrap(), DISPLAYED_HOSTNAME);
        assert_eq!(field(&top, 13).varint().unwrap(), 1);
        assert_eq!(field(&top, 14).varint().unwrap(), 3);
        assert_eq!(field(&top, 15).varint().unwrap(), 1, "denyAccessRequests");
        assert!(matches!(field(&top, 22).value, Value::Bytes(b"")), "empty");
        assert!(matches!(field(&top, 23).value, Value::Bytes(b"")), "empty");
        assert_eq!(field(&top, 101).bytes().unwrap(), token_hash);
    }

    #[test]
    fn the_display_name_is_field_6_ciphertext() {
        let record_key = PcsKey::random();
        let sealed = display_name(&record_key, "group-1234", "Family").unwrap();
        let aad = "group-1234-cloudkit.zoneshare-displayName";
        let plain = pcs::decrypt_field(&record_key, &sealed, aad.as_bytes()).unwrap();
        let top = fields(&plain);
        assert_eq!(field(&top, 6).string().unwrap(), "Family");
        assert!(
            pcs::decrypt_field(
                &record_key,
                &sealed,
                b"group-9999-cloudkit.zoneshare-displayName"
            )
            .is_err(),
            "a different zone fails to decrypt"
        );
    }

    #[test]
    fn only_a_missing_zone_is_created() {
        assert!(missing_zone(&Error::CloudKit {
            code: 48,
            description: None
        }));
        assert!(missing_zone(&Error::CloudKit {
            code: 59,
            description: None
        }));
        assert!(!missing_zone(&Error::CloudKit {
            code: 53,
            description: None
        }));
        assert!(!missing_zone(&Error::Message("boom".into())));
    }
}
