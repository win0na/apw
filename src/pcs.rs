//! PCS (Protected Cloud Storage) share protection.
//!
//! Shared-keychain zones are encrypted with a PCS keyset. The service private
//! key is a normal synced keychain item, so this module only needs the item
//! body plus the zone metadata CloudKit returns. Everything here is read-only:
//! keys are unwrapped and used to decrypt, never created or saved.

use std::fmt::Write as _;

use aes::cipher::{BlockDecrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, Nonce};
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

const P256_KDF_PREFIX: &[u8] = &[
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x12, 0x03, 0x01, 0x08, 0x07,
];
const ANONYMOUS_SENDER: &[u8] = b"Anonymous Sender    ";

/// A PCS service key: a P-256 encryption key and, for v2 keys, a signing key.
pub struct ServiceKey {
    pub secret: SecretKey,
    pub signing: Option<SecretKey>,
}

impl ServiceKey {
    /// Parse the DER body of a `PCSPrivateKey` keychain item.
    pub fn parse_der(data: &[u8]) -> Result<Self> {
        let (outer, rest) = read_tlv(data)?;
        if !rest.is_empty() {
            return Err(Error::Message(
                "trailing bytes after PCS private key".into(),
            ));
        }

        let compact = match outer.tag {
            0x30 => {
                let fields = children(outer.value)?;
                fields
                    .first()
                    .filter(|field| field.tag == 0x04)
                    .map(|field| field.value)
                    .ok_or_else(|| Error::Message("PCS v1 key has no key body".into()))?
            }
            0x65 => {
                // [APPLICATION 5] { OCTET STRING { protobuf ProtoPCSKey } }
                let fields = children(outer.value)?;
                let body = fields
                    .first()
                    .filter(|field| field.tag == 0x04)
                    .map(|field| field.value)
                    .ok_or_else(|| Error::Message("PCS v2 key has no key body".into()))?;
                return Self::parse_proto(body);
            }
            tag => {
                return Err(Error::Message(format!(
                    "unsupported PCS private key tag {tag:#x}"
                )))
            }
        };

        Self::from_compact(compact)
    }

    fn parse_proto(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);
        let mut secret = None;
        let mut signing = None;
        while let Some(field) = reader.next()? {
            match field.number {
                1 => secret = compact_from_proto(field.bytes()?)?,
                2 => signing = compact_from_proto(field.bytes()?)?,
                _ => {}
            }
        }

        Ok(Self {
            secret: secret.ok_or_else(|| Error::Message("PCS key has no secret".into()))?,
            signing,
        })
    }

    /// Compact keys are `X || d` (64 bytes) or just `d` (32 bytes).
    pub fn from_compact(raw: &[u8]) -> Result<Self> {
        let scalar = match raw.len() {
            64 => &raw[32..],
            32 => raw,
            other => return Err(Error::Message(format!("unsupported PCS key size {other}"))),
        };
        let secret = SecretKey::from_slice(scalar)
            .map_err(|_| Error::Message("invalid PCS P-256 scalar".into()))?;
        Ok(Self {
            secret,
            signing: None,
        })
    }

    /// The 32-byte X coordinate that PCS uses as the key identifier.
    pub fn public_x(&self) -> Vec<u8> {
        let point = self.secret.public_key().to_encoded_point(true);
        point.as_bytes()[1..].to_vec()
    }
}

fn compact_from_proto(data: &[u8]) -> Result<Option<SecretKey>> {
    let mut reader = Reader::new(data);
    let mut key = None;
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            key = Some(field.bytes()?);
        }
    }
    match key {
        Some(raw) => Ok(Some(ServiceKey::from_compact(raw)?.secret)),
        None => Ok(None),
    }
}

/// A key reference: the key type and the raw public key bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsKeyRef {
    pub keytype: u64,
    pub key: Vec<u8>,
    pub trailing: Vec<Vec<u8>>,
}

/// One wrapped key in a protection keyset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsShareKey {
    pub decryption_key: PcsKeyRef,
    pub wrapped: Vec<u8>,
    pub flags: Option<u64>,
    pub trailing: Vec<Vec<u8>>,
}

/// A protection attribute: an integer key and its DER-encoded value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsAttribute {
    pub key: u64,
    pub value: Vec<u8>,
    pub trailing: Vec<Vec<u8>>,
}

/// The outer `PCSKeySet` of a protection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsKeySet {
    pub unknown1: u64,
    pub keys: Vec<PcsShareKey>,
    /// SET items that were not share keys, kept verbatim.
    pub unparsed: Vec<Vec<u8>>,
    pub attributes: Option<Vec<PcsAttribute>>,
    pub trailing: Vec<Vec<u8>>,
}

impl PcsKeySet {
    pub fn encode(&self) -> Vec<u8> {
        let mut keys: Vec<Vec<u8>> = self.keys.iter().map(PcsShareKey::encode).collect();
        keys.extend(self.unparsed.iter().cloned());
        let mut parts = vec![der_integer(self.unknown1), der_set(keys)];
        if let Some(attributes) = &self.attributes {
            parts.push(der_context(0, &encode_attributes(attributes)));
        }
        parts.extend(self.trailing.iter().cloned());
        der_sequence(parts)
    }
}

/// A `PCSSignature`: a signing key id, a digest type, and the DER signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsSignature {
    pub keyid: Vec<u8>,
    pub digest: u64,
    pub signature: Vec<u8>,
    pub trailing: Vec<Vec<u8>>,
}

impl PcsSignature {
    fn encode(&self) -> Vec<u8> {
        let mut parts = vec![
            der_octets(&self.keyid),
            der_integer(self.digest),
            der_octets(&self.signature),
        ];
        parts.extend(self.trailing.iter().cloned());
        der_context(3, &der_sequence(parts))
    }
}

/// The `[1]` signature envelope: a version and the encoded object signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsSignatureData {
    pub version: u64,
    pub signature: Vec<u8>,
    pub trailing: Vec<Vec<u8>>,
}

impl Default for PcsSignatureData {
    fn default() -> Self {
        Self {
            version: 1,
            signature: Vec::new(),
            trailing: Vec::new(),
        }
    }
}

impl PcsSignatureData {
    fn encode(&self) -> Vec<u8> {
        let mut parts = vec![der_integer(self.version), der_octets(&self.signature)];
        parts.extend(self.trailing.iter().cloned());
        der_context(1, &der_sequence(parts))
    }
}

/// A parsed `PCSShareProtection` that re-encodes to the DER it was built from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Protection {
    pub keyset: PcsKeySet,
    pub meta: Vec<u8>,
    pub signature_data: Option<PcsSignatureData>,
    pub hmac: Vec<u8>,
    pub truncated_key_id: Vec<u8>,
    pub signature: Option<PcsSignature>,
    pub attributes: Option<Vec<PcsAttribute>>,
    /// Unknown outer elements, kept verbatim so they survive a round trip.
    pub trailing: Vec<Vec<u8>>,
}

/// The result of opening a protection: working keys and the identity keys.
pub struct Decoded {
    pub keys: Vec<PcsKey>,
    pub identities: Vec<SecretKey>,
}

impl Protection {
    pub fn parse(der: &[u8]) -> Result<Self> {
        let (outer, rest) = read_tlv(der)?;
        if !rest.is_empty() {
            return Err(Error::Message(
                "trailing bytes after PCS share protection".into(),
            ));
        }
        if outer.tag != 0x61 {
            return Err(Error::Message(format!(
                "unexpected PCS protection tag {:#x}",
                outer.tag
            )));
        }

        // Apple wraps the whole protection in one more SEQUENCE inside the
        // [APPLICATION 1] tag: `61 { 30 { keyset, meta, ... } }`. Our earlier
        // encoder emitted the fields directly under `61`, which parsed its own
        // output but rejected every real blob. Accept the wrapped form, which
        // is what all observed protections use, and keep accepting the bare
        // form so hand-built or differently tagged protections still read.
        let content = children(outer.value)?;
        let fields = match content.as_slice() {
            [only] if only.tag == 0x30 => children(only.value)?,
            _ => content,
        };
        let keyset = fields
            .first()
            .filter(|field| field.tag == 0x30)
            .ok_or_else(|| Error::Message("PCS protection has no keyset".into()))?;

        let mut meta = None;
        let mut signature_data = None;
        let mut hmac = None;
        let mut truncated_key_id = None;
        let mut signature = None;
        let mut attributes = None;
        let mut trailing = Vec::new();

        for field in &fields[1..] {
            match field.tag {
                0xa0 if meta.is_none() => meta = Some(parse_explicit_octets(field.value)?),
                0xa1 if signature_data.is_none() => {
                    signature_data = Some(parse_signature_data(field.value)?)
                }
                0x04 if hmac.is_none() => hmac = Some(field.value.to_vec()),
                0xa2 if truncated_key_id.is_none() => {
                    truncated_key_id = Some(parse_explicit_octets(field.value)?)
                }
                0xa3 if signature.is_none() => signature = Some(parse_signature(field.value)?),
                0xa4 if attributes.is_none() => attributes = Some(parse_attributes(field.value)?),
                _ => trailing.push(field.raw.to_vec()),
            }
        }

        Ok(Self {
            keyset: parse_outer_keyset(keyset.value)?,
            meta: meta.ok_or_else(|| Error::Message("PCS protection has no meta".into()))?,
            signature_data,
            hmac: hmac.ok_or_else(|| Error::Message("PCS protection has no HMAC".into()))?,
            truncated_key_id: truncated_key_id
                .ok_or_else(|| Error::Message("PCS protection has no key id".into()))?,
            signature,
            attributes,
            trailing,
        })
    }

    pub fn signer(&self) -> Option<PublicKey> {
        self.signature
            .as_ref()
            .and_then(|signature| public_from_key_id(&signature.keyid).ok())
    }

    pub fn public_x(&self) -> Result<&[u8]> {
        self.keyset
            .keys
            .first()
            .map(|key| key.decryption_key.key.as_slice())
            .ok_or_else(|| Error::Message("PCS protection has no keys".into()))
    }

    /// Open the protection with one of `keys` and return its working keys.
    ///
    /// `custom_signing` is accepted for parity with the macOS client; signature
    /// verification is skipped because this client never trusts a key it did
    /// not just unwrap.
    pub fn decode(&self, keys: &[SecretKey], _custom_signing: bool) -> Result<Decoded> {
        let (secret, entry) = keys
            .iter()
            .find_map(|key| {
                let public = key.public_key().to_encoded_point(true);
                let x = &public.as_bytes()[1..];
                self.keyset
                    .keys
                    .iter()
                    .find(|entry| entry.decryption_key.key.as_slice() == x)
                    .map(|entry| (key, entry))
            })
            .ok_or_else(|| Error::Message("no PCS key matches this protection".into()))?;

        let master = PcsKey::unwrap(secret, &entry.wrapped)?;
        let readonly = entry.flags.unwrap_or(0) & 1 != 0;
        let version = self.signature_data.as_ref().map_or(1, |data| data.version);
        let master = if version != 5 && !readonly {
            master.share_variant()
        } else {
            master
        };

        let expected = master.key_id();
        if self.truncated_key_id.len() > expected.len()
            || expected[..self.truncated_key_id.len()] != self.truncated_key_id[..]
        {
            return Err(Error::Message("PCS key id does not match".into()));
        }

        let mut hmac_input = self.keyset.encode();
        hmac_input.extend_from_slice(&self.meta);
        if let Some(data) = &self.signature_data {
            hmac_input.extend_from_slice(&data.signature);
        }
        if master.hmac(&hmac_input) != self.hmac {
            return Err(Error::Message("PCS HMAC check failed".into()));
        }

        let plain_identities = master.decrypt(&self.meta, &[])?;
        if std::env::var_os("APW_DEBUG").is_some() {
            eprintln!(
                "pcs: meta {} -> {} bytes",
                self.meta.len(),
                plain_identities.len()
            );
        }
        let identities = parse_identities(&plain_identities)?;
        if std::env::var_os("APW_DEBUG").is_some() {
            eprintln!(
                "pcs: identities symm {:?} entries {:?}",
                identities.symm_keys.as_ref().map(Vec::len),
                identities.identities.as_ref().map(Vec::len)
            );
            for entry in identities.identities.iter().flatten() {
                eprintln!("pcs: identity keyset {} bytes", entry.keyset.len());
            }
        }
        let (mut keys, private) = identity_keys(&identities)?;
        let mut all = vec![master];
        all.append(&mut keys);
        Ok(Decoded {
            keys: all,
            identities: private,
        })
    }

    /// Encode the protection as canonical DER.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut parts = vec![self.keyset.encode()];
        parts.push(der_context(0, &der_octets(&self.meta)));
        if let Some(signature_data) = &self.signature_data {
            parts.push(signature_data.encode());
        }
        parts.push(der_octets(&self.hmac));
        parts.push(der_context(2, &der_octets(&self.truncated_key_id)));
        if let Some(signature) = &self.signature {
            parts.push(signature.encode());
        }
        if let Some(attributes) = &self.attributes {
            parts.push(der_context(4, &encode_attributes(attributes)));
        }
        parts.extend(self.trailing.iter().cloned());
        // Real protections carry the explicit inner SEQUENCE; re-emit it so the
        // encoding matches Apple byte for byte.
        Ok(der_application(1, &der_sequence(parts)))
    }

    /// The bytes the object signature covers.
    fn digest(&self) -> Result<Vec<u8>> {
        let signature = self.object_signature()?;
        let mut data = self.keyset.encode();
        data.extend_from_slice(&self.meta);
        data.extend_from_slice(&(signature.outer_sign_key_type as u32).to_be_bytes());
        data.extend_from_slice(&(signature.roll_count as u32).to_be_bytes());
        data.extend_from_slice(&(signature.symm_key_count.unwrap_or(0) as u32).to_be_bytes());
        data.extend_from_slice(&(signature.public.keytype as u32).to_be_bytes());
        data.extend_from_slice(&signature.public.key);
        if let Some(attributes) = &signature.attributes {
            data.extend_from_slice(attributes);
        }
        if let Some(list) = &signature.ec_key_list {
            data.extend_from_slice(list);
        }
        Ok(data)
    }

    /// Verify the self-signature over the digest and recompute the HMAC.
    ///
    /// The signature checked is the object signature carried inside
    /// `signature_data`, which the master EC key signs over the keyset, meta,
    /// and object signature fields. This is deliberately separate from
    /// `decode`: decoding never trusts a key it did not unwrap, while this
    /// checks that an encoded protection still carries the bytes Apple signed.
    pub fn verify(&self, signer: &PublicKey, master: &PcsKey) -> Result<()> {
        let digest = self.digest()?;
        let object = self.object_signature()?;
        let signature = EcdsaSignature::from_der(&object.signature.signature)
            .map_err(|_| Error::Message("PCS signature is not a DER ECDSA signature".into()))?;
        let point = signer.to_encoded_point(false);
        let verifying = VerifyingKey::from_sec1_bytes(point.as_bytes())
            .map_err(|_| Error::Message("invalid PCS signature key".into()))?;
        let hash = Sha256::digest(&digest);
        verifying
            .verify_prehash(hash.as_slice(), &signature)
            .map_err(|_| Error::Message("PCS signature check failed".into()))?;

        let mut hmac_input = self.keyset.encode();
        hmac_input.extend_from_slice(&self.meta);
        if let Some(data) = &self.signature_data {
            hmac_input.extend_from_slice(&data.signature);
        }
        if master.hmac(&hmac_input) != self.hmac {
            return Err(Error::Message("PCS HMAC check failed".into()));
        }
        Ok(())
    }

    fn object_signature(&self) -> Result<ObjectSignature> {
        let data = self
            .signature_data
            .as_ref()
            .map(|data| data.signature.as_slice())
            .filter(|data| !data.is_empty())
            .ok_or_else(|| Error::Message("PCS protection has no signature data".into()))?;
        parse_object_signature(data)
    }
}

/// Structural parse of a protection, with no service key involved.
///
/// This is the parse-only entry point used by the fixture round-trip tests.
/// It decodes every outer element and the object signature inside
/// `signature_data`, but cannot touch the identity keyset: `meta` is a v3 PCS
/// ciphertext and only [`Protection::decode`] can open it with a service key.
pub type ParsedProtection = Protection;

/// Parse a protection without unwrapping or decrypting anything.
pub fn parse_structure(der: &[u8]) -> Result<ParsedProtection> {
    Protection::parse(der)
}

/// The `PCSObjectSignature` inside `signature_data`, as far as the digest needs.
struct ObjectSignature {
    roll_count: u64,
    outer_sign_key_type: u64,
    public: PcsKeyRef,
    signature: PcsSignature,
    symm_key_count: Option<u64>,
    ec_key_list: Option<Vec<u8>>,
    attributes: Option<Vec<u8>>,
}

/// The decrypted identity bundle stored in a protection's meta field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsIdentities {
    /// Contents of the optional `[0]` SET OF OCTET STRING.
    pub symm_keys: Option<Vec<Vec<u8>>>,
    /// The required `[1]` integer/octets pair.
    pub tag1: Option<PcsIdentitiesTag1>,
    /// The optional `[2]` SET OF identity entries.
    pub identities: Option<Vec<PcsIdentityData>>,
    pub trailing: Vec<Vec<u8>>,
}

impl PcsIdentities {
    /// Parse a decrypted identity bundle. This is only reachable after
    /// [`Protection::decode`] has GCM-decrypted `meta` with the service key.
    pub fn parse(der: &[u8]) -> Result<Self> {
        parse_identities(der)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut parts = Vec::new();
        if let Some(keys) = &self.symm_keys {
            let set = der_set(keys.iter().map(|key| der_octets(key)).collect());
            parts.push(der_context(0, &set));
        }
        if let Some(tag1) = &self.tag1 {
            let mut inner = vec![der_integer(tag1.unknown1), der_octets(&tag1.unknown2)];
            inner.extend(tag1.trailing.iter().cloned());
            parts.push(der_context(1, &der_sequence(inner)));
        }
        if let Some(identities) = &self.identities {
            let set = der_set(identities.iter().map(PcsIdentityData::encode).collect());
            parts.push(der_context(2, &set));
        }
        parts.extend(self.trailing.iter().cloned());
        der_sequence(parts)
    }
}

/// The `[1]` identity pair: an unknown integer and an octet body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsIdentitiesTag1 {
    pub unknown1: u64,
    pub unknown2: Vec<u8>,
    pub trailing: Vec<Vec<u8>>,
}

/// One identity: an unknown integer and an encoded inner keyset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcsIdentityData {
    pub unknown1: u64,
    pub keyset: Vec<u8>,
    pub trailing: Vec<Vec<u8>>,
}

impl PcsIdentityData {
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = vec![der_integer(self.unknown1), der_octets(&self.keyset)];
        parts.extend(self.trailing.iter().cloned());
        der_sequence(parts)
    }
}

/// The `[APPLICATION 2]` keyset of private identity keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsPrivateKeySet {
    /// Tag of the leading unknown value, stored verbatim.
    ///
    /// The earlier lane assumed UTF8String (`0x0c`). No fixture exposes the
    /// inner keyset in plaintext (`meta` is a v3 PCS ciphertext), so this is
    /// not verified against real bytes; re-encoding preserves whichever tag a
    /// decrypted bundle actually carries.
    pub unknown1_tag: u8,
    pub unknown1: Vec<u8>,
    /// SET items kept verbatim so unknown key forms survive.
    pub keys: Vec<Vec<u8>>,
    /// The second SET, normally empty; `None` means it was absent.
    pub unknown2: Option<Vec<Vec<u8>>>,
    pub hash: Option<Vec<u8>>,
    pub trailing: Vec<Vec<u8>>,
    /// Apple wraps the inner keyset in an explicit SEQUENCE inside
    /// `[APPLICATION 2]`; re-emit that wrapper when it was present.
    pub nested: bool,
}

impl Default for PcsPrivateKeySet {
    fn default() -> Self {
        Self {
            unknown1_tag: 0x0c,
            unknown1: Vec::new(),
            keys: Vec::new(),
            unknown2: None,
            hash: None,
            trailing: Vec::new(),
            nested: false,
        }
    }
}

impl PcsPrivateKeySet {
    /// Parse an inner identity keyset. Like [`PcsIdentities::parse`], this sees
    /// plaintext only after the surrounding `meta` has been decrypted.
    pub fn parse(der: &[u8]) -> Result<Self> {
        parse_inner_keyset(der)
    }

    /// Encode the keyset, recomputing the hash when the field is present.
    pub fn encode(&self) -> Vec<u8> {
        let hash = self.hash.as_ref().map(|_| self.compute_hash());
        self.encode_with(hash.as_deref())
    }

    /// Encode the keyset with the hash field omitted.
    pub fn encode_without_hash(&self) -> Vec<u8> {
        self.encode_with(None)
    }

    /// SHA-256 of the keyset DER with the hash field omitted.
    pub fn compute_hash(&self) -> Vec<u8> {
        Sha256::digest(self.encode_without_hash()).to_vec()
    }

    fn encode_with(&self, hash: Option<&[u8]>) -> Vec<u8> {
        let mut parts = vec![
            der_tlv(self.unknown1_tag, &self.unknown1),
            der_set(self.keys.clone()),
        ];
        if let Some(items) = &self.unknown2 {
            parts.push(der_set(items.clone()));
        }
        if let Some(hash) = hash {
            parts.push(der_octets(hash));
        }
        parts.extend(self.trailing.iter().cloned());
        let body = if self.nested {
            der_sequence(parts)
        } else {
            parts.concat()
        };
        der_application(2, &body)
    }
}

fn parse_explicit_octets(data: &[u8]) -> Result<Vec<u8>> {
    let fields = children(data)?;
    if fields.len() != 1 || fields[0].tag != 0x04 {
        return Err(Error::Message("PCS value is not an octet string".into()));
    }
    Ok(fields[0].value.to_vec())
}

/// Unwrap an explicit tag whose value is a single SET OF.
fn parse_explicit_set<'a>(data: &'a [u8], what: &str) -> Result<Tlv<'a>> {
    let mut fields = children(data)?;
    if fields.len() != 1 || fields[0].tag != 0x31 {
        return Err(Error::Message(format!("bad {what}")));
    }
    Ok(fields.remove(0))
}

fn parse_signature_data(data: &[u8]) -> Result<PcsSignatureData> {
    let fields = children(data)?;
    let sequence = fields
        .first()
        .filter(|field| field.tag == 0x30)
        .ok_or_else(|| Error::Message("bad PCS signature data".into()))?;
    let parts = children(sequence.value)?;
    let version = match parts.first().filter(|part| part.tag == 0x02) {
        Some(part) => integer(part.value)?,
        None => 1,
    };
    let signature = parts
        .get(1)
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .unwrap_or_default();
    let trailing = parts.iter().skip(2).map(|part| part.raw.to_vec()).collect();
    Ok(PcsSignatureData {
        version,
        signature,
        trailing,
    })
}

fn parse_signature(data: &[u8]) -> Result<PcsSignature> {
    let fields = children(data)?;
    let sequence = fields
        .first()
        .filter(|field| field.tag == 0x30)
        .ok_or_else(|| Error::Message("bad PCS signature".into()))?;
    parse_signature_value(sequence.value)
}

fn parse_signature_value(data: &[u8]) -> Result<PcsSignature> {
    let parts = children(data)?;
    let keyid = parts
        .first()
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .unwrap_or_default();
    let digest = match parts.get(1).filter(|part| part.tag == 0x02) {
        Some(part) => integer(part.value)?,
        None => 1,
    };
    let signature = parts
        .get(2)
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .unwrap_or_default();
    let trailing = parts.iter().skip(3).map(|part| part.raw.to_vec()).collect();
    Ok(PcsSignature {
        keyid,
        digest,
        signature,
        trailing,
    })
}

fn parse_attributes(data: &[u8]) -> Result<Vec<PcsAttribute>> {
    let (sequence, rest) = read_tlv(data)?;
    if !rest.is_empty() || sequence.tag != 0x30 {
        return Err(Error::Message("bad PCS attributes".into()));
    }
    children(sequence.value)?
        .iter()
        .map(|item| {
            if item.tag != 0x30 {
                return Err(Error::Message("bad PCS attribute".into()));
            }
            parse_attribute(item.value)
        })
        .collect()
}

fn parse_attribute(data: &[u8]) -> Result<PcsAttribute> {
    let parts = children(data)?;
    let key = match parts.first().filter(|part| part.tag == 0x02) {
        Some(part) => integer(part.value)?,
        None => 0,
    };
    let value = parts
        .get(1)
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .unwrap_or_default();
    let trailing = parts.iter().skip(2).map(|part| part.raw.to_vec()).collect();
    Ok(PcsAttribute {
        key,
        value,
        trailing,
    })
}

fn parse_outer_keyset(data: &[u8]) -> Result<PcsKeySet> {
    let mut unknown1 = 0;
    let mut saw_integer = false;
    let mut set = None;
    let mut attributes = None;
    let mut trailing = Vec::new();

    for field in children(data)? {
        match field.tag {
            0x02 if !saw_integer => {
                unknown1 = integer(field.value)?;
                saw_integer = true;
            }
            0x31 if set.is_none() => set = Some(field.value),
            0xa0 if attributes.is_none() => attributes = Some(parse_attributes(field.value)?),
            _ => trailing.push(field.raw.to_vec()),
        }
    }

    let mut keys = Vec::new();
    let mut unparsed = Vec::new();
    for item in children(set.unwrap_or_default())? {
        if item.tag == 0x30 {
            keys.push(parse_share_key(item.value)?);
        } else {
            unparsed.push(item.raw.to_vec());
        }
    }

    Ok(PcsKeySet {
        unknown1,
        keys,
        unparsed,
        attributes,
        trailing,
    })
}

fn parse_share_key(data: &[u8]) -> Result<PcsShareKey> {
    let parts = children(data)?;
    let reference = parts
        .first()
        .filter(|part| part.tag == 0x30)
        .ok_or_else(|| Error::Message("PCS key has no reference".into()))?;
    let decryption_key = parse_key_ref(reference.value)?;
    let wrapped = parts
        .get(1)
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .ok_or_else(|| Error::Message("PCS key has no wrapped body".into()))?;
    let flags = match parts.get(2).filter(|part| part.tag == 0x02) {
        Some(part) => Some(integer(part.value)?),
        None => None,
    };
    let skip = if flags.is_some() { 3 } else { 2 };
    let trailing = parts
        .iter()
        .skip(skip)
        .map(|part| part.raw.to_vec())
        .collect();
    Ok(PcsShareKey {
        decryption_key,
        wrapped,
        flags,
        trailing,
    })
}

fn parse_key_ref(data: &[u8]) -> Result<PcsKeyRef> {
    let parts = children(data)?;
    let keytype = match parts.first().filter(|part| part.tag == 0x02) {
        Some(part) => integer(part.value)?,
        None => 0,
    };
    let key = parts
        .get(1)
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .unwrap_or_default();
    let trailing = parts.iter().skip(2).map(|part| part.raw.to_vec()).collect();
    Ok(PcsKeyRef {
        keytype,
        key,
        trailing,
    })
}

fn parse_identities(data: &[u8]) -> Result<PcsIdentities> {
    let (outer, rest) = read_tlv(data)?;
    if !rest.is_empty() || outer.tag != 0x30 {
        return Err(Error::Message("bad PCS identities".into()));
    }

    let mut symm_keys = None;
    let mut tag1 = None;
    let mut identities = None;
    let mut trailing = Vec::new();

    for field in children(outer.value)? {
        match field.tag {
            0xa0 if symm_keys.is_none() => {
                let set = parse_explicit_set(field.value, "PCS symmetric keys")?;
                let mut keys = Vec::new();
                for item in children(set.value)? {
                    if item.tag == 0x04 {
                        keys.push(item.value.to_vec());
                    } else {
                        trailing.push(item.raw.to_vec());
                    }
                }
                symm_keys = Some(keys);
            }
            0xa1 if tag1.is_none() => tag1 = Some(parse_identities_tag1(field.value)?),
            0xa2 if identities.is_none() => {
                let set = parse_explicit_set(field.value, "PCS identities")?;
                let mut entries = Vec::new();
                for item in children(set.value)? {
                    if item.tag == 0x30 {
                        entries.push(parse_identity_data(item.value)?);
                    } else {
                        trailing.push(item.raw.to_vec());
                    }
                }
                identities = Some(entries);
            }
            _ => trailing.push(field.raw.to_vec()),
        }
    }

    Ok(PcsIdentities {
        symm_keys,
        tag1,
        identities,
        trailing,
    })
}

fn parse_identities_tag1(data: &[u8]) -> Result<PcsIdentitiesTag1> {
    let fields = children(data)?;
    let sequence = fields
        .first()
        .filter(|field| field.tag == 0x30)
        .ok_or_else(|| Error::Message("bad PCS identities tag 1".into()))?;
    let parts = children(sequence.value)?;
    let unknown1 = match parts.first().filter(|part| part.tag == 0x02) {
        Some(part) => integer(part.value)?,
        None => 0,
    };
    let unknown2 = parts
        .get(1)
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .unwrap_or_default();
    let trailing = parts.iter().skip(2).map(|part| part.raw.to_vec()).collect();
    Ok(PcsIdentitiesTag1 {
        unknown1,
        unknown2,
        trailing,
    })
}

fn parse_identity_data(data: &[u8]) -> Result<PcsIdentityData> {
    let parts = children(data)?;
    let unknown1 = match parts.first().filter(|part| part.tag == 0x02) {
        Some(part) => integer(part.value)?,
        None => 0,
    };
    let keyset = parts
        .get(1)
        .filter(|part| part.tag == 0x04)
        .map(|part| part.value.to_vec())
        .unwrap_or_default();
    let trailing = parts.iter().skip(2).map(|part| part.raw.to_vec()).collect();
    Ok(PcsIdentityData {
        unknown1,
        keyset,
        trailing,
    })
}

fn parse_inner_keyset(data: &[u8]) -> Result<PcsPrivateKeySet> {
    let (outer, rest) = read_tlv(data)?;
    if !rest.is_empty() || outer.tag != 0x62 {
        return Err(Error::Message("bad PCS identity keyset".into()));
    }

    let mut keyset = PcsPrivateKeySet::default();
    let top = children(outer.value)?;
    let fields = if top.len() == 1 && top[0].tag == 0x30 {
        keyset.nested = true;
        children(top[0].value)?
    } else {
        top
    };
    for (index, field) in fields.into_iter().enumerate() {
        match index {
            0 => {
                keyset.unknown1_tag = field.tag;
                keyset.unknown1 = field.value.to_vec();
            }
            1 => {
                if field.tag != 0x31 {
                    return Err(Error::Message("bad PCS identity key set".into()));
                }
                keyset.keys = children(field.value)?
                    .into_iter()
                    .map(|item| item.raw.to_vec())
                    .collect();
            }
            _ => match field.tag {
                0x31 if keyset.unknown2.is_none() => {
                    keyset.unknown2 = Some(
                        children(field.value)?
                            .into_iter()
                            .map(|item| item.raw.to_vec())
                            .collect(),
                    );
                }
                0x04 if keyset.hash.is_none() => keyset.hash = Some(field.value.to_vec()),
                _ => keyset.trailing.push(field.raw.to_vec()),
            },
        }
    }
    Ok(keyset)
}

fn identity_keys(identities: &PcsIdentities) -> Result<(Vec<PcsKey>, Vec<SecretKey>)> {
    let symmetric = identities
        .symm_keys
        .iter()
        .flatten()
        .map(|key| PcsKey(key.clone()))
        .collect();
    let mut private = Vec::new();
    for identity in identities.identities.iter().flatten() {
        if identity.keyset.is_empty() {
            continue;
        }
        let keyset = parse_inner_keyset(&identity.keyset)?;
        if std::env::var_os("APW_DEBUG").is_some() {
            let tags: Vec<u8> = keyset.keys.iter().map(|item| item[0]).collect();
            eprintln!(
                "pcs: inner keys {:?} tags {tags:02x?} hash {:?}",
                keyset.keys.len(),
                keyset.hash.as_ref().map(Vec::len)
            );
        }
        for item in &keyset.keys {
            match parse_private_key(item) {
                Ok(key) => private.push(key),
                Err(error) => {
                    if std::env::var_os("APW_DEBUG").is_some() {
                        eprintln!("pcs: private key parse failed: {error}");
                    }
                }
            }
        }
    }
    Ok((symmetric, private))
}

fn parse_object_signature(data: &[u8]) -> Result<ObjectSignature> {
    let (outer, rest) = read_tlv(data)?;
    if !rest.is_empty() || outer.tag != 0x30 {
        return Err(Error::Message("bad PCS object signature".into()));
    }
    let parts = children(outer.value)?;
    if parts.len() < 4 {
        return Err(Error::Message("PCS object signature is truncated".into()));
    }

    let roll_count = integer_field(&parts[0], "roll count")?;
    let outer_sign_key_type = integer_field(&parts[1], "sign key type")?;
    let public = parse_key_ref_field(&parts[2])?;
    let signature = parse_signature_field(&parts[3])?;

    let mut symm_key_count = None;
    let mut ec_key_list = None;
    let mut attributes = None;
    for part in &parts[4..] {
        match part.tag {
            0xa0 if symm_key_count.is_none() => {
                let inner = children(part.value)?;
                let value = inner
                    .first()
                    .filter(|item| item.tag == 0x02)
                    .ok_or_else(|| Error::Message("bad PCS signature key count".into()))?;
                symm_key_count = Some(integer(value.value)?);
            }
            0xa2 if ec_key_list.is_none() => ec_key_list = Some(part.value.to_vec()),
            0xa3 if attributes.is_none() => attributes = Some(part.value.to_vec()),
            _ => {}
        }
    }

    Ok(ObjectSignature {
        roll_count,
        outer_sign_key_type,
        public,
        signature,
        symm_key_count,
        ec_key_list,
        attributes,
    })
}

fn integer_field(part: &Tlv<'_>, what: &str) -> Result<u64> {
    if part.tag != 0x02 {
        return Err(Error::Message(format!("PCS {what} is not an integer")));
    }
    integer(part.value)
}

fn parse_key_ref_field(part: &Tlv<'_>) -> Result<PcsKeyRef> {
    if part.tag != 0x30 {
        return Err(Error::Message("PCS key reference is not a sequence".into()));
    }
    parse_key_ref(part.value)
}

fn parse_signature_field(part: &Tlv<'_>) -> Result<PcsSignature> {
    if part.tag != 0x30 {
        return Err(Error::Message("PCS signature is not a sequence".into()));
    }
    parse_signature_value(part.value)
}

fn encode_attributes(attributes: &[PcsAttribute]) -> Vec<u8> {
    der_sequence(attributes.iter().map(PcsAttribute::encode).collect())
}

fn parse_private_key(data: &[u8]) -> Result<SecretKey> {
    let (outer, _) = read_tlv(data)?;
    match outer.tag {
        0x30 => {
            let fields = children(outer.value)?;
            let body = fields
                .first()
                .filter(|field| field.tag == 0x04)
                .map(|field| field.value)
                .ok_or_else(|| Error::Message("PCS identity key has no body".into()))?;
            Ok(ServiceKey::from_compact(body)?.secret)
        }
        0x65 => {
            let fields = children(outer.value)?;
            let body = fields
                .first()
                .filter(|field| field.tag == 0x04)
                .map(|field| field.value)
                .ok_or_else(|| Error::Message("PCS identity key has no body".into()))?;
            Ok(ServiceKey::parse_proto(body)?.secret)
        }
        tag => Err(Error::Message(format!(
            "unexpected PCS identity key tag {tag:#x}"
        ))),
    }
}

impl PcsKeyRef {
    fn encode(&self) -> Vec<u8> {
        let mut parts = vec![der_integer(self.keytype), der_octets(&self.key)];
        parts.extend(self.trailing.iter().cloned());
        der_sequence(parts)
    }
}

impl PcsShareKey {
    fn encode(&self) -> Vec<u8> {
        let mut parts = vec![self.decryption_key.encode(), der_octets(&self.wrapped)];
        if let Some(flags) = self.flags {
            parts.push(der_integer(flags));
        }
        parts.extend(self.trailing.iter().cloned());
        der_sequence(parts)
    }
}

impl PcsAttribute {
    fn encode(&self) -> Vec<u8> {
        let mut parts = vec![der_integer(self.key), der_octets(&self.value)];
        parts.extend(self.trailing.iter().cloned());
        der_sequence(parts)
    }
}

/// Build the CloudKit protection-info blob: field 1 is the DER, field 2 is the
/// uppercase hex SHA-1 tag CloudKit uses to identify it.
pub fn protection_info(der: &[u8]) -> Vec<u8> {
    let tag = uppercase_hex(&Sha1::digest(der));
    let mut writer = Writer::new();
    writer.bytes(1, der).string(2, &tag);
    writer.finish()
}

fn uppercase_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let count = bytes.len() - first;
    let mut out = Vec::with_capacity(1 + count);
    out.push(0x80 | count as u8);
    out.extend_from_slice(&bytes[first..]);
    out
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    out.extend_from_slice(&der_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// A canonical DER INTEGER. Zero is `02 01 00`.
fn der_integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_octets(value: &[u8]) -> Vec<u8> {
    der_tlv(0x04, value)
}

fn der_sequence(parts: Vec<Vec<u8>>) -> Vec<u8> {
    der_tlv(0x30, &parts.concat())
}

/// A SET OF whose elements are sorted by their full encoded bytes.
fn der_set(mut parts: Vec<Vec<u8>>) -> Vec<u8> {
    parts.sort();
    der_tlv(0x31, &parts.concat())
}

fn der_context(number: u8, inner: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 + number, inner)
}

fn der_application(number: u8, inner: &[u8]) -> Vec<u8> {
    der_tlv(0x60 + number, inner)
}

fn public_from_key_id(key: &[u8]) -> Result<PublicKey> {
    match key.len() {
        33 | 65 => PublicKey::from_sec1_bytes(key)
            .map_err(|_| Error::Message("invalid PCS public key".into())),
        32 => public_from_x(key),
        other => Err(Error::Message(format!("PCS public key has {other} bytes"))),
    }
}

/// A PCS master key. Working keys are derived from its raw bytes.
#[derive(Clone)]
pub struct PcsKey(Vec<u8>);

impl PcsKey {
    fn unwrap(secret: &SecretKey, wrapped: &[u8]) -> Result<Self> {
        if wrapped.len() < 3 {
            return Err(Error::Message("PCS wrapped key is truncated".into()));
        }
        let bits = u16::from_be_bytes([wrapped[0], wrapped[1]]) as usize;
        let ephemeral_len = bits / 8;
        if ephemeral_len == 0 || wrapped.len() < 2 + ephemeral_len + 1 {
            return Err(Error::Message(
                "PCS wrapped key has no ephemeral key".into(),
            ));
        }
        let ephemeral = &wrapped[2..2 + ephemeral_len];
        let wrapped_len = wrapped[2 + ephemeral_len] as usize;
        let blob = &wrapped[3 + ephemeral_len..];
        if blob.len() < wrapped_len {
            return Err(Error::Message("PCS wrapped key is truncated".into()));
        }

        let public = public_from_x(ephemeral)?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        let kek = rfc6637_kdf(shared.raw_secret_bytes().as_slice());
        let plain = aes_key_unwrap(&kek, &blob[..wrapped_len])?;

        if plain.len() < 3 || plain[0] != 1 {
            return Err(Error::Message("PCS key unwrap returned a bad body".into()));
        }
        let pad = plain[plain.len() - 1] as usize;
        if pad == 0 || pad > plain.len() - 3 {
            return Err(Error::Message("PCS key unwrap has bad padding".into()));
        }
        let body = &plain[1..plain.len() - pad - 2];
        let checksum = plain[1 + body.len()..3 + body.len()]
            .try_into()
            .map_err(|_| Error::Message("PCS key unwrap has no checksum".into()))?;
        let sum = body
            .iter()
            .fold(0u16, |acc, byte| acc.wrapping_add(*byte as u16));
        if sum != u16::from_be_bytes(checksum) {
            return Err(Error::Message("PCS key unwrap checksum failed".into()));
        }
        Ok(Self(body.to_vec()))
    }

    fn derive(&self, label: &[u8]) -> Vec<u8> {
        kdf_ctr_hmac(&self.0, label, &[], self.0.len())
    }

    pub fn key_id(&self) -> Vec<u8> {
        let key = self.derive(b"master key id labell");
        hmac_sha256(&key, b"M key input data 2 u")
    }

    fn share_variant(&self) -> Self {
        Self(self.derive(b"MsaeEooevaX fooo 012"))
    }

    fn hmac(&self, data: &[u8]) -> Vec<u8> {
        let key = self.derive(b"hmackey-of-masterkey");
        hmac_sha256(&key, data)
    }

    /// Decrypt a v3 PCS ciphertext. The header is authenticated with `aad`.
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 4 + 12 + 12 || ciphertext[0] != 3 {
            return Err(Error::Message("unsupported PCS ciphertext".into()));
        }
        let tail = ciphertext[3] as usize;
        let header_len = 4 + tail;
        if ciphertext.len() < header_len + 24 {
            return Err(Error::Message("PCS ciphertext is truncated".into()));
        }

        let mut key_id = Vec::with_capacity(2 + tail);
        key_id.extend_from_slice(&ciphertext[1..3]);
        key_id.extend_from_slice(&ciphertext[4..header_len]);
        let expected = self.key_id();
        if key_id.len() > expected.len() || expected[..key_id.len()] != key_id {
            return Err(Error::Message(
                "PCS ciphertext key id does not match".into(),
            ));
        }

        let encryption_key = self.derive(b"encryption key key m");
        // Apple's v3 field ciphertext uses a 12-byte GCM tag, not the
        // 16-byte default.
        let cipher = AesGcm::<Aes128, U12, U12>::new_from_slice(&encryption_key[..16])
            .map_err(|_| Error::Message("invalid PCS encryption key".into()))?;
        let iv = &ciphertext[header_len..header_len + 12];
        let tag = &ciphertext[header_len + 12..header_len + 24];
        let body = &ciphertext[header_len + 24..];

        let mut authenticated = ciphertext[..header_len].to_vec();
        authenticated.extend_from_slice(aad);
        let mut message = body.to_vec();
        message.extend_from_slice(tag);
        cipher
            .decrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: &message,
                    aad: &authenticated,
                },
            )
            .map_err(|_| Error::Message("PCS field decryption failed".into()))
    }
}

fn rfc6637_kdf(secret: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(1u32.to_be_bytes());
    hasher.update(secret);
    hasher.update(P256_KDF_PREFIX);
    hasher.update(ANONYMOUS_SENDER);
    hasher.update(b"fingerprint");
    hasher.update([0u8; 9]);
    let digest = hasher.finalize();
    digest[..16].try_into().expect("fixed length")
}

fn public_from_x(x: &[u8]) -> Result<PublicKey> {
    if x.len() != 32 {
        return Err(Error::Message(format!(
            "PCS public key has {} bytes",
            x.len()
        )));
    }
    let mut encoded = [0u8; 33];
    encoded[0] = 0x03;
    encoded[1..].copy_from_slice(x);
    PublicKey::from_sec1_bytes(&encoded)
        .map_err(|_| Error::Message("invalid PCS P-256 point".into()))
}

fn kdf_ctr_hmac(key: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(label.len() + 1 + context.len() + 4);
    suffix.extend_from_slice(label);
    suffix.push(0);
    suffix.extend_from_slice(context);
    suffix.extend_from_slice(&((length as u32) * 8).to_be_bytes());

    let mut out = Vec::with_capacity(length);
    let mut counter = 1u32;
    while out.len() < length {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
        mac.update(&counter.to_be_bytes());
        mac.update(&suffix);
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(length);
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 3394 AES key unwrap with a 128-bit KEK.
fn aes_key_unwrap(kek: &[u8; 16], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 || !blob.len().is_multiple_of(8) {
        return Err(Error::Message("bad AES key wrap length".into()));
    }
    let cipher = Aes128::new_from_slice(kek).map_err(|_| Error::Message("bad KEK".into()))?;
    let n = blob.len() / 8 - 1;
    let mut a: [u8; 8] = blob[..8].try_into().expect("checked length");
    let mut blocks: Vec<[u8; 8]> = blob[8..].as_chunks::<8>().0.to_vec();

    for round in (0..6u64).rev() {
        for index in (0..n).rev() {
            let counter = (n as u64) * round + index as u64 + 1;
            let mut block = [0u8; 16];
            let counter = counter.to_be_bytes();
            for (index, byte) in block[..8].iter_mut().enumerate() {
                *byte = a[index] ^ counter[index];
            }
            block[8..].copy_from_slice(&blocks[index]);
            let mut buffer = aes::Block::clone_from_slice(&block);
            cipher.decrypt_block(&mut buffer);
            a.copy_from_slice(&buffer[..8]);
            blocks[index].copy_from_slice(&buffer[8..]);
        }
    }

    if a != [0xa6; 8] {
        return Err(Error::Message(
            "AES key unwrap integrity check failed".into(),
        ));
    }
    Ok(blocks.concat())
}

fn integer(data: &[u8]) -> Result<u64> {
    if data.len() > 8 {
        return Err(Error::Message("PCS integer is too large".into()));
    }
    Ok(data
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | *byte as u64))
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

fn read_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if data.len() < 2 {
        return Err(Error::Message("truncated DER".into()));
    }
    let tag = data[0];
    let (length, header) = if data[1] < 0x80 {
        (data[1] as usize, 2)
    } else {
        let count = (data[1] & 0x7f) as usize;
        if count == 0 || count > 4 || data.len() < 2 + count {
            return Err(Error::Message("bad DER length".into()));
        }
        let mut length = 0usize;
        for byte in &data[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    let end = header
        .checked_add(length)
        .ok_or_else(|| Error::Message("bad DER length".into()))?;
    if data.len() < end {
        return Err(Error::Message("truncated DER value".into()));
    }
    Ok((
        Tlv {
            tag,
            value: &data[header..end],
            raw: &data[..end],
        },
        &data[end..],
    ))
}

fn children(data: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (item, tail) = read_tlv(rest)?;
        out.push(item);
        rest = tail;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwraps_rfc3394_vector() {
        let kek: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let wrapped = [
            0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a,
            0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
        ];
        let key = aes_key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(
            key,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }

    #[test]
    fn kdf_length_is_exact() {
        let out = kdf_ctr_hmac(b"key", b"label", b"context", 32);
        assert_eq!(out.len(), 32);
        assert_ne!(out, kdf_ctr_hmac(b"key", b"label", b"context", 16));
    }

    #[test]
    fn rejects_bad_der() {
        assert!(read_tlv(&[0x30]).is_err());
        assert!(read_tlv(&[0x30, 0x82, 0x01]).is_err());
        assert!(Protection::parse(&[0x30, 0x00]).is_err());
    }

    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;

    fn share_key(x: u8, flags: Option<u64>) -> PcsShareKey {
        PcsShareKey {
            decryption_key: PcsKeyRef {
                keytype: 3,
                key: vec![x; 33],
                trailing: Vec::new(),
            },
            wrapped: vec![0x10, 0x20, x],
            flags,
            trailing: Vec::new(),
        }
    }

    fn attribute(key: u64, value: &[u8]) -> PcsAttribute {
        PcsAttribute {
            key,
            value: value.to_vec(),
            trailing: Vec::new(),
        }
    }

    fn object_signature(public: &[u8], signature: &[u8]) -> Vec<u8> {
        let key_ref = PcsKeyRef {
            keytype: 1,
            key: public.to_vec(),
            trailing: Vec::new(),
        };
        der_sequence(vec![
            der_integer(1),
            der_integer(0),
            key_ref.encode(),
            der_sequence(vec![der_octets(&[]), der_integer(1), der_octets(signature)]),
        ])
    }

    fn hmac_for(protection: &Protection, master: &PcsKey) -> Vec<u8> {
        let mut input = protection.keyset.encode();
        input.extend_from_slice(&protection.meta);
        if let Some(data) = &protection.signature_data {
            input.extend_from_slice(&data.signature);
        }
        master.hmac(&input)
    }

    fn sample_protection() -> Protection {
        Protection {
            keyset: PcsKeySet {
                unknown1: 0,
                keys: vec![share_key(0x11, None), share_key(0x22, Some(1))],
                unparsed: Vec::new(),
                attributes: Some(vec![attribute(3, &[0x30, 0x00])]),
                trailing: vec![der_context(5, &der_integer(7))],
            },
            meta: vec![0xaa, 0xbb, 0xcc],
            signature_data: Some(PcsSignatureData {
                version: 5,
                signature: object_signature(&[0x09; 65], &[0x30, 0x00]),
                trailing: Vec::new(),
            }),
            hmac: vec![0x44; 32],
            truncated_key_id: vec![0x55; 4],
            signature: Some(PcsSignature {
                keyid: vec![0x02; 33],
                digest: 1,
                signature: vec![0x30, 0x00],
                trailing: Vec::new(),
            }),
            attributes: Some(vec![attribute(7, &[0x30, 0x00])]),
            trailing: vec![der_context(9, &der_octets(b"extra"))],
        }
    }

    #[test]
    fn protection_encode_decode_round_trip() {
        let protection = sample_protection();
        let first = protection.encode().unwrap();
        let parsed = Protection::parse(&first).unwrap();
        assert_eq!(parsed, protection);
        assert_eq!(parsed.encode().unwrap(), first);
    }

    /// A DER fixture written out by hand, independent of the encoder.
    ///
    /// The `61 { 30 { ... } }` shape is the one real Apple protections use:
    /// `[APPLICATION 1]` wraps an explicit SEQUENCE, whose first element is the
    /// keyset SEQUENCE. The earlier hand-written fixture omitted that middle
    /// SEQUENCE.
    #[test]
    fn re_encodes_a_hand_written_der() {
        let der: &[u8] = &[
            0x61, 0x23, // [APPLICATION 1] wrapper
            0x30, 0x21, // explicit inner SEQUENCE
            0x30, 0x05, 0x02, 0x01, 0x00, 0x31, 0x00, //
            0xa0, 0x03, 0x04, 0x01, 0xaa, //
            0xa1, 0x0b, 0x30, 0x09, 0x02, 0x01, 0x05, 0x04, 0x04, 0x30, 0x02, 0x05, 0x00, //
            0x04, 0x01, 0xbb, //
            0xa2, 0x03, 0x04, 0x01, 0xcc, //
        ];
        let protection = Protection::parse(der).unwrap();
        assert_eq!(protection.meta, [0xaa]);
        assert_eq!(protection.hmac, [0xbb]);
        assert_eq!(protection.truncated_key_id, [0xcc]);
        assert_eq!(protection.signature_data.as_ref().unwrap().version, 5);
        assert_eq!(protection.encode().unwrap(), der);
    }

    #[test]
    fn empty_sets_and_absent_optionals_round_trip() {
        let protection = Protection {
            keyset: PcsKeySet::default(),
            meta: Vec::new(),
            signature_data: Some(PcsSignatureData::default()),
            hmac: Vec::new(),
            truncated_key_id: Vec::new(),
            signature: None,
            attributes: None,
            trailing: Vec::new(),
        };
        let encoded = protection.encode().unwrap();
        let parsed = Protection::parse(&encoded).unwrap();
        assert_eq!(parsed, protection);
        assert_eq!(parsed.encode().unwrap(), encoded);

        // The keyset always carries the INTEGER 0 and an empty SET OF keys,
        // even when there are no keys.
        assert!(encoded
            .windows(5)
            .any(|window| window == [0x02u8, 0x01, 0x00, 0x31, 0x00].as_slice()));
    }

    #[test]
    fn optional_flags_are_omitted_only_when_absent() {
        let encoded = share_key(0x11, None).encode();
        let (outer, _) = read_tlv(&encoded).unwrap();
        assert_eq!(children(outer.value).unwrap().len(), 2);

        let encoded = share_key(0x11, Some(0)).encode();
        let (outer, _) = read_tlv(&encoded).unwrap();
        let parts = children(outer.value).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].tag, 0x02);
        assert_eq!(parts[2].value, [0x00]);
        assert_eq!(parts[2].raw, [0x02, 0x01, 0x00]);
    }

    #[test]
    fn set_of_keys_is_sorted_by_encoded_bytes() {
        let first = PcsKeySet {
            keys: vec![share_key(0x11, None), share_key(0x22, None)],
            ..PcsKeySet::default()
        }
        .encode();
        let second = PcsKeySet {
            keys: vec![share_key(0x22, None), share_key(0x11, None)],
            ..PcsKeySet::default()
        }
        .encode();
        assert_eq!(first, second);

        let (outer, _) = read_tlv(&first).unwrap();
        let set = children(outer.value)
            .unwrap()
            .into_iter()
            .find(|field| field.tag == 0x31)
            .unwrap();
        let items = children(set.value).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].raw < items[1].raw);
        assert_eq!(items[0].raw, share_key(0x11, None).encode().as_slice());
    }

    #[test]
    fn inner_keyset_hash_covers_every_byte_and_excludes_itself() {
        let mut keyset = PcsPrivateKeySet {
            keys: vec![der_octets(&[0x11; 64])],
            unknown2: Some(Vec::new()),
            hash: Some(vec![0x00; 32]),
            ..PcsPrivateKeySet::default()
        };
        let without_hash = keyset.encode_without_hash();
        let hash = keyset.compute_hash();
        assert_eq!(hash, Sha256::digest(&without_hash).to_vec());

        let encoded = keyset.encode();
        let (outer, rest) = read_tlv(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(outer.tag, 0x62);
        let stored = children(outer.value)
            .unwrap()
            .into_iter()
            .last()
            .filter(|field| field.tag == 0x04)
            .unwrap();
        assert_eq!(stored.value, hash.as_slice());
        assert!(!without_hash
            .windows(hash.len())
            .any(|window| window == hash.as_slice()));

        let before = keyset.compute_hash();
        keyset.keys[0] = der_octets(&[0x12; 64]);
        assert_ne!(keyset.compute_hash(), before);

        let absent = PcsPrivateKeySet {
            keys: vec![der_octets(&[0x11; 64])],
            ..PcsPrivateKeySet::default()
        };
        let encoded = absent.encode();
        assert_eq!(encoded, absent.encode_without_hash());
        let (outer, _) = read_tlv(&encoded).unwrap();
        assert_eq!(children(outer.value).unwrap().len(), 2);
    }

    /// The inner keyset's leading value is stored and re-emitted with whatever
    /// tag it arrived with. The fixtures cannot answer whether Apple uses
    /// UTF8String (`0x0c`) or OCTET STRING (`0x04`) because `meta` is always
    /// encrypted; this keeps both forms byte-exact instead of guessing.
    #[test]
    fn inner_keyset_preserves_the_unknown1_tag() {
        for tag in [0x0c, 0x04] {
            let keyset = PcsPrivateKeySet {
                unknown1_tag: tag,
                unknown1: b"identity".to_vec(),
                keys: vec![der_octets(&[0x11; 64])],
                unknown2: Some(Vec::new()),
                hash: Some(vec![0x00; 32]),
                trailing: Vec::new(),
                nested: false,
            };
            let encoded = keyset.encode();
            let parsed = PcsPrivateKeySet::parse(&encoded).unwrap();
            assert_eq!(parsed.unknown1_tag, tag);
            assert_eq!(parsed.unknown1, keyset.unknown1);
            assert_eq!(parsed.keys, keyset.keys);
            assert_eq!(parsed.unknown2, Some(Vec::new()));
            assert_eq!(
                parsed.hash.as_deref(),
                Some(keyset.compute_hash().as_slice())
            );
            assert_eq!(parsed.encode(), encoded);
        }
    }

    #[test]
    fn identities_encode_decode_round_trip() {
        let inner = PcsPrivateKeySet {
            keys: vec![der_octets(&[0x11; 64]), der_octets(&[0x22; 64])],
            unknown2: Some(Vec::new()),
            hash: Some(vec![0x00; 32]),
            ..PcsPrivateKeySet::default()
        };
        let identities = PcsIdentities {
            symm_keys: Some(vec![vec![0x01; 16], vec![0x02; 16]]),
            tag1: Some(PcsIdentitiesTag1 {
                unknown1: 0,
                unknown2: vec![0x03; 4],
                trailing: Vec::new(),
            }),
            identities: Some(vec![PcsIdentityData {
                unknown1: 0,
                keyset: inner.encode(),
                trailing: Vec::new(),
            }]),
            trailing: Vec::new(),
        };
        let encoded = identities.encode();
        let parsed = parse_identities(&encoded).unwrap();
        assert_eq!(parsed, identities);
        assert_eq!(parsed.encode(), encoded);

        // No identities at all.
        let bare = PcsIdentities::default();
        let encoded = bare.encode();
        assert_eq!(encoded, [0x30, 0x00]);
        assert_eq!(parse_identities(&encoded).unwrap(), bare);

        // Empty SETs are present, not dropped.
        let empty = PcsIdentities {
            symm_keys: Some(Vec::new()),
            tag1: None,
            identities: Some(Vec::new()),
            trailing: Vec::new(),
        };
        let encoded = empty.encode();
        let parsed = parse_identities(&encoded).unwrap();
        assert_eq!(parsed, empty);
        assert_eq!(parsed.encode(), encoded);
    }

    #[test]
    fn verifies_a_signed_digest_and_rejects_a_change() {
        let signing = SigningKey::random(&mut rand::thread_rng());
        let secret = SecretKey::from_slice(&signing.to_bytes()).unwrap();
        let public = secret.public_key();
        let public_bytes = public.to_encoded_point(false).as_bytes().to_vec();

        let master = PcsKey(vec![0x5a; 16]);
        let mut protection = Protection {
            keyset: PcsKeySet {
                keys: vec![share_key(0x11, None)],
                ..PcsKeySet::default()
            },
            meta: vec![0xde, 0xad, 0xbe, 0xef],
            signature_data: Some(PcsSignatureData {
                version: 5,
                signature: object_signature(&public_bytes, &[]),
                trailing: Vec::new(),
            }),
            hmac: Vec::new(),
            truncated_key_id: vec![0x01, 0x02, 0x03, 0x04],
            signature: Some(PcsSignature {
                keyid: Vec::new(),
                digest: 1,
                signature: Vec::new(),
                trailing: Vec::new(),
            }),
            attributes: None,
            trailing: Vec::new(),
        };

        let digest = protection.digest().unwrap();
        let hash = Sha256::digest(&digest);
        let signature: p256::ecdsa::Signature = signing.sign_prehash(hash.as_slice()).unwrap();
        let der = signature.to_der().as_bytes().to_vec();
        protection.signature_data.as_mut().unwrap().signature =
            object_signature(&public_bytes, &der);
        protection.hmac = hmac_for(&protection, &master);

        let encoded = protection.encode().unwrap();
        let parsed = Protection::parse(&encoded).unwrap();
        assert_eq!(parsed, protection);
        parsed.verify(&public, &master).unwrap();

        let mut tampered = parsed.clone();
        tampered.meta[0] ^= 0xff;
        tampered.hmac = hmac_for(&tampered, &master);
        assert!(tampered.verify(&public, &master).is_err());
    }

    /// Real Apple protections, gated on `APW_PCS_FIXTURES`.
    ///
    /// All four blobs from the P1 probe (`group-510F…` and `group-671C…`,
    /// `-zone.bin` and `-record.bin`) share this shape, which differs from
    /// what the first pass of this codec assumed:
    ///
    /// * `61 82 …` `[APPLICATION 1]` wraps one explicit `30` SEQUENCE, and
    ///   *that* SEQUENCE holds the keyset, meta, and signatures. The earlier
    ///   encoder put the fields directly under `61`, so it re-read its own
    ///   output but rejected real bytes.
    /// * The keyset is `SEQUENCE { INTEGER 0, SET OF PCSShareKey }`. No keyset
    ///   `[0]` attributes are present in any of the four.
    /// * The two zone keysets carry two share keys (`flags` INTEGER 16 and 8 in
    ///   510F, one key with `flags` 8 in 671C); both records carry one key with
    ///   no `flags`. The SET OF is sorted by encoded bytes, matching `der_set`.
    /// * Outer elements present, in order: keyset, `[0]` meta (explicit OCTET
    ///   STRING), `[1]` signature data (explicit `SEQUENCE { INTEGER version,
    ///   OCTET signature }`), bare OCTET STRING hmac (32 bytes), `[2]`
    ///   truncated key id (explicit 4-byte OCTET STRING), `[3]` signature
    ///   (explicit `SEQUENCE { OCTET key id, INTEGER digest, OCTET signature }`).
    ///   **No outer `[4]` attributes element exists in any fixture**, so
    ///   `attributes` stays `None`; the `[4]` wrapper in the encoder is only
    ///   used when a protection actually carries attributes.
    /// * Signature data versions are 4 (both zones) and 5 (both records). The
    ///   enclosed object signature has `roll_count` 3/4/1/1, sign key type 3,
    ///   an uncompressed (65-byte) public key, and a `[2]` EC key list shaped
    ///   `[2] { SEQUENCE { SEQUENCE { INTEGER 3, OCTET 32 } } }`. It is kept
    ///   as raw bytes inside the signature OCTET STRING, so re-encoding is
    ///   exact.
    /// * `meta` is a v3 PCS ciphertext (`03 …`, 165 bytes in zones and 41 in
    ///   records), not a plaintext identity bundle. The inner
    ///   `PCSPrivateKeySet` therefore cannot be inspected from these fixtures:
    ///   the `unknown1` tag (UTF8String `0c` vs OCTET STRING `04`), whether
    ///   `unknown2` is present/empty, and whether the stored hash equals
    ///   `sha256(encode_without_hash)` remain unverified against real bytes.
    ///   The parser stores `unknown1_tag` verbatim and the synthetic test below
    ///   locks in the hash rule for when a decrypted bundle is available.
    ///
    /// On mismatch the first differing offset and surrounding hex are printed.
    #[test]
    fn real_protection_fixtures_round_trip_byte_identically() {
        use std::fmt::Write as _;

        let dir = match std::env::var_os("APW_PCS_FIXTURES") {
            Some(dir) => dir,
            None => return,
        };
        let dir = std::path::PathBuf::from(dir);
        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .expect("APW_PCS_FIXTURES is not a readable directory")
            .map(|entry| entry.expect("fixture directory entry").path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name.ends_with("-zone.bin") || name.ends_with("-record.bin")
            })
            .collect();
        paths.sort();
        assert!(
            !paths.is_empty(),
            "APW_PCS_FIXTURES has no *-zone.bin or *-record.bin files"
        );

        for path in paths {
            let der = std::fs::read(&path).expect("read fixture");
            let parsed = parse_structure(&der).unwrap_or_else(|error| {
                panic!("{}: structural parse failed: {error}", path.display())
            });
            let encoded = parsed
                .encode()
                .unwrap_or_else(|error| panic!("{}: encode failed: {error}", path.display()));

            // The observed fixture facts the encoder depends on.
            assert_eq!(parsed.keyset.unknown1, 0, "{}", path.display());
            assert!(!parsed.keyset.keys.is_empty(), "{}", path.display());
            assert!(parsed.keyset.attributes.is_none(), "{}", path.display());
            assert!(parsed.signature_data.is_some(), "{}", path.display());
            assert_eq!(parsed.hmac.len(), 32, "{}", path.display());
            assert_eq!(parsed.truncated_key_id.len(), 4, "{}", path.display());
            assert!(parsed.attributes.is_none(), "{}", path.display());

            if encoded != der {
                let offset = der
                    .iter()
                    .zip(&encoded)
                    .position(|(expected, actual)| expected != actual)
                    .unwrap_or_else(|| der.len().min(encoded.len()));
                let start = offset.saturating_sub(8);
                let end = (offset + 8).min(der.len().max(encoded.len()));
                let mut input = String::new();
                for byte in &der[start..end.min(der.len())] {
                    let _ = write!(input, "{byte:02x} ");
                }
                let mut output = String::new();
                for byte in &encoded[start..end.min(encoded.len())] {
                    let _ = write!(output, "{byte:02x} ");
                }
                panic!(
                    "{}: re-encode differs at offset {offset} (input {} bytes, output {} bytes)\n  input  [{start:#06x}..]: {input}\n  output [{start:#06x}..]: {output}",
                    path.display(),
                    der.len(),
                    encoded.len(),
                );
            }
        }
    }

    #[test]
    fn protection_info_has_der_and_uppercase_sha1() {
        let der = [0x61u8, 0x03, 0x30, 0x01, 0x00];
        let blob = protection_info(&der);
        assert_eq!(blob[0], 0x0a);
        assert_eq!(blob[1] as usize, der.len());
        assert_eq!(&blob[2..2 + der.len()], &der);

        let tag = &blob[2 + der.len()..];
        assert_eq!(tag[0], 0x12);
        assert_eq!(tag[1], 40);
        let hex = std::str::from_utf8(&tag[2..]).unwrap();
        assert_eq!(hex, uppercase_hex(&Sha1::digest(der)));
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
    }
}
