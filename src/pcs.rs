//! PCS (Protected Cloud Storage) share protection.
//!
//! Shared-keychain zones are encrypted with a PCS keyset. The service private
//! key is a normal synced keychain item, so this module only needs the item
//! body plus the zone metadata CloudKit returns. Everything here is read-only:
//! keys are unwrapped and used to decrypt, never created or saved.

use aes::cipher::{BlockDecrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::wire::Reader;

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

/// One wrapped key in a protection keyset.
struct KeyEntry<'a> {
    public_x: &'a [u8],
    wrapped: &'a [u8],
    flags: u32,
}

/// A parsed `PCSShareProtection`.
pub struct Protection<'a> {
    keyset_raw: &'a [u8],
    entries: Vec<KeyEntry<'a>>,
    meta: &'a [u8],
    signature_version: u64,
    signature_data: &'a [u8],
    hmac: &'a [u8],
    truncated_key_id: &'a [u8],
    signer: Option<&'a [u8]>,
}

/// The result of opening a protection: working keys and the identity keys.
pub struct Decoded {
    pub keys: Vec<PcsKey>,
    pub identities: Vec<SecretKey>,
}

impl<'a> Protection<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Self> {
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

        let fields = children(outer.value)?;
        let keyset = fields
            .first()
            .filter(|field| field.tag == 0x30)
            .ok_or_else(|| Error::Message("PCS protection has no keyset".into()))?;

        let mut meta = None;
        let mut signature_version = 1;
        let mut signature_data: &[u8] = &[];
        let mut hmac = None;
        let mut truncated_key_id = None;
        let mut signer = None;

        for field in &fields[1..] {
            match field.tag {
                0xa0 => meta = Some(field.value),
                0xa1 => {
                    let parts = children(field.value)?;
                    let seq = parts
                        .first()
                        .filter(|part| part.tag == 0x30)
                        .ok_or_else(|| Error::Message("bad PCS signature data".into()))?;
                    let parts = children(seq.value)?;
                    if let Some(version) = parts.first().filter(|part| part.tag == 0x02) {
                        signature_version = integer(version.value)?;
                    }
                    if let Some(data) = parts.get(1).filter(|part| part.tag == 0x04) {
                        signature_data = data.value;
                    }
                }
                0x04 => hmac = Some(field.value),
                0xa2 => truncated_key_id = Some(field.value),
                0xa3 => {
                    // PCSSignature { keyid, digest, signature }
                    let parts = children(field.value)?;
                    if let Some(seq) = parts.first().filter(|part| part.tag == 0x30) {
                        let parts = children(seq.value)?;
                        if let Some(keyid) = parts.first().filter(|part| part.tag == 0x04) {
                            signer = Some(keyid.value);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            keyset_raw: keyset.raw,
            entries: parse_entries(keyset.value)?,
            meta: meta.ok_or_else(|| Error::Message("PCS protection has no meta".into()))?,
            signature_version,
            signature_data,
            hmac: hmac.ok_or_else(|| Error::Message("PCS protection has no HMAC".into()))?,
            truncated_key_id: truncated_key_id
                .ok_or_else(|| Error::Message("PCS protection has no key id".into()))?,
            signer,
        })
    }

    pub fn signer(&self) -> Option<PublicKey> {
        self.signer.and_then(|key| public_from_x(key).ok())
    }

    pub fn public_x(&self) -> Result<&[u8]> {
        self.entries
            .first()
            .map(|entry| entry.public_x)
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
                self.entries
                    .iter()
                    .find(|entry| entry.public_x == x)
                    .map(|entry| (key, entry))
            })
            .ok_or_else(|| Error::Message("no PCS key matches this protection".into()))?;

        let master = PcsKey::unwrap(secret, entry.wrapped)?;
        let readonly = entry.flags & 1 != 0;
        let master = if self.signature_version != 5 && !readonly {
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

        let mut hmac_input =
            Vec::with_capacity(self.keyset_raw.len() + self.meta.len() + self.signature_data.len());
        hmac_input.extend_from_slice(self.keyset_raw);
        hmac_input.extend_from_slice(self.meta);
        hmac_input.extend_from_slice(self.signature_data);
        if master.hmac(&hmac_input) != self.hmac {
            return Err(Error::Message("PCS HMAC check failed".into()));
        }

        let identities = master.decrypt(self.meta, &[])?;
        let (mut keys, private) = parse_identities(&identities)?;
        let mut all = vec![master];
        all.append(&mut keys);
        Ok(Decoded {
            keys: all,
            identities: private,
        })
    }
}

fn parse_entries(data: &[u8]) -> Result<Vec<KeyEntry<'_>>> {
    let fields = children(data)?;
    let set = fields
        .iter()
        .find(|field| field.tag == 0x31)
        .ok_or_else(|| Error::Message("PCS keyset has no keys".into()))?;

    let mut entries = Vec::new();
    for item in children(set.value)? {
        if item.tag != 0x30 {
            continue;
        }
        let parts = children(item.value)?;
        let reference = parts
            .first()
            .filter(|part| part.tag == 0x30)
            .ok_or_else(|| Error::Message("PCS key has no reference".into()))?;
        let reference = children(reference.value)?;
        let public_x = reference
            .get(1)
            .filter(|part| part.tag == 0x04)
            .map(|part| part.value)
            .ok_or_else(|| Error::Message("PCS key has no public key".into()))?;
        let wrapped = parts
            .get(1)
            .filter(|part| part.tag == 0x04)
            .map(|part| part.value)
            .ok_or_else(|| Error::Message("PCS key has no wrapped body".into()))?;
        let flags = match parts.get(2) {
            Some(part) if part.tag == 0x02 => integer(part.value)? as u32,
            _ => 0,
        };
        entries.push(KeyEntry {
            public_x,
            wrapped,
            flags,
        });
    }
    Ok(entries)
}

fn parse_identities(data: &[u8]) -> Result<(Vec<PcsKey>, Vec<SecretKey>)> {
    let (outer, rest) = read_tlv(data)?;
    if !rest.is_empty() || outer.tag != 0x30 {
        return Err(Error::Message("bad PCS identities".into()));
    }

    let mut symmetric = Vec::new();
    let mut private = Vec::new();
    for field in children(outer.value)? {
        match field.tag {
            0xa0 => {
                for item in children(field.value)? {
                    if item.tag == 0x04 {
                        symmetric.push(PcsKey(item.value.to_vec()));
                    }
                }
            }
            0xa2 => {
                for item in children(field.value)? {
                    if item.tag != 0x30 {
                        continue;
                    }
                    let parts = children(item.value)?;
                    let Some(keyset) = parts.get(1).filter(|part| part.tag == 0x04) else {
                        continue;
                    };
                    private.extend(parse_key_set(keyset.value)?);
                }
            }
            _ => {}
        }
    }
    Ok((symmetric, private))
}

fn parse_key_set(data: &[u8]) -> Result<Vec<SecretKey>> {
    let (outer, rest) = read_tlv(data)?;
    if !rest.is_empty() || outer.tag != 0x62 {
        return Err(Error::Message("bad PCS identity keyset".into()));
    }
    let mut keys = Vec::new();
    for field in children(outer.value)? {
        if field.tag != 0x31 {
            continue;
        }
        for item in children(field.value)? {
            if let Ok(key) = parse_private_key(item.raw) {
                keys.push(key);
            }
        }
    }
    Ok(keys)
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
        let cipher = Aes128Gcm::new_from_slice(&encryption_key[..16])
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
}
