//! Octagon peer keys.
//!
//! Apple stores public keys as DER SPKI and private keys as X9.63
//! `04 || X || Y || d`. Signatures are ECDSA P-384 over a domain prefix and the
//! message; the peer ID hashes the signed data and the signature.

use base64::Engine;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::EncodePublicKey;
use p384::SecretKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub const PEER_PERMANENT_INFO: &str = "TPPB.PeerPermanentInfo";
pub const PEER_STABLE_INFO: &str = "TPPB.PeerStableInfo";
pub const PEER_DYNAMIC_INFO: &str = "TPPB.PeerDynamicInfo";
pub const VOUCHER: &str = "TPPB.Voucher";

#[derive(Clone)]
pub struct PeerKeys {
    pub signing: SecretKey,
    pub encryption: SecretKey,
}

impl PeerKeys {
    pub fn generate() -> Self {
        Self {
            signing: SecretKey::random(&mut OsRng),
            encryption: SecretKey::random(&mut OsRng),
        }
    }

    pub fn from_x963(signing: &[u8], encryption: &[u8]) -> Result<Self> {
        Ok(Self {
            signing: load_private(signing)?,
            encryption: load_private(encryption)?,
        })
    }

    pub fn signing_x963(&self) -> Vec<u8> {
        encode_private(&self.signing)
    }

    pub fn encryption_x963(&self) -> Vec<u8> {
        encode_private(&self.encryption)
    }

    pub fn signing_spki(&self) -> Result<Vec<u8>> {
        encode_public(&self.signing)
    }

    pub fn encryption_spki(&self) -> Result<Vec<u8>> {
        encode_public(&self.encryption)
    }

    pub fn sign(&self, domain: &str, data: &[u8]) -> Result<Vec<u8>> {
        sign(&self.signing, domain, data)
    }
}

pub fn sign(key: &SecretKey, domain: &str, data: &[u8]) -> Result<Vec<u8>> {
    let signing = SigningKey::from(key.clone());
    let mut message = Vec::with_capacity(domain.len() + data.len());
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(data);
    let signature: Signature = signing.sign(&message);
    Ok(signature.to_der().as_bytes().to_vec())
}

pub fn verify(public: &SecretKey, domain: &str, data: &[u8], signature: &[u8]) -> Result<()> {
    let verifying = VerifyingKey::from(public.public_key());
    let signature = Signature::from_der(signature)
        .map_err(|error| Error::Message(format!("invalid P-384 signature: {error}")))?;
    let mut message = Vec::with_capacity(domain.len() + data.len());
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(data);
    verifying
        .verify(&message, &signature)
        .map_err(|error| Error::Message(format!("P-384 signature does not verify: {error}")))
}

pub fn peer_id(data: &[u8], signature: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(signature);
    let digest = hasher.finalize();
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn encode_public(key: &SecretKey) -> Result<Vec<u8>> {
    key.public_key()
        .to_public_key_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|error| Error::Message(format!("cannot encode P-384 public key: {error}")))
}

fn encode_private(key: &SecretKey) -> Vec<u8> {
    let point = key.public_key().to_encoded_point(false);
    let mut out = Vec::with_capacity(145);
    out.push(0x04);
    out.extend_from_slice(point.x().expect("uncompressed point has x"));
    out.extend_from_slice(point.y().expect("uncompressed point has y"));
    out.extend_from_slice(&key.to_bytes());
    out
}

fn load_private(data: &[u8]) -> Result<SecretKey> {
    if data.len() != 145 || data[0] != 0x04 {
        return Err(Error::Message(
            "peer private key is not X9.63 encoded".into(),
        ));
    }
    SecretKey::from_slice(&data[97..145])
        .map_err(|error| Error::Message(format!("invalid P-384 private key: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x963_round_trip() {
        let keys = PeerKeys::generate();
        let signing = keys.signing_x963();
        let encryption = keys.encryption_x963();
        assert_eq!(signing.len(), 145);
        assert_eq!(encryption.len(), 145);

        let loaded = PeerKeys::from_x963(&signing, &encryption).unwrap();
        assert_eq!(loaded.signing_x963(), signing);
        assert_eq!(loaded.encryption_x963(), encryption);
    }

    #[test]
    fn signature_verifies() {
        let keys = PeerKeys::generate();
        let data = b"permanent info";
        let signature = keys.sign(PEER_PERMANENT_INFO, data).unwrap();
        verify(&keys.signing, PEER_PERMANENT_INFO, data, &signature).unwrap();
        assert!(verify(&keys.signing, PEER_STABLE_INFO, data, &signature).is_err());
    }

    #[test]
    fn peer_id_is_prefixed_base64() {
        let keys = PeerKeys::generate();
        let data = b"permanent info";
        let signature = keys.sign(PEER_PERMANENT_INFO, data).unwrap();
        let id = peer_id(data, &signature);
        assert!(id.starts_with("SHA256:"));
        assert_eq!(id.len(), 7 + 44);
    }

    #[test]
    fn spki_is_der() {
        let keys = PeerKeys::generate();
        let spki = keys.signing_spki().unwrap();
        assert_eq!(spki[0], 0x30);
    }
}
