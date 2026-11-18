use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::model::Vault;

pub mod key;

const MAGIC: &[u8; 8] = b"APWSNAP\x00";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;

pub fn seal(vault: &Vault, key: &[u8; 32]) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(vault)?;
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(MAGIC.len() + 1);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| Error::Aead)?;

    let mut out = header;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(bytes: &[u8], key: &[u8; 32]) -> Result<Vault> {
    let header_len = MAGIC.len() + 1;
    if bytes.len() < header_len + NONCE_LEN {
        return Err(Error::Message("snapshot is truncated".into()));
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(Error::Message("snapshot has an unknown format".into()));
    }
    let version = bytes[MAGIC.len()];
    if version != VERSION {
        return Err(Error::Message(format!(
            "snapshot version {version} is not supported"
        )));
    }

    let header = &bytes[..header_len];
    let nonce = &bytes[header_len..header_len + NONCE_LEN];
    let ciphertext = &bytes[header_len + NONCE_LEN..];

    let cipher = Aes256Gcm::new(key.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| Error::Aead)?;

    Ok(serde_json::from_slice(&plaintext)?)
}
