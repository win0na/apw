use base64::Engine;
use rand::RngCore;

use crate::config::{Config, Paths};
use crate::error::{Error, Result};

const SERVICE: &str = "apw";
const ACCOUNT: &str = "snapshot-key";
const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    SecretService,
    Passphrase,
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::SecretService => f.write_str("secret-service"),
            KeySource::Passphrase => f.write_str("passphrase"),
        }
    }
}

pub struct SnapshotKey {
    pub key: [u8; KEY_LEN],
    pub source: KeySource,
}

pub fn load_or_create(config: &mut Config, paths: &Paths) -> Result<SnapshotKey> {
    if let Some(passphrase) = std::env::var("APW_PASSPHRASE")
        .ok()
        .filter(|v| !v.is_empty())
    {
        return derive_from_passphrase(config, paths, &passphrase);
    }

    #[cfg(feature = "keyring")]
    if let Some(key) = secret_service_key()? {
        return Ok(SnapshotKey {
            key,
            source: KeySource::SecretService,
        });
    }

    let passphrase = read_passphrase()?;
    derive_from_passphrase(config, paths, &passphrase)
}

#[cfg(feature = "keyring")]
fn secret_service_key() -> Result<Option<[u8; KEY_LEN]>> {
    let entry = match keyring::Entry::new(SERVICE, ACCOUNT) {
        Ok(entry) => entry,
        Err(_) => return Ok(None),
    };

    match entry.get_password() {
        Ok(encoded) => {
            let key = decode_key(&encoded)?;
            Ok(Some(key))
        }
        Err(keyring::Error::NoEntry) => {
            let key = random_key();
            entry
                .set_password(&base64::engine::general_purpose::STANDARD.encode(key))
                .map_err(Error::from)?;
            Ok(Some(key))
        }
        Err(_) => Ok(None),
    }
}

fn read_passphrase() -> Result<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(Error::Message(
            "no Secret Service key and no terminal for a passphrase; set APW_PASSPHRASE".into(),
        ));
    }
    rpassword::prompt_password("apw passphrase: ")
        .map_err(|error| Error::Message(format!("cannot read passphrase: {error}")))
}

fn derive_from_passphrase(
    config: &mut Config,
    paths: &Paths,
    passphrase: &str,
) -> Result<SnapshotKey> {
    let salt = match &config.kdf_salt {
        Some(encoded) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| Error::Message("config kdf_salt is not valid base64".into()))?,
        None => {
            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            config.kdf_salt = Some(base64::engine::general_purpose::STANDARD.encode(salt));
            config.save(paths)?;
            salt.to_vec()
        }
    };

    let mut key = [0u8; KEY_LEN];
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|error| Error::Message(format!("invalid Argon2 parameters: {error}")))?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|error| Error::Message(format!("cannot derive the snapshot key: {error}")))?;

    Ok(SnapshotKey {
        key,
        source: KeySource::Passphrase,
    })
}

fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn decode_key(encoded: &str) -> Result<[u8; KEY_LEN]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| Error::Message("Secret Service holds an invalid snapshot key".into()))?;
    bytes
        .try_into()
        .map_err(|_| Error::Message("Secret Service holds a key of the wrong length".into()))
}
