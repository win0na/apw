use base64::Engine;
use rand::RngCore;

use crate::config::{Config, Paths};
use crate::error::{Error, Result};

#[cfg(feature = "keyring")]
const SERVICE: &str = "apw";
#[cfg(feature = "keyring")]
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

/// Resolve the key of an existing snapshot. This never creates a key: a
/// missing Secret Service entry must not mint a new key behind an old
/// snapshot.
pub fn load(config: &mut Config, paths: &Paths) -> Result<SnapshotKey> {
    if let Some(passphrase) = env_passphrase() {
        return derive_from_passphrase(config, paths, &passphrase, false);
    }

    #[cfg(feature = "keyring")]
    if let Some(key) = existing_secret_service_key() {
        return Ok(SnapshotKey {
            key,
            source: KeySource::SecretService,
        });
    }

    let passphrase = read_passphrase()?;
    derive_from_passphrase(config, paths, &passphrase, false)
}

/// Derive a key for reading an existing snapshot. A missing KDF salt is an
/// error: minting one here would derive a key that cannot open the snapshot and
/// would overwrite the salt the writer used.
pub fn derive_for_load(
    config: &mut Config,
    paths: &Paths,
    passphrase: &str,
) -> Result<SnapshotKey> {
    derive_from_passphrase(config, paths, passphrase, false)
}

/// Create the key for a first write. Only this path may store a new Secret
/// Service entry or prompt for a new passphrase.
pub fn create(config: &mut Config, paths: &Paths) -> Result<SnapshotKey> {
    if let Some(passphrase) = env_passphrase() {
        return derive_from_passphrase(config, paths, &passphrase, true);
    }

    #[cfg(feature = "keyring")]
    if let Some(key) = create_secret_service_key() {
        return Ok(SnapshotKey {
            key,
            source: KeySource::SecretService,
        });
    }

    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(Error::Message(
            "Secret Service is unavailable and stdin is not a terminal; set APW_PASSPHRASE".into(),
        ));
    }

    let passphrase = rpassword::prompt_password("New apw passphrase: ")
        .map_err(|error| Error::Message(format!("cannot read passphrase: {error}")))?;
    let confirm = rpassword::prompt_password("Confirm the apw passphrase: ")
        .map_err(|error| Error::Message(format!("cannot read passphrase: {error}")))?;
    if passphrase.is_empty() {
        return Err(Error::Invalid("the passphrase is empty".into()));
    }
    if passphrase != confirm {
        return Err(Error::Invalid("the passphrases do not match".into()));
    }
    std::env::set_var("APW_PASSPHRASE", &passphrase);
    derive_from_passphrase(config, paths, &passphrase, true)
}

fn env_passphrase() -> Option<String> {
    std::env::var("APW_PASSPHRASE")
        .ok()
        .filter(|value| !value.is_empty())
}

/// Read the existing Secret Service key. A missing entry or an unavailable
/// backend both fall through to the passphrase.
#[cfg(feature = "keyring")]
fn existing_secret_service_key() -> Option<[u8; KEY_LEN]> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).ok()?;
    let encoded = entry.get_password().ok()?;
    decode_key(&encoded).ok()
}

/// Cache a passphrase-derived key in Secret Service. A readable entry is left
/// alone: it may belong to a snapshot in another data directory, and replacing
/// it would orphan that snapshot.
#[cfg(feature = "keyring")]
pub fn remember(key: &[u8; KEY_LEN]) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    if entry
        .get_password()
        .ok()
        .and_then(|encoded| decode_key(&encoded).ok())
        .is_some()
    {
        return Ok(());
    }
    entry.set_password(&base64::engine::general_purpose::STANDARD.encode(key))?;
    Ok(())
}

/// Resolve the Secret Service key for a first write. An existing readable entry
/// is reused and never overwritten: it may belong to a snapshot in another data
/// directory, and replacing it would orphan that snapshot.
#[cfg(feature = "keyring")]
fn create_secret_service_key() -> Option<[u8; KEY_LEN]> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).ok()?;
    match entry.get_password() {
        Ok(encoded) => decode_key(&encoded).ok(),
        Err(keyring::Error::NoEntry) => {
            let key = random_key();
            entry
                .set_password(&base64::engine::general_purpose::STANDARD.encode(key))
                .ok()?;
            Some(key)
        }
        Err(_) => None,
    }
}

fn read_passphrase() -> Result<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(Error::Message(
            "no snapshot key; set APW_PASSPHRASE or unlock Secret Service".into(),
        ));
    }
    rpassword::prompt_password("apw passphrase: ")
        .map_err(|error| Error::Message(format!("cannot read passphrase: {error}")))
}

fn derive_from_passphrase(
    config: &mut Config,
    paths: &Paths,
    passphrase: &str,
    create_salt: bool,
) -> Result<SnapshotKey> {
    let salt = match &config.kdf_salt {
        Some(encoded) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| Error::Message("config kdf_salt is not valid base64".into()))?,
        None if !create_salt => {
            return Err(Error::Message(
                "config has no kdf_salt; cannot derive the passphrase key".into(),
            ));
        }
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

#[cfg(feature = "keyring")]
fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

#[cfg(feature = "keyring")]
fn decode_key(encoded: &str) -> Result<[u8; KEY_LEN]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| Error::Message("Secret Service holds an invalid snapshot key".into()))?;
    bytes
        .try_into()
        .map_err(|_| Error::Message("Secret Service holds a key of the wrong length".into()))
}

#[cfg(test)]
mod tests {
    use super::{derive_from_passphrase, KeySource, KEY_LEN};
    use crate::config::{Config, Paths};

    fn test_paths(dir: &std::path::Path) -> Paths {
        Paths {
            config_dir: dir.join("config"),
            config_file: dir.join("config").join("config.toml"),
            data_dir: dir.join("data"),
            snapshot_file: dir.join("data").join("snapshot.bin"),
            state_dir: dir.join("state"),
            state_file: dir.join("state").join("state.json"),
        }
    }

    #[test]
    fn load_does_not_mint_a_missing_salt() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(dir.path());
        let mut config = Config::default();

        let error = match derive_from_passphrase(&mut config, &paths, "hunter2", false) {
            Ok(_) => panic!("the load path derived a key from a missing salt"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("kdf_salt"),
            "unexpected error: {error}"
        );
        assert!(config.kdf_salt.is_none());
        assert!(!paths.config_file.exists(), "load wrote the config file");
    }

    #[test]
    fn create_mints_a_salt_and_derives_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(dir.path());
        let mut config = Config::default();

        let key = derive_from_passphrase(&mut config, &paths, "hunter2", true).unwrap();
        assert_eq!(key.key.len(), KEY_LEN);
        assert_ne!(key.key, [0u8; KEY_LEN]);
        assert_eq!(key.source, KeySource::Passphrase);

        let salt = config.kdf_salt.clone().expect("a salt was minted");
        assert!(!salt.is_empty());
        let saved = Config::load(&paths).unwrap();
        assert_eq!(saved.kdf_salt.as_deref(), Some(salt.as_str()));

        let again = derive_from_passphrase(&mut config, &paths, "hunter2", true).unwrap();
        assert_eq!(again.key, key.key);
        assert_eq!(config.kdf_salt.as_deref(), Some(salt.as_str()));
    }
}
