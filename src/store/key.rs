use base64::Engine;
use rand::RngCore;

use crate::config::{Config, Paths};
use crate::error::{Error, Result};

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

#[derive(Clone)]
pub struct SnapshotKey {
    pub key: [u8; KEY_LEN],
    pub source: KeySource,
}

/// Resolve the key of an existing snapshot. This never mints a key: a missing
/// Secret Service entry must not create a new key behind an old snapshot.
pub fn load(config: &mut Config, paths: &Paths) -> Result<SnapshotKey> {
    if let Some(key) = session_key(paths) {
        return Ok(key);
    }
    if let Some(passphrase) = env_passphrase() {
        let key = derive_from_passphrase(config, paths, &passphrase, false)?;
        remember_session(paths, &key);
        return Ok(key);
    }

    #[cfg(feature = "secret-service")]
    if let Some(key) = secret_service::read() {
        let key = SnapshotKey {
            key,
            source: KeySource::SecretService,
        };
        remember_session(paths, &key);
        return Ok(key);
    }

    let passphrase = read_passphrase()?;
    let key = derive_from_passphrase(config, paths, &passphrase, false)?;
    remember_session(paths, &key);
    Ok(key)
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
    if let Some(key) = session_key(paths) {
        return Ok(key);
    }
    if let Some(passphrase) = env_passphrase() {
        let key = derive_from_passphrase(config, paths, &passphrase, true)?;
        remember_session(paths, &key);
        return Ok(key);
    }

    #[cfg(feature = "secret-service")]
    if let Some(key) = secret_service::create_or_read() {
        let key = SnapshotKey {
            key,
            source: KeySource::SecretService,
        };
        remember_session(paths, &key);
        return Ok(key);
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
    let key = derive_from_passphrase(config, paths, &passphrase, true)?;
    remember_session(paths, &key);
    Ok(key)
}

/// The key resolved earlier in this process. A command may load the snapshot
/// and save it again; the passphrase must be asked for once, not twice.
static SESSION: std::sync::OnceLock<std::sync::Mutex<Vec<(std::path::PathBuf, SnapshotKey)>>> =
    std::sync::OnceLock::new();

fn session() -> &'static std::sync::Mutex<Vec<(std::path::PathBuf, SnapshotKey)>> {
    SESSION.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn session_key(paths: &Paths) -> Option<SnapshotKey> {
    let guard = session().lock().ok()?;
    guard
        .iter()
        .find(|(path, _)| path == &paths.snapshot_file)
        .map(|(_, key)| key.clone())
}

pub fn remember_session(paths: &Paths, key: &SnapshotKey) {
    if let Ok(mut guard) = session().lock() {
        guard.retain(|(path, _)| path != &paths.snapshot_file);
        guard.push((paths.snapshot_file.clone(), key.clone()));
    }
}

fn env_passphrase() -> Option<String> {
    std::env::var("APW_PASSPHRASE")
        .ok()
        .filter(|value| !value.is_empty())
}

/// Store the key even when an item is readable. The passphrase recovery path
/// uses this after opening a snapshot that the stored key could not, so the
/// next command stops prompting.
#[cfg(feature = "secret-service")]
pub fn replace(key: &[u8; KEY_LEN]) -> Result<()> {
    store_result(key)
}

#[cfg(feature = "secret-service")]
fn store_result(key: &[u8; KEY_LEN]) -> Result<()> {
    if secret_service::store(key) {
        Ok(())
    } else {
        Err(Error::Message(
            "cannot store the snapshot key in Secret Service".into(),
        ))
    }
}

#[cfg(feature = "secret-service")]
mod secret_service {
    use std::collections::HashMap;

    use dbus_secret_service::{EncryptionType, Item, SecretService};

    use super::{decode_key, encode_key, random_key, KEY_LEN};

    /// The item apw writes. Attributes, not the label, identify it.
    const ATTRIBUTES: [(&str, &str); 3] = [
        ("application", "apw"),
        ("purpose", "snapshot-key"),
        ("schema", "1"),
    ];
    const LABEL: &str = "apw snapshot key (v1)";
    const CONTENT_TYPE: &str = "text/plain";

    /// keyring 3.6.3 stored the key as `service`/`username`/`target`. It is
    /// read once and copied to the item above.
    const LEGACY_ATTRIBUTES: [(&str, &str); 3] = [
        ("service", "apw"),
        ("username", "snapshot-key"),
        ("target", "default"),
    ];

    /// What the search found. Only `Absent` may mint a new key: an item that
    /// exists but cannot be read must never be replaced, because the old key
    /// may still open a snapshot in another data directory.
    enum Stored {
        Key([u8; KEY_LEN]),
        Absent,
        Unreadable,
    }

    /// Read the current item, copying a keyring item on the first run.
    pub fn read() -> Option<[u8; KEY_LEN]> {
        match read_with(&connect()?) {
            Stored::Key(key) => Some(key),
            Stored::Absent | Stored::Unreadable => None,
        }
    }

    /// Reuse the stored key for a first write. Only an absent item mints one;
    /// an unreadable item falls through to the passphrase so the key survives.
    pub fn create_or_read() -> Option<[u8; KEY_LEN]> {
        let service = connect()?;
        match read_with(&service) {
            Stored::Key(key) => Some(key),
            Stored::Unreadable => None,
            Stored::Absent => {
                // Writes hold the snapshot lock, so a first write has no
                // competing minter.
                let key = random_key();
                store_with(&service, &key).then_some(key)
            }
        }
    }

    /// Write the key when no item is readable. The caller has already checked
    /// for an existing item.
    pub fn store(key: &[u8; KEY_LEN]) -> bool {
        connect().is_some_and(|service| store_with(&service, key))
    }

    /// A command must not wait forever on an unlock prompt. Interactive runs
    /// get 30 seconds to answer; a headless run cannot answer at all, so a
    /// locked item counts as unreadable and the caller falls back to the
    /// passphrase or fails with the documented message.
    fn connect() -> Option<SecretService> {
        use std::io::IsTerminal;
        let seconds = if std::io::stdin().is_terminal() {
            30
        } else {
            0
        };
        SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, seconds).ok()
    }

    fn read_with(service: &SecretService) -> Stored {
        match read_matching(service) {
            Stored::Key(key) => return Stored::Key(key),
            Stored::Unreadable => {
                // The keyring item may still hold the readable key.
                return match read_legacy(service) {
                    Stored::Key(key) => {
                        copy(&key);
                        Stored::Key(key)
                    }
                    _ => Stored::Unreadable,
                };
            }
            Stored::Absent => {}
        }
        match read_legacy(service) {
            Stored::Key(key) => {
                copy(&key);
                Stored::Key(key)
            }
            Stored::Unreadable => Stored::Unreadable,
            Stored::Absent => read_default_fallback(service),
        }
    }

    /// keyring 3.6.3 refused to guess when more than one item matched. Keep
    /// that rule: a wrong key is worse than a prompt.
    fn read_legacy(service: &SecretService) -> Stored {
        let Ok(found) = service.search_items(attributes(&LEGACY_ATTRIBUTES)) else {
            return Stored::Unreadable;
        };
        match found.unlocked.len() + found.locked.len() {
            0 => Stored::Absent,
            1 => {
                let Some(item) = found.unlocked.into_iter().chain(found.locked).next() else {
                    return Stored::Unreadable;
                };
                match read_item(&item) {
                    Some(key) => Stored::Key(key),
                    None => Stored::Unreadable,
                }
            }
            _ => Stored::Unreadable,
        }
    }

    /// keyring v1 stored items without a `target` attribute in the default
    /// collection. Search that collection for the two attributes and filter
    /// the missing target here.
    fn read_default_fallback(service: &SecretService) -> Stored {
        let Ok(collection) = service.get_default_collection() else {
            return Stored::Unreadable;
        };
        let mut query = HashMap::new();
        query.insert("service", "apw");
        query.insert("username", "snapshot-key");
        let Ok(items) = collection.search_items(query) else {
            return Stored::Unreadable;
        };
        let legacy: Vec<_> = items
            .into_iter()
            .filter(|item| {
                item.get_attributes()
                    .is_ok_and(|attributes| !attributes.contains_key("target"))
            })
            .collect();
        match legacy.len() {
            0 => Stored::Absent,
            1 => match read_item(&legacy[0]) {
                Some(key) => {
                    copy(&key);
                    Stored::Key(key)
                }
                None => Stored::Unreadable,
            },
            _ => Stored::Unreadable,
        }
    }

    fn read_matching(service: &SecretService) -> Stored {
        let Ok(found) = service.search_items(attributes(&ATTRIBUTES)) else {
            return Stored::Unreadable;
        };
        if found.unlocked.is_empty() && found.locked.is_empty() {
            return Stored::Absent;
        }
        found
            .unlocked
            .iter()
            .chain(found.locked.iter())
            .find_map(read_item)
            .map_or(Stored::Unreadable, Stored::Key)
    }

    /// Copy the key to the current item without touching the old one. The
    /// copy runs on a connection that never prompts, because it can be reached
    /// from a read command, and it is skipped while the default collection is
    /// locked. The old item is not deleted: it is the fallback for readers that
    /// still use the keyring item.
    fn copy(key: &[u8; KEY_LEN]) {
        let Ok(service) = SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0)
        else {
            return;
        };
        let Ok(collection) = service.get_default_collection() else {
            return;
        };
        if collection.is_locked().unwrap_or(true) {
            return;
        }
        let _ = collection.create_item(
            LABEL,
            attributes(&ATTRIBUTES),
            encode_key(key).as_bytes(),
            true,
            CONTENT_TYPE,
        );
    }

    fn store_with(service: &SecretService, key: &[u8; KEY_LEN]) -> bool {
        let Ok(collection) = service.get_default_collection() else {
            return false;
        };
        collection
            .create_item(
                LABEL,
                attributes(&ATTRIBUTES),
                encode_key(key).as_bytes(),
                true,
                CONTENT_TYPE,
            )
            .is_ok()
    }

    fn read_item(item: &Item<'_>) -> Option<[u8; KEY_LEN]> {
        if item.is_locked().unwrap_or(false) {
            item.unlock().ok()?;
        }
        decode_key(std::str::from_utf8(&item.get_secret().ok()?).ok()?).ok()
    }

    fn attributes<'a>(pairs: &[(&'a str, &'a str)]) -> HashMap<&'a str, &'a str> {
        pairs.iter().copied().collect()
    }

    #[cfg(test)]
    mod tests {
        use super::{ATTRIBUTES, LEGACY_ATTRIBUTES};

        #[test]
        fn the_new_attributes_do_not_match_the_keyring_item() {
            let new = super::attributes(&ATTRIBUTES);
            let legacy = super::attributes(&LEGACY_ATTRIBUTES);
            for (key, value) in &legacy {
                assert_ne!(new.get(key), Some(value), "{key} is shared");
            }
            assert_eq!(legacy.get("service"), Some(&"apw"));
            assert_eq!(legacy.get("username"), Some(&"snapshot-key"));
            assert_eq!(legacy.get("target"), Some(&"default"));
        }
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

#[cfg(feature = "secret-service")]
fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

#[cfg(feature = "secret-service")]
fn encode_key(key: &[u8; KEY_LEN]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

#[cfg(feature = "secret-service")]
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
    use super::{
        derive_from_passphrase, remember_session, session_key, KeySource, SnapshotKey, KEY_LEN,
    };
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
    fn session_cache_is_scoped_to_one_snapshot() {
        let first = std::env::temp_dir().join("apw-session-test-a.bin");
        let second = std::env::temp_dir().join("apw-session-test-b.bin");
        let paths = |snapshot: &std::path::Path| Paths {
            config_dir: std::env::temp_dir(),
            config_file: std::env::temp_dir().join("config.toml"),
            data_dir: std::env::temp_dir(),
            snapshot_file: snapshot.to_path_buf(),
            state_dir: std::env::temp_dir(),
            state_file: std::env::temp_dir().join("state.json"),
        };
        let key = SnapshotKey {
            key: [7u8; KEY_LEN],
            source: KeySource::Passphrase,
        };
        remember_session(&paths(&first), &key);
        assert!(session_key(&paths(&first)).is_some());
        assert!(session_key(&paths(&second)).is_none());
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
