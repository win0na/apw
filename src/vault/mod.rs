use crate::config::{write_private, Config, Paths};
use crate::error::{Error, Result};
use crate::model::Vault;
use crate::store;
use crate::store::key::KeySource;

pub mod fixture;

/// Resolve the snapshot key before any network work, so a missing key fails
/// early. On a first write this creates the key.
pub fn prepare(paths: &Paths, config: &mut Config) -> Result<()> {
    if snapshot_exists(paths)? {
        store::key::load(config, paths)?;
    } else {
        let _ = store::key::create(config, paths)?;
    }
    Ok(())
}

pub fn load(paths: &Paths, config: &mut Config) -> Result<Vault> {
    if !snapshot_exists(paths)? {
        return Err(Error::Auth(format!(
            "no snapshot at {}; run `apw login` first",
            paths.snapshot_file.display()
        )));
    }
    let key = store::key::load(config, paths)?;
    let bytes = std::fs::read(&paths.snapshot_file)?;
    match store::open(&bytes, &key.key) {
        Ok(vault) => Ok(vault),
        Err(Error::Aead) if key.source == KeySource::SecretService => {
            reopen_with_passphrase(paths, config, &bytes)
        }
        Err(error) => Err(error),
    }
}

pub fn save(paths: &Paths, config: &mut Config, vault: &Vault) -> Result<()> {
    paths.ensure()?;
    let key = if snapshot_exists(paths)? {
        store::key::load(config, paths)?
    } else {
        store::key::create(config, paths)?
    };
    let bytes = store::seal(vault, &key.key)?;
    write_private(&paths.snapshot_file, &bytes)
}

/// A snapshot written with a passphrase can outlive the Secret Service entry
/// that 0.1.5 left behind: the entry opens nothing. If the passphrase still
/// works, replace the stale entry so the next read does not prompt again.
fn reopen_with_passphrase(paths: &Paths, config: &mut Config, bytes: &[u8]) -> Result<Vault> {
    let recovered = (|| -> Result<Vault> {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return Err(Error::Aead);
        }
        let passphrase = rpassword::prompt_password("apw passphrase: ")
            .map_err(|error| Error::Message(format!("cannot read passphrase: {error}")))?;
        let derived = store::key::derive_for_load(config, paths, &passphrase)?;
        let vault = store::open(bytes, &derived.key)?;
        // Later saves in this process must use the key that opened the file,
        // not the stale Secret Service entry that failed above.
        store::key::remember_session(paths, &derived);
        #[cfg(feature = "secret-service")]
        {
            // The vault is open; a backend failure must not hide that.
            let _ = store::key::replace(&derived.key);
        }
        Ok(vault)
    })();
    recovered.map_err(|_| Error::Aead)
}

fn snapshot_exists(paths: &Paths) -> Result<bool> {
    match std::fs::metadata(&paths.snapshot_file) {
        Ok(meta) => Ok(meta.is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
