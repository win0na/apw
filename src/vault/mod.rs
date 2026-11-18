use crate::config::{write_private, Config, Paths};
use crate::error::{Error, Result};
use crate::model::Vault;
use crate::store;

pub mod fixture;

/// Read the snapshot passphrase once per process and export it, so later
/// `load` and `save` calls do not prompt again. Returns the passphrase when one
/// is in use; Secret Service keys need no passphrase and return `None`.
pub fn ensure_passphrase(paths: &Paths) -> Result<Option<String>> {
    use std::io::IsTerminal;

    if let Some(value) = std::env::var("APW_PASSPHRASE")
        .ok()
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(value));
    }

    #[cfg(feature = "keyring")]
    if crate::store::key::has_secret_service_key()? {
        return Ok(None);
    }

    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }

    let passphrase = if paths.snapshot_file.exists() {
        rpassword::prompt_password("apw passcode: ")?
    } else {
        eprintln!("The apw passcode encrypts the local snapshot.");
        eprintln!("Use your device passcode so the escrow step can reuse it.");
        let first = rpassword::prompt_password("Enter a new apw passcode: ")?;
        let second = rpassword::prompt_password("Confirm the apw passcode: ")?;
        if first != second {
            return Err(Error::Invalid("the passcodes do not match".into()));
        }
        first
    };
    if passphrase.is_empty() {
        return Err(Error::Invalid("the passcode is empty".into()));
    }
    std::env::set_var("APW_PASSPHRASE", &passphrase);
    Ok(Some(passphrase))
}

pub fn load(paths: &Paths, config: &mut Config) -> Result<Vault> {
    let key = store::key::load_or_create(config, paths)?;
    let bytes = match std::fs::read(&paths.snapshot_file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Message(format!(
                "no snapshot at {}; run `apw login` first",
                paths.snapshot_file.display()
            )));
        }
        Err(error) => return Err(error.into()),
    };
    store::open(&bytes, &key.key)
}

pub fn save(paths: &Paths, config: &mut Config, vault: &Vault) -> Result<()> {
    paths.ensure()?;
    let key = store::key::load_or_create(config, paths)?;
    let bytes = store::seal(vault, &key.key)?;
    write_private(&paths.snapshot_file, &bytes)
}
