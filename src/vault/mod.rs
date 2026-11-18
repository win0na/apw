use crate::config::{write_private, Config, Paths};
use crate::error::{Error, Result};
use crate::model::Vault;
use crate::store;

pub mod fixture;

/// Resolve the snapshot key before any network work, so a missing key fails
/// early. On a first write this creates the key.
pub fn prepare(paths: &Paths, config: &mut Config) -> Result<()> {
    if paths.snapshot_file.exists() {
        store::key::load(config, paths)?;
    } else {
        let _ = store::key::create(config, paths)?;
    }
    Ok(())
}

pub fn load(paths: &Paths, config: &mut Config) -> Result<Vault> {
    if !paths.snapshot_file.exists() {
        return Err(Error::Auth(format!(
            "no snapshot at {}; run `apw login` first",
            paths.snapshot_file.display()
        )));
    }
    let key = store::key::load(config, paths)?;
    let bytes = std::fs::read(&paths.snapshot_file)?;
    store::open(&bytes, &key.key)
}

pub fn save(paths: &Paths, config: &mut Config, vault: &Vault) -> Result<()> {
    paths.ensure()?;
    let key = if paths.snapshot_file.exists() {
        store::key::load(config, paths)?
    } else {
        store::key::create(config, paths)?
    };
    let bytes = store::seal(vault, &key.key)?;
    write_private(&paths.snapshot_file, &bytes)
}
