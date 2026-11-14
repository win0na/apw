use crate::config::{write_private, Config, Paths};
use crate::error::{Error, Result};
use crate::model::Vault;
use crate::store;

pub mod fixture;

pub fn load(paths: &Paths, config: &mut Config) -> Result<Vault> {
    let key = store::key::load_or_create(config, paths)?;
    let bytes = match std::fs::read(&paths.snapshot_file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Message(format!(
                "no snapshot at {}; run `apw sync` first",
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
