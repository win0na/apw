use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Local anisette sidecar. Most installs run it on the default port.
pub const DEFAULT_ANISETTE_URL: &str = "http://127.0.0.1:6969";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anisette_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    #[serde(default)]
    pub sync: SyncConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default = "SyncConfig::min_interval_default")]
    pub min_interval_seconds: u64,
    #[serde(default = "SyncConfig::max_backoff_default")]
    pub max_backoff_seconds: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            min_interval_seconds: Self::min_interval_default(),
            max_backoff_seconds: Self::max_backoff_default(),
        }
    }
}

impl SyncConfig {
    fn min_interval_default() -> u64 {
        300
    }

    fn max_backoff_default() -> u64 {
        21600
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub entries: u32,
    #[serde(default)]
    pub logins: u32,
    #[serde(default)]
    pub passkeys: u32,
    #[serde(default)]
    pub groups: u32,
    #[serde(default)]
    pub shared_entries: u32,
    #[serde(default)]
    pub failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub snapshot_file: PathBuf,
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::Message("HOME is not set".into()))?;

        let config_dir = env_dir("APW_CONFIG_DIR", "XDG_CONFIG_HOME", &home, ".config");
        let data_dir = env_dir("APW_DATA_DIR", "XDG_DATA_HOME", &home, ".local/share");
        let state_dir = env_dir("APW_STATE_DIR", "XDG_STATE_HOME", &home, ".local/state");

        Ok(Self {
            config_file: config_dir.join("config.toml"),
            snapshot_file: data_dir.join("snapshot.bin"),
            state_file: state_dir.join("state.json"),
            config_dir,
            data_dir,
            state_dir,
        })
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [&self.config_dir, &self.data_dir, &self.state_dir] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}

fn env_dir(override_name: &str, xdg_name: &str, home: &std::path::Path, fallback: &str) -> PathBuf {
    if let Some(value) = std::env::var_os(override_name) {
        return PathBuf::from(value);
    }
    if let Some(value) = std::env::var_os(xdg_name) {
        return PathBuf::from(value).join("apw");
    }
    home.join(fallback).join("apw")
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Self> {
        match std::fs::read_to_string(&paths.config_file) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        paths.ensure()?;
        let text = toml::to_string_pretty(self)?;
        write_private(&paths.config_file, text.as_bytes())
    }

    pub fn anisette_url(&self) -> Option<String> {
        std::env::var("APW_ANISETTE_URL")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| self.anisette_url.clone().filter(|value| !value.is_empty()))
            .or_else(|| Some(DEFAULT_ANISETTE_URL.to_string()))
    }
}

pub fn load_state(paths: &Paths) -> Result<State> {
    match std::fs::read_to_string(&paths.state_file) {
        Ok(text) => Ok(serde_json::from_str(&text)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(error) => Err(error.into()),
    }
}

pub fn save_state(paths: &Paths, state: &State) -> Result<()> {
    paths.ensure()?;
    let text = serde_json::to_vec_pretty(state)?;
    write_private(&paths.state_file, &text)
}

pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_ANISETTE_URL};

    #[test]
    fn anisette_defaults_to_the_local_sidecar() {
        if std::env::var_os("APW_ANISETTE_URL").is_none() {
            let config = Config::default();
            assert_eq!(config.anisette_url().as_deref(), Some(DEFAULT_ANISETTE_URL));
        }
    }
}
