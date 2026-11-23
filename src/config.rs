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
    #[serde(default)]
    pub tui: TuiConfig,
    /// Keys written by a newer apw. A save keeps them instead of deleting them.
    #[serde(flatten)]
    pub extra: toml::Table,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TuiConfig {
    /// Category to open on the next launch: logins, notes, wifi, passkeys, groups, trash, pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_category: Option<String>,
    /// Force the list/detail split (`true`) or the stacked layout (`false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<bool>,
    /// Keep the block wordmark on the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_wordmark: Option<bool>,
    /// Start with mouse reporting on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mouse: Option<bool>,
    /// Clear the filter when the interface opens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_query_on_launch: Option<bool>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default = "SyncConfig::min_interval_default")]
    pub min_interval_seconds: u64,
    #[serde(default = "SyncConfig::max_backoff_default")]
    pub max_backoff_seconds: u64,
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            min_interval_seconds: Self::min_interval_default(),
            max_backoff_seconds: Self::max_backoff_default(),
            extra: toml::Table::new(),
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
    pub wifi: u32,
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

    /// Read, change, and write the config under the snapshot lock.
    ///
    /// Callers that only change one field must use this instead of saving a
    /// stale in-memory copy: the load fails closed, so a malformed file is
    /// never replaced by a default.
    pub fn update<F>(paths: &Paths, change: F) -> Result<Self>
    where
        F: FnOnce(&mut Self),
    {
        let _lock = lock_config(paths)?;
        let mut config = Self::load(paths)?;
        change(&mut config);
        config.save(paths)?;
        Ok(config)
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

/// Held for the lifetime of a command that loads, refreshes and saves the
/// snapshot. The file itself carries no data; the kernel lock is the state.
pub struct SnapshotLock {
    _file: std::fs::File,
}

/// Serialize snapshot writers across processes so a timer run and a manual
/// sync cannot both load, fetch and save and lose one side's updates.
pub fn lock_snapshot(paths: &Paths) -> Result<SnapshotLock> {
    use std::os::unix::fs::OpenOptionsExt;
    paths.ensure()?;
    let path = paths.data_dir.join("snapshot.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
    // SAFETY: fd is open for the lifetime of `file`.
    if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(SnapshotLock { _file: file })
}

/// Serialize config read-modify-write across processes. Separate from the
/// snapshot lock so a long sync does not block a tab change.
pub fn lock_config(paths: &Paths) -> Result<SnapshotLock> {
    use std::os::unix::fs::OpenOptionsExt;
    paths.ensure()?;
    let path = paths.config_dir.join("config.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
    // SAFETY: fd is open for the lifetime of `file`.
    if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(SnapshotLock { _file: file })
}

pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "apw".to_string());

    // A fixed `<name>.tmp` lets two concurrent writers truncate each other's
    // scratch file and publish a partial document. Each writer gets its own
    // temp name instead; `create_new` keeps a collision from reusing a file.
    let mut created = None;
    for _ in 0..4 {
        let candidate = parent.join(format!(
            ".{name}.{}.{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (tmp, mut file) = created.ok_or_else(|| {
        Error::Message(format!(
            "cannot create a temporary file next to {}",
            path.display()
        ))
    })?;

    let write = || -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, path)?;
        // Persist the directory entry so the rename survives a crash. Some
        // filesystems reject a directory fsync and an fd limit can refuse the
        // open, but the bytes are already durable and the rename already
        // happened, so a failure here must not report the write as failed.
        if let Err(error) = std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!("config: directory fsync failed: {error}");
            }
        }
        Ok(())
    };

    let result = write();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
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

    #[test]
    fn update_preserves_unknown_keys_and_the_salt() {
        let dir = tempfile::tempdir().unwrap();
        let paths = super::Paths {
            config_dir: dir.path().join("config"),
            config_file: dir.path().join("config/config.toml"),
            data_dir: dir.path().join("data"),
            snapshot_file: dir.path().join("data/snapshot.bin"),
            state_dir: dir.path().join("state"),
            state_file: dir.path().join("state/state.json"),
        };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(
            &paths.config_file,
            "kdf_salt = \"c2FsdA==\"\nfuture_key = \"keep me\"\n",
        )
        .unwrap();
        Config::update(&paths, |config| {
            config.account = Some("me@example.com".into());
        })
        .unwrap();
        let saved = Config::load(&paths).unwrap();
        assert_eq!(saved.kdf_salt.as_deref(), Some("c2FsdA=="));
        assert_eq!(
            saved
                .extra
                .get("future_key")
                .and_then(|value| value.as_str()),
            Some("keep me")
        );
    }

    #[test]
    fn concurrent_writes_publish_one_complete_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let payloads = [vec![b'a'; 256 * 1024], vec![b'b'; 256 * 1024]];

        std::thread::scope(|scope| {
            for payload in &payloads {
                let path = path.clone();
                scope.spawn(move || super::write_private(&path, payload).unwrap());
            }
        });

        let written = std::fs::read(&path).unwrap();
        assert!(
            payloads.contains(&written),
            "the published file is not one of the payloads: {} bytes",
            written.len()
        );
    }
}
