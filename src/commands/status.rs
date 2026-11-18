use crate::config::{self, Config, Paths};
use crate::error::Result;
use crate::output::{self, Style};

pub fn run(paths: &Paths, config: &Config, style: Style) -> Result<()> {
    let state = config::load_state(paths)?;
    let snapshot = std::fs::metadata(&paths.snapshot_file).ok();
    let interval = config.sync.min_interval_seconds;

    let needs_sync = match state.last_sync {
        Some(last) => {
            let elapsed = chrono::Utc::now().signed_duration_since(last).num_seconds();
            elapsed < 0 || elapsed as u64 > interval
        }
        None => true,
    };

    let result = serde_json::json!({
        "account": state.account,
        "source": state.source,
        "entries": state.entries,
        "logins": state.logins,
        "passkeys": state.passkeys,
        "wifi": state.wifi,
        "groups": state.groups,
        "shared_entries": state.shared_entries,
        "last_sync": state.last_sync,
        "last_status": state.last_status,
        "snapshot": paths.snapshot_file,
        "snapshot_bytes": snapshot.map(|meta| meta.len()).unwrap_or(0),
        "needs_sync": needs_sync,
        "config": paths.config_file,
    });

    if style.json {
        output::print_json(&output::success(result));
        return Ok(());
    }

    let rows = [
        (
            "Account",
            result["account"].as_str().unwrap_or("-").to_string(),
        ),
        (
            "Source",
            result["source"].as_str().unwrap_or("-").to_string(),
        ),
        ("Entries", result["entries"].to_string()),
        ("Logins", result["logins"].to_string()),
        ("Passkeys", result["passkeys"].to_string()),
        ("Wi-Fi", result["wifi"].to_string()),
        ("Groups", result["groups"].to_string()),
        ("Shared", result["shared_entries"].to_string()),
        (
            "Last sync",
            result["last_sync"].as_str().unwrap_or("never").to_string(),
        ),
        (
            "Last status",
            result["last_status"].as_str().unwrap_or("-").to_string(),
        ),
        (
            "Snapshot",
            format!(
                "{} ({} bytes)",
                paths.snapshot_file.display(),
                result["snapshot_bytes"]
            ),
        ),
    ];
    output::print_kv(&rows);
    Ok(())
}
