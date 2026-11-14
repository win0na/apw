use crate::config::{self, Config, Paths};
use crate::error::Result;
use crate::output;

pub fn run(paths: &Paths, config: &Config, json: bool) -> Result<()> {
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
        "groups": state.groups,
        "last_sync": state.last_sync,
        "snapshot": paths.snapshot_file,
        "snapshot_bytes": snapshot.map(|meta| meta.len()).unwrap_or(0),
        "needs_sync": needs_sync,
        "config": paths.config_file,
    });

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([result])));
        return Ok(());
    }

    for (label, value) in [
        (
            "account",
            result["account"].as_str().unwrap_or("-").to_string(),
        ),
        (
            "source",
            result["source"].as_str().unwrap_or("-").to_string(),
        ),
        ("entries", result["entries"].to_string()),
        ("groups", result["groups"].to_string()),
        (
            "last sync",
            result["last_sync"].as_str().unwrap_or("never").to_string(),
        ),
        (
            "snapshot",
            format!(
                "{} ({} bytes)",
                paths.snapshot_file.display(),
                result["snapshot_bytes"]
            ),
        ),
    ] {
        println!("{label:<10} {value}");
    }
    Ok(())
}
