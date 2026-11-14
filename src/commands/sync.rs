use std::path::PathBuf;

use crate::config::{self, Config, Paths, State};
use crate::error::{Error, Result};
use crate::output;
use crate::vault;

pub fn run(
    paths: &Paths,
    config: &mut Config,
    force: bool,
    fixture: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let fixture = fixture.or_else(|| {
        std::env::var_os("APW_FIXTURE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    });

    let Some(fixture) = fixture else {
        return Err(Error::Message(
            "live sync needs the iCloud backend, which this build does not include yet; \
             use `apw sync --fixture <file>`"
                .into(),
        ));
    };

    if !force {
        let state = config::load_state(paths)?;
        if let Some(last) = state.last_sync {
            let elapsed = chrono::Utc::now().signed_duration_since(last).num_seconds();
            if elapsed >= 0 && (elapsed as u64) < config.sync.min_interval_seconds {
                return Err(Error::Message(format!(
                    "last sync was {elapsed}s ago; the floor is {}s (use --force)",
                    config.sync.min_interval_seconds
                )));
            }
        }
    }

    let mut vault = vault::fixture::read(&fixture)?;
    vault.account = config.account.clone().or(vault.account);
    vault.generated_at = Some(chrono::Utc::now());

    vault::save(paths, config, &vault)?;

    let state = State {
        last_sync: vault.generated_at,
        last_status: Some("ok".into()),
        account: vault.account.clone(),
        source: Some(vault.source.to_string()),
        entries: vault.entries.len() as u32,
        groups: vault.groups.len() as u32,
        failures: 0,
        next_attempt: None,
    };
    config::save_state(paths, &state)?;

    let result = serde_json::json!({
        "source": vault.source.to_string(),
        "account": vault.account,
        "entries": vault.entries.len(),
        "groups": vault.groups.len(),
        "snapshot": paths.snapshot_file,
    });

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([result])));
    } else {
        println!(
            "synced {} entries from {}",
            vault.entries.len(),
            fixture.display()
        );
    }
    Ok(())
}
