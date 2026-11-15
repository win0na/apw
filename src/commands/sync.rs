use std::path::{Path, PathBuf};

use base64::Engine;

use crate::auth::anisette::Anisette;
use crate::ckks;
use crate::cloudkit::Gateway;
use crate::commands::join::block_on;
use crate::config::{self, Config, Paths, State};
use crate::error::{Error, Result};
use crate::model::{Entry, Source};
use crate::octagon::{self, keys::PeerKeys};
use crate::output;
use crate::vault;

pub fn run(
    paths: &Paths,
    config: &mut Config,
    force: bool,
    fixture: Option<PathBuf>,
    json: bool,
) -> Result<()> {
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

    let fixture = fixture.or_else(|| {
        std::env::var_os("APW_FIXTURE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    });

    match fixture {
        Some(fixture) => sync_fixture(paths, config, &fixture, json),
        None => sync_live(paths, config, json),
    }
}

fn sync_fixture(paths: &Paths, config: &mut Config, fixture: &Path, json: bool) -> Result<()> {
    let mut snapshot = vault::fixture::read(fixture)?;
    snapshot.account = config.account.clone().or(snapshot.account);
    snapshot.generated_at = Some(chrono::Utc::now());
    vault::save(paths, config, &snapshot)?;
    finish(
        paths,
        &snapshot,
        json,
        &format!("fixture {}", fixture.display()),
    )
}

fn sync_live(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    if !paths.snapshot_file.exists() {
        return Err(Error::Invalid("run `apw login` first".into()));
    }
    let mut snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Invalid("run `apw login` first".into()))?;
    let peer_state = snapshot
        .peer
        .clone()
        .ok_or_else(|| Error::Invalid("run `apw join` first".into()))?;
    let anisette_url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let encryption = PeerKeys::from_x963(
        &decode(&peer_state.signing_key)?,
        &decode(&peer_state.encryption_key)?,
    )?;

    let (tlkshares, synckeys, items) = block_on(async {
        let identity = Anisette::new(&anisette_url).identity().await?;
        let gateway = Gateway::bootstrap(&session, &identity).await?;

        let mut tlkshares = Vec::new();
        let mut synckeys = Vec::new();
        let mut items = Vec::new();

        let mut peers = vec![peer_state.id.clone()];
        if let Some(sponsor) = &peer_state.sponsor_id {
            peers.push(sponsor.clone());
        }
        for peer in peers {
            let response = octagon::tlk_shares(&gateway, &peer).await?;
            let (mut shares, mut keys) = ckks::shares_from_response(&response)?;
            tlkshares.append(&mut shares);
            synckeys.append(&mut keys);
        }

        for zone in ["Passwords", "Manatee"] {
            let mut token: Option<Vec<u8>> = None;
            loop {
                let page = match gateway.record_sync(zone, token.as_deref()).await {
                    Ok(page) => page,
                    Err(error) if error.to_string().to_lowercase().contains("zone") => break,
                    Err(error) => return Err(error),
                };
                for record in page.records {
                    match record.record_type.as_str() {
                        "tlkshare" => tlkshares.push(record),
                        "synckey" => synckeys.push(record),
                        "item" => items.push(record),
                        _ => {}
                    }
                }
                if page.status == 1 {
                    match page.token {
                        Some(next) if Some(&next) != token.as_ref() => token = Some(next),
                        _ => break,
                    }
                } else {
                    break;
                }
            }
        }
        Ok::<_, Error>((tlkshares, synckeys, items))
    })?;

    let tlks = ckks::unwrap_tlkshares(&tlkshares, &peer_state.id, &encryption.encryption);
    let class_keys = ckks::unwrap_class_keys(&synckeys, &tlks);
    let decrypted = ckks::decrypt_items(&items, &class_keys);
    let mut entries: Vec<Entry> = decrypted
        .iter()
        .filter_map(|(id, value)| ckks::entry_from_plist(id, value))
        .collect();
    entries.sort_by(|left, right| left.id.cmp(&right.id));

    snapshot.entries = entries;
    snapshot.source = Source::Icloud;
    snapshot.generated_at = Some(chrono::Utc::now());
    vault::save(paths, config, &snapshot)?;

    let note = format!(
        "iCloud ({} TLK shares, {} class keys)",
        tlks.len(),
        class_keys.len()
    );
    finish(paths, &snapshot, json, &note)
}

fn finish(paths: &Paths, snapshot: &crate::model::Vault, json: bool, note: &str) -> Result<()> {
    let state = State {
        last_sync: snapshot.generated_at,
        last_status: Some("ok".into()),
        account: snapshot.account.clone(),
        source: Some(snapshot.source.to_string()),
        entries: snapshot.entries.len() as u32,
        groups: snapshot.groups.len() as u32,
        failures: 0,
        next_attempt: None,
    };
    config::save_state(paths, &state)?;

    let result = serde_json::json!({
        "source": snapshot.source.to_string(),
        "account": snapshot.account,
        "entries": snapshot.entries.len(),
        "groups": snapshot.groups.len(),
        "snapshot": paths.snapshot_file,
    });

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([result])));
    } else {
        println!("synced {} entries from {note}", snapshot.entries.len());
    }
    Ok(())
}

fn decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Message(format!("invalid stored peer key: {error}")))
}
