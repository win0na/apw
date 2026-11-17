use std::path::{Path, PathBuf};

use base64::Engine;

use crate::auth::anisette::Anisette;
use crate::ckks;
use crate::cloudkit::Gateway;
use crate::commands::join::block_on;
use crate::config::{self, Config, Paths, State};
use crate::error::{Error, Result};
use crate::model::{Entry, EntryKind, Source};
use crate::octagon::{self, keys::PeerKeys};
use crate::output;
use crate::pcs::ServiceKey;
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

    let (tlkshares, synckeys, items, session) = block_on(async {
        let mut session = session;
        let identity = Anisette::new(&anisette_url).identity().await?;
        let mac = Anisette::new(&anisette_url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = match Gateway::bootstrap(
            &session,
            &mac,
            crate::cloudkit::CONTAINER,
            crate::cloudkit::Scope::Private,
        )
        .await
        {
            Ok(gateway) => gateway,
            Err(error) if crate::auth::is_auth_error(&error) => {
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("sync: session rejected, re-fetching the service map");
                }
                session = crate::auth::refresh_services_async(config, &session)
                    .await
                    .map_err(|refresh| {
                        Error::Message(format!(
                            "{error}; refresh failed: {refresh}; run `apw login`"
                        ))
                    })?;
                Gateway::bootstrap(
                    &session,
                    &mac,
                    crate::cloudkit::CONTAINER,
                    crate::cloudkit::Scope::Private,
                )
                .await?
            }
            Err(error) => return Err(error),
        };

        let mut tlkshares = Vec::new();
        let mut synckeys = Vec::new();
        let mut items = Vec::new();

        let mut peers = vec![peer_state.id.clone()];
        if let Some(sponsor) = &peer_state.sponsor_id {
            peers.push(sponsor.clone());
        }
        for peer in peers {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!("sync: tlk shares for {peer}");
            }
            match octagon::tlk_shares(&gateway, &peer).await {
                Ok(response) => {
                    let (mut shares, mut keys) = ckks::shares_from_response(&response)?;
                    tlkshares.append(&mut shares);
                    synckeys.append(&mut keys);
                }
                Err(error) => {
                    if std::env::var_os("APW_DEBUG").is_some() {
                        eprintln!("sync: tlk shares for {peer} failed: {error}");
                    }
                }
            }
        }

        for zone in ["Passwords", "Manatee"] {
            let mut token: Option<Vec<u8>> = None;
            loop {
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("sync: zone {zone} token {:?}", token.as_ref().map(Vec::len));
                }
                let page = match gateway.record_sync(zone, None, token.as_deref()).await {
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
        Ok::<_, Error>((tlkshares, synckeys, items, session))
    })?;
    snapshot.session = Some(session.clone());

    if std::env::var_os("APW_DEBUG").is_some() {
        let receivers: Vec<&str> = tlkshares
            .iter()
            .filter_map(|record| record.text("receiver"))
            .collect();
        eprintln!(
            "sync: peer {} receivers {:?}",
            peer_state.id,
            &receivers[..receivers.len().min(4)]
        );
        if let Some(record) = tlkshares.first() {
            eprintln!(
                "sync: tlkshare fields {:?}",
                record.fields.keys().collect::<Vec<_>>()
            );
        }
        let mine = tlkshares
            .iter()
            .filter(|record| record.text("receiver") == Some(peer_state.id.as_str()))
            .count();
        let sponsor = peer_state
            .sponsor_id
            .as_deref()
            .map(|id| {
                tlkshares
                    .iter()
                    .filter(|record| record.text("receiver") == Some(id))
                    .count()
            })
            .unwrap_or(0);
        eprintln!("sync: shares for me {mine}, sponsor {sponsor}");
    }
    let mut tlks = ckks::unwrap_tlkshares(&tlkshares, &peer_state.id, &encryption.encryption);
    if let (Some(sponsor_id), Some(sponsor_key)) =
        (&peer_state.sponsor_id, &peer_state.sponsor_encryption_key)
    {
        if let Ok(sponsor) =
            PeerKeys::from_x963(&decode(&peer_state.signing_key)?, &decode(sponsor_key)?)
        {
            tlks.extend(ckks::unwrap_tlkshares(
                &tlkshares,
                sponsor_id,
                &sponsor.encryption,
            ));
        }
    }
    let class_keys = ckks::unwrap_class_keys(&synckeys, &tlks);
    let decrypted = ckks::decrypt_items(&items, &class_keys);
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "sync: {} tlk shares, {} synckeys, {} items, {} tlks, {} class keys, {} decrypted",
            tlkshares.len(),
            synckeys.len(),
            items.len(),
            tlks.len(),
            class_keys.len(),
            decrypted.len()
        );
    }
    if std::env::var_os("APW_DEBUG").is_some() {
        let mut groups: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        for (_, value) in &decrypted {
            let Some(dict) = value.as_dictionary() else {
                continue;
            };
            let agrp = dict
                .get("agrp")
                .and_then(|value| value.as_string())
                .unwrap_or("<none>")
                .to_string();
            let metadata = dict
                .get("v_Data")
                .and_then(|value| value.as_data())
                .is_some_and(|bytes| bytes.starts_with(b"bplist00"));
            let slot = groups.entry(agrp).or_default();
            if metadata {
                slot.0 += 1;
            } else {
                slot.1 += 1;
            }
        }
        for (agrp, (metadata, data)) in groups {
            eprintln!("sync: agrp {agrp}: metadata {metadata}, data {data}");
        }
    }

    if std::env::var_os("APW_DEBUG").is_some() {
        dump_items(&decrypted);
    }
    let service_keys = service_keys(&decrypted);
    let mut group_data = Vec::new();
    if !service_keys.is_empty() {
        let read = block_on(async {
            let mac = Anisette::new(&anisette_url)
                .identity_for(Some("macos"))
                .await?;
            let mut out = Vec::new();
            for scope in [
                crate::cloudkit::Scope::Private,
                crate::cloudkit::Scope::Shared,
            ] {
                let gateway = match Gateway::bootstrap(
                    &session,
                    &mac,
                    crate::cloudkit::SHARED_CONTAINER,
                    scope,
                )
                .await
                {
                    Ok(gateway) => gateway,
                    Err(error) => {
                        if std::env::var_os("APW_DEBUG").is_some() {
                            eprintln!("sync: group container {scope:?} failed: {error}");
                        }
                        continue;
                    }
                };
                match crate::groups::read_all(&gateway, &service_keys).await {
                    Ok(mut groups) => out.append(&mut groups),
                    Err(error) => {
                        if std::env::var_os("APW_DEBUG").is_some() {
                            eprintln!("sync: group read {scope:?} failed: {error}");
                        }
                    }
                }
            }
            Ok::<_, Error>(out)
        })?;
        group_data = read;
    }

    let mut logins: Vec<Entry> = Vec::new();
    let mut sidecars: Vec<Entry> = Vec::new();
    let mut passkeys: Vec<Entry> = Vec::new();

    for (id, value) in &decrypted {
        let Some(entry) = ckks::entry_from_plist(id, value) else {
            continue;
        };
        let agrp = entry.agrp.clone().unwrap_or_default();
        // Tombstones and key material are not user items.
        if agrp.ends_with("-recently-deleted")
            || agrp.starts_with("com.apple.ProtectedCloudStorage")
        {
            continue;
        }
        if agrp == "com.apple.password-manager.website-metadata" {
            continue;
        }
        if agrp == "com.apple.password-manager" {
            sidecars.push(entry);
            continue;
        }
        if entry.kind == EntryKind::Passkey {
            // The Apple ID credential is system-managed and does not appear in
            // the app's Passkeys list.
            if entry.title.as_deref() == Some("apple.com") {
                continue;
            }
            passkeys.push(entry);
            continue;
        }
        logins.push(entry);
    }

    let unmatched = crate::model::merge_sidecars(&mut logins, sidecars);
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!("sync: {} sidecars without a login", unmatched.len());
        for entry in unmatched.iter().take(12) {
            eprintln!(
                "sync: unmatched id={} domain={} title={:?} notes={}",
                entry.id,
                entry.domain(),
                entry.title,
                entry.notes.as_ref().map(String::len).unwrap_or(0)
            );
        }
    }

    // A `com.apple.cfnetwork` record with no secret is a note, a card, or an
    // associated-domain stub; its title comes from the sidecar that was just
    // merged. Reclassify so `pw list` keeps showing credentials only.
    for entry in &mut logins {
        let empty = entry
            .password
            .as_deref()
            .is_none_or(|password| password.is_empty())
            && is_uuid(&entry.domain());
        if !empty {
            continue;
        }
        let title = entry.title.clone().unwrap_or_default();
        entry.kind = if title.starts_with("Secure Note") || title == "Password" {
            EntryKind::Note
        } else if title.starts_with("Credit") || title.starts_with("Debit") {
            EntryKind::Card
        } else {
            EntryKind::Login
        };
        if !title.is_empty() && is_uuid(&entry.domain()) {
            entry.sites = vec![title.clone()];
            entry.url = None;
        }
    }

    // Sidecars whose domain has no cfnetwork record at all describe credentials
    // that exist only in the metadata store. Keep them visible without a secret.
    let domains: std::collections::HashSet<String> = logins
        .iter()
        .map(|entry| entry.domain().to_lowercase())
        .collect();
    for sidecar in unmatched {
        let domain = sidecar.domain();
        if domain.is_empty() || is_uuid(&domain) || domains.contains(&domain.to_lowercase()) {
            continue;
        }
        let mut entry = sidecar;
        entry.password = None;
        entry.kind = EntryKind::Login;
        entry.url = Some(format!("https://{domain}"));
        entry.sites = vec![domain];
        logins.push(entry);
    }

    for data in &group_data {
        for entry in &data.entries {
            let duplicate = logins.iter().any(|personal| {
                personal.domain().eq_ignore_ascii_case(&entry.domain())
                    && personal.username == entry.username
                    && personal.password == entry.password
            });
            if !duplicate {
                logins.push(entry.clone());
            }
        }
    }

    logins.sort_by(|left, right| left.id.cmp(&right.id));
    passkeys.sort_by(|left, right| left.id.cmp(&right.id));
    logins.append(&mut passkeys);

    snapshot.entries = logins;
    snapshot.groups = group_data.into_iter().map(|data| data.group).collect();
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

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.chars().enumerate().all(|(index, ch)| match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit(),
        })
}

fn finish(paths: &Paths, snapshot: &crate::model::Vault, json: bool, note: &str) -> Result<()> {
    let state = State {
        last_sync: snapshot.generated_at,
        last_status: Some("ok".into()),
        account: snapshot.account.clone(),
        source: Some(snapshot.source.to_string()),
        entries: snapshot.item_count() as u32,
        logins: snapshot.login_count() as u32,
        passkeys: snapshot.passkey_count() as u32,
        groups: snapshot.groups.len() as u32,
        shared_entries: snapshot
            .entries
            .iter()
            .filter(|entry| entry.group.is_some())
            .count() as u32,
        failures: 0,
        next_attempt: None,
    };
    config::save_state(paths, &state)?;

    let result = serde_json::json!({
        "source": snapshot.source.to_string(),
        "account": snapshot.account,
        "entries": snapshot.item_count(),
        "logins": snapshot.login_count(),
        "passkeys": snapshot.passkey_count(),
        "groups": snapshot.groups.len(),
        "snapshot": paths.snapshot_file,
    });

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([result])));
    } else {
        println!("synced {} logins from {note}", snapshot.login_count());
    }
    Ok(())
}

/// The PCS service keys are ordinary Manatee items; collect every candidate and
/// let the protection match the right one.
fn service_keys(decrypted: &[(String, plist::Value)]) -> Vec<ServiceKey> {
    let mut out = Vec::new();
    for (_, value) in decrypted {
        let Some(dict) = value.as_dictionary() else {
            continue;
        };
        let agrp = dict.get("agrp").and_then(|value| value.as_string());
        if agrp != Some("com.apple.ProtectedCloudStorage") {
            continue;
        }
        let vwht = dict.get("vwht").and_then(|value| value.as_string());
        if vwht != Some("Manatee") {
            continue;
        }
        let Some(body) = dict.get("v_Data").and_then(|value| value.as_data()) else {
            continue;
        };
        if let Ok(key) = ServiceKey::parse_der(body) {
            out.push(key);
        }
    }
    out
}

/// Debug helper: write the decrypted record inventory for offline analysis.
fn dump_items(decrypted: &[(String, plist::Value)]) {
    let mut out = Vec::new();
    for (id, value) in decrypted {
        let Some(dict) = value.as_dictionary() else {
            continue;
        };
        let text = |key: &str| {
            dict.get(key)
                .and_then(|value| value.as_string())
                .map(str::to_string)
        };
        let meta = dict
            .get("v_Data")
            .and_then(|value| value.as_data())
            .filter(|bytes| bytes.starts_with(b"bplist00"))
            .and_then(|bytes| plist::from_bytes::<plist::Value>(bytes).ok())
            .and_then(|value| serde_json::to_value(value).ok());
        let data = dict.get("v_Data").and_then(|value| value.as_data());
        out.push(serde_json::json!({
            "id": id,
            "data_len": data.map(|bytes| bytes.len()),
            "data": data.map(|bytes| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(bytes)
            }),
            "data_sha": data.map(|bytes| {
                use sha2::{Digest, Sha256};
                data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))
            }),
            "agrp": text("agrp"),
            "srvr": text("srvr"),
            "acct": text("acct"),
            "labl": text("labl"),
            "type": dict.get("type"),
            "meta": meta,
        }));
    }
    let _ = std::fs::write(
        "/tmp/opencode/apw-items.json",
        serde_json::to_vec_pretty(&out).unwrap_or_default(),
    );
}

fn decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Message(format!("invalid stored peer key: {error}")))
}
