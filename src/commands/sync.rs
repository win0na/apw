use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;

use crate::auth::anisette::Anisette;
use crate::ckks;
use crate::cloudkit::Gateway;
use crate::commands::join::block_on;
use crate::config::{self, Config, Paths, State};
use crate::error::{Error, Result};
use crate::model::{Entry, EntryKind, OpKind, RecordMeta, Source};
use crate::octagon::{self, keys::PeerKeys};
use crate::output;
use crate::pcs::ServiceKey;
use crate::push;
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
                // A pending queue is work the floor must not starve: allow the
                // run so a queued write can be pushed.
                let has_pending = vault::load(paths, config)
                    .map(|vault| !vault.pending.is_empty())
                    .unwrap_or(false);
                if !has_pending {
                    return Err(Error::Message(format!(
                        "last sync was {elapsed}s ago; the floor is {}s (use --force)",
                        config.sync.min_interval_seconds
                    )));
                }
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
        None => sync_live(paths, config, json, true),
    }
}

fn sync_fixture(paths: &Paths, config: &mut Config, fixture: &Path, json: bool) -> Result<()> {
    let mut snapshot = vault::fixture::read(fixture)?;
    // A fixture has no session or peer. Keep the ones a live snapshot already
    // holds so testing does not orphan the trust peer. Pending edits and the
    // synckey names are live state that only a zone read replaces.
    if paths.snapshot_file.exists() {
        let existing = vault::load(paths, config)?;
        if snapshot.session.is_none() {
            snapshot.session = existing.session;
        }
        if snapshot.peer.is_none() {
            snapshot.peer = existing.peer;
        }
        snapshot.pending = existing.pending;
        snapshot.synckeys = existing.synckeys;
    }
    snapshot.account = config.account.clone().or(snapshot.account);
    snapshot.generated_at = Some(chrono::Utc::now());
    if paths.snapshot_file.exists() {
        let _ = std::fs::copy(
            &paths.snapshot_file,
            paths.snapshot_file.with_extension("bin.prev"),
        );
    }
    vault::save(paths, config, &snapshot)?;
    finish(
        paths,
        &snapshot,
        json,
        &format!("fixture {}", fixture.display()),
        false,
        true,
    )
}

/// Sync without printing. `login` calls this so one command produces one
/// envelope.
pub fn run_silent(paths: &Paths, config: &mut Config) -> Result<()> {
    sync_live(paths, config, false, false)
}

fn sync_live(paths: &Paths, config: &mut Config, json: bool, emit: bool) -> Result<()> {
    if !paths.snapshot_file.exists() {
        return Err(Error::Auth("run `apw login` first".into()));
    }
    let mut snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let peer_state = snapshot
        .peer
        .clone()
        .ok_or_else(|| Error::Auth("run `apw join` first".into()))?;
    let anisette_url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let encryption = PeerKeys::from_x963(
        &decode(&peer_state.signing_key)?,
        &decode(&peer_state.encryption_key)?,
    )?;

    let (
        tlkshares,
        synckeys,
        items,
        zone_of,
        wifi_records,
        sync_keys,
        zones_read,
        session,
        gateway,
    ) = block_on(async {
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
        let mut zone_of: BTreeMap<String, String> = BTreeMap::new();
        let mut sync_keys: BTreeMap<String, String> = BTreeMap::new();
        let mut zones_read = false;

        let mut peers = vec![peer_state.id.clone()];
        if let Some(sponsor) = &peer_state.sponsor_id {
            peers.push(sponsor.clone());
        }
        for peer in peers {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!("sync: tlk shares for {peer}");
            }
            let response = octagon::tlk_shares(&gateway, &peer)
                .await
                .map_err(|error| Error::Message(format!("TLK shares for {peer}: {error}")))?;
            let (mut shares, mut keys) = ckks::shares_from_response(&response)?;
            tlkshares.append(&mut shares);
            synckeys.append(&mut keys);
        }
        if tlkshares.is_empty() {
            return Err(Error::Message(
                "no TLK shares; keeping the previous snapshot".into(),
            ));
        }

        let mut wifi_records = Vec::new();
        for zone in ["Passwords", "Manatee", "WiFi"] {
            let mut token: Option<Vec<u8>> = None;
            let mut pages = 0usize;
            loop {
                pages += 1;
                if pages > 100 {
                    return Err(Error::Message(format!("zone {zone} did not finish paging")));
                }
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("sync: zone {zone} token {:?}", token.as_ref().map(Vec::len));
                }
                let page = match gateway.record_sync(zone, None, token.as_deref()).await {
                    Ok(page) => page,
                    Err(error) => {
                        let text = error.to_string().to_lowercase();
                        // A missing zone is normal (Wi-Fi is absent on some
                        // accounts); anything else is a failed sync.
                        if text.contains("does not exist") || text.contains("zonenotfound") {
                            break;
                        }
                        return Err(error);
                    }
                };
                for record in page.records {
                    match record.record_type.as_str() {
                        "tlkshare" => tlkshares.push(record),
                        "synckey" => {
                            if let Some(class) = record.text("class") {
                                sync_keys.insert(format!("{zone}:{class}"), record.name.clone());
                            }
                            synckeys.push(record);
                        }
                        "item" if zone == "WiFi" => {
                            zone_of.insert(record.name.clone(), zone.to_string());
                            wifi_records.push(record);
                        }
                        "item" => {
                            zone_of.insert(record.name.clone(), zone.to_string());
                            items.push(record);
                        }
                        _ => {}
                    }
                }
                zones_read = true;
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
        Ok::<_, Error>((
            tlkshares,
            synckeys,
            items,
            zone_of,
            wifi_records,
            sync_keys,
            zones_read,
            session,
            gateway,
        ))
    })?;
    snapshot.session = Some(session.clone());
    // Only a zone read replaces the synckey names; an early failure keeps them.
    if zones_read {
        snapshot.synckeys = sync_keys;
    }

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
    let wifi_decrypted = ckks::decrypt_items(&wifi_records, &class_keys);
    // A partial decrypt must not silently shrink the snapshot. Structural skips
    // (`no_parent`, `no_data`, `no_wrapped`) are not data loss.
    let total = items.len() + wifi_records.len();
    let got = decrypted.values.len() + wifi_decrypted.values.len();
    let lost = decrypted.lost + wifi_decrypted.lost;
    let allow = std::env::var("APW_ALLOW_PARTIAL").ok().as_deref() == Some("1");
    if !allow {
        if total > 0 && got == 0 {
            return Err(Error::Message(
                "sync decrypted no items; refusing to write an empty snapshot (set APW_ALLOW_PARTIAL=1 to accept a partial sync)".into(),
            ));
        }
        // A first sync has no snapshot to protect; write what decrypted and
        // mark the run partial. Once entries exist, keep the previous vault.
        if lost > 0 && !snapshot.entries.is_empty() {
            return Err(Error::Message(format!(
                "sync could not decrypt {lost} item(s); keeping the previous snapshot (set APW_ALLOW_PARTIAL=1 to accept a partial sync)"
            )));
        }
    }
    if lost > 0 {
        eprintln!(
            "sync: accepted a partial sync; {lost} of {total} item(s) could not be decrypted"
        );
    } else if allow && total > 0 && got == 0 {
        eprintln!("sync: accepted an empty partial sync");
    }
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "sync: {} tlk shares, {} synckeys, {} items, {} tlks, {} class keys, {} decrypted",
            tlkshares.len(),
            synckeys.len(),
            items.len(),
            tlks.len(),
            class_keys.len(),
            decrypted.values.len()
        );
    }
    if std::env::var_os("APW_DEBUG").is_some() {
        let mut groups: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        for (_, value) in &decrypted.values {
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

    let service_keys = service_keys(&decrypted.values);
    let mut group_data = Vec::new();
    let mut group_warnings: Vec<String> = Vec::new();
    if !service_keys.is_empty() {
        let read = block_on(async {
            let mac = Anisette::new(&anisette_url)
                .identity_for(Some("macos"))
                .await?;
            let mut groups = Vec::new();
            let mut warnings = Vec::new();
            for scope in [
                crate::cloudkit::Scope::Private,
                crate::cloudkit::Scope::Shared,
            ] {
                let gateway = match Gateway::bootstrap_with_bundle(
                    &session,
                    &mac,
                    crate::cloudkit::SHARED_CONTAINER,
                    scope,
                    crate::cloudkit::BUNDLE_SHARING,
                )
                .await
                {
                    Ok(gateway) => gateway,
                    Err(error) => {
                        warnings.push(format!("group container {scope:?} unavailable: {error}"));
                        continue;
                    }
                };
                match crate::groups::read_all(&gateway, &service_keys).await {
                    Ok(mut read) => {
                        groups.append(&mut read.groups);
                        warnings.append(&mut read.warnings);
                    }
                    Err(error) => {
                        warnings.push(format!("group read {scope:?} failed: {error}"));
                    }
                }
            }
            Ok::<_, Error>((groups, warnings))
        })?;
        group_data = read.0;
        group_warnings = read.1;
    }
    // A zone that failed to bootstrap, a zone that failed to read, or an item
    // that failed to decrypt all mean the shared view is incomplete. Keep the
    // previous shared entries rather than deleting them.
    if service_keys.is_empty() && !snapshot.groups.is_empty() {
        group_warnings.push(
            "shared group keys were not available; keeping the previous shared entries".into(),
        );
    }
    let incomplete = !group_warnings.is_empty()
        || group_data.iter().any(|data| data.skipped > 0)
        || (service_keys.is_empty() && !snapshot.groups.is_empty());

    let mut logins: Vec<Entry> = Vec::new();
    let mut sidecars: Vec<Entry> = Vec::new();
    let mut passkeys: Vec<Entry> = Vec::new();

    for (id, value) in &decrypted.values {
        let Some(mut entry) = ckks::entry_from_plist(id, value) else {
            continue;
        };
        if let Some(info) = decrypted.records.get(id) {
            let zone = zone_of.get(id).map(String::as_str).unwrap_or_default();
            attach_record(&mut entry, info, zone, value);
        }
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
        classify_stub(entry);
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

    if incomplete {
        for warning in &group_warnings {
            eprintln!("sync: {warning}");
        }
        // Keep the shared entries the previous snapshot already had instead of
        // dropping the ones this run could not read.
        let previous: Vec<Entry> = snapshot
            .entries
            .iter()
            .filter(|entry| entry.group.is_some())
            .cloned()
            .collect();
        for entry in previous {
            let duplicate = logins.iter().any(|found| {
                found.group == entry.group
                    && found.domain().eq_ignore_ascii_case(&entry.domain())
                    && found.username == entry.username
                    && found.password == entry.password
            });
            if !duplicate {
                logins.push(entry);
            }
        }
    } else {
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
    }

    let mut wifi: Vec<Entry> = Vec::new();
    for (id, value) in &wifi_decrypted.values {
        let named = value
            .as_dictionary()
            .and_then(|dict| dict.get("acct"))
            .and_then(|value| value.as_string())
            .is_some_and(|acct| !acct.is_empty());
        if !named {
            continue;
        }
        let Some(mut entry) = ckks::entry_from_plist_kind(id, value, Some(EntryKind::Wifi)) else {
            continue;
        };
        if let Some(info) = wifi_decrypted.records.get(id) {
            attach_record(&mut entry, info, "WiFi", value);
        }
        wifi.push(entry);
    }
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "sync: {} wifi records, {} wifi entries",
            wifi_records.len(),
            wifi.len()
        );
    }

    // Merge the separately built lists first: a queued Wi-Fi or passkey write
    // must replace the fetched copy, not add beside it when the fetched copy
    // is appended later.
    logins.append(&mut passkeys);
    logins.append(&mut wifi);

    // A pending local write must win over the stale server copy the merge just
    // fetched. Overlay the pre-sync entries for queued Create/Edit ids and drop
    // the entries a queued Delete names.
    let deletes: std::collections::HashSet<&str> = snapshot
        .pending
        .iter()
        .filter(|op| op.kind == OpKind::Delete)
        .map(|op| op.item_name.as_str())
        .collect();
    let writes: std::collections::HashSet<&str> = snapshot
        .pending
        .iter()
        .filter(|op| matches!(op.kind, OpKind::Create | OpKind::Edit))
        .map(|op| op.item_name.as_str())
        .collect();
    let local_by_id: BTreeMap<&str, &Entry> = snapshot
        .entries
        .iter()
        .filter(|entry| writes.contains(entry.id.as_str()))
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    logins.retain(|entry| !deletes.contains(entry.id.as_str()));
    for (id, local) in &local_by_id {
        match logins.iter_mut().find(|entry| entry.id.as_str() == *id) {
            Some(slot) => *slot = (*local).clone(),
            None => logins.push((*local).clone()),
        }
    }

    logins.sort_by(|left, right| left.id.cmp(&right.id));
    if std::env::var_os("APW_DEBUG").is_some() {
        let with_record = logins.iter().filter(|entry| entry.record.is_some()).count();
        eprintln!(
            "sync: {with_record} entries carry record metadata, {} pending ops",
            snapshot.pending.len()
        );
    }

    // A failed TLK unwrap or a transient zone error yields an empty list. Do
    // not replace a good snapshot with it.
    if logins.is_empty() && !snapshot.entries.is_empty() {
        return Err(Error::Message(
            "sync returned no entries; keeping the previous snapshot".into(),
        ));
    }
    if paths.snapshot_file.exists() {
        let _ = std::fs::copy(
            &paths.snapshot_file,
            paths.snapshot_file.with_extension("bin.prev"),
        );
    }

    snapshot.entries = logins;
    if !incomplete {
        snapshot.groups = group_data.into_iter().map(|data| data.group).collect();
    }
    snapshot.source = Source::Icloud;
    snapshot.generated_at = Some(chrono::Utc::now());

    // Push local writes after the merge, so the vault that is saved holds both
    // the fetched view and the new server etags.
    if !snapshot.pending.is_empty() {
        let synckeys = snapshot.synckeys.clone();
        let env = push::PushEnv {
            gateway: &gateway,
            class_keys: &class_keys,
            synckeys: &synckeys,
        };
        let crate::model::Vault {
            ref mut entries,
            ref mut pending,
            ..
        } = snapshot;
        block_on(async {
            push::push_pending(entries, pending, &env).await;
            Ok::<(), Error>(())
        })?;
    }

    vault::save(paths, config, &snapshot)?;

    let note = format!(
        "iCloud ({} TLK shares, {} class keys)",
        tlks.len(),
        class_keys.len()
    );
    finish(paths, &snapshot, json, &note, incomplete || lost > 0, emit)
}

/// Copy the record addressing and payloads onto an entry so a later push can
/// re-seal and address the item. `zone` is the zone the record was read from.
fn attach_record(entry: &mut Entry, info: &ckks::RecordInfo, zone: &str, value: &plist::Value) {
    let mut record = RecordMeta {
        zone: info.zone.clone().unwrap_or_else(|| zone.to_string()),
        owner: info.owner.clone(),
        item_type: info.record_type.clone(),
        item_etag: info.etag.clone(),
        parent: info.parent.clone(),
        plist: Some(base64::engine::general_purpose::STANDARD.encode(&info.bplist)),
        ..RecordMeta::default()
    };
    // A password-manager metadata item is the sidecar for a login. Its own
    // record name and etag let a later edit rewrite the metadata, and the
    // decrypted metadata dictionary is what a push has to re-seal. The outer
    // sidecar plist is kept so an edit can preserve the keys Apple wrote.
    if entry.agrp.as_deref() == Some("com.apple.password-manager") {
        record.sidecar_name = Some(entry.id.clone());
        record.sidecar_type = Some(info.record_type.clone());
        record.sidecar_etag = info.etag.clone();
        record.metadata = ckks::metadata_bytes(value)
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes));
        record.sidecar_plist = Some(base64::engine::general_purpose::STANDARD.encode(&info.bplist));
    }
    entry.record = Some(record);
}

/// Classify a passwordless item whose site is a UUID: note, card, or stub.
///
/// Card titles win over note markers. A metadata `notes` value marks a note
/// even when its title is custom; a stub with neither stays a login (an
/// associated-domain record, for example).
fn classify_stub(entry: &mut Entry) {
    let empty = entry
        .password
        .as_deref()
        .is_none_or(|password| password.is_empty())
        && is_uuid(&entry.domain());
    if !empty {
        return;
    }
    let title = entry.title.clone().unwrap_or_default();
    entry.kind = if title.starts_with("Credit") || title.starts_with("Debit") {
        EntryKind::Card
    } else if title.starts_with("Secure Note") || title == "Password" || entry.notes.is_some() {
        EntryKind::Note
    } else {
        EntryKind::Login
    };
    if !title.is_empty() {
        entry.sites = vec![title];
        entry.url = None;
    }
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.chars().enumerate().all(|(index, ch)| match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit(),
        })
}

fn finish(
    paths: &Paths,
    snapshot: &crate::model::Vault,
    json: bool,
    note: &str,
    partial: bool,
    emit: bool,
) -> Result<()> {
    let state = State {
        last_sync: snapshot.generated_at,
        last_status: Some(if partial { "partial" } else { "ok" }.into()),
        account: snapshot.account.clone(),
        source: Some(snapshot.source.to_string()),
        entries: snapshot.item_count() as u32,
        logins: snapshot.login_count() as u32,
        passkeys: snapshot.passkey_count() as u32,
        wifi: snapshot.wifi_count() as u32,
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
        "wifi": snapshot.wifi_count(),
        "groups": snapshot.groups.len(),
        "snapshot": paths.snapshot_file,
        "partial": partial,
    });

    if emit {
        if output::use_json(json) {
            output::print_json(&output::success(result));
        } else {
            println!("synced {} logins from {note}", snapshot.login_count());
        }
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

fn decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Message(format!("invalid stored peer key: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE: &str = "6F1C2A4E-0B7D-4C3A-9E55-1234567890AB";

    fn stub(title: &str, notes: Option<&str>) -> Entry {
        Entry {
            id: "item-1".to_string(),
            kind: EntryKind::Login,
            title: Some(title.to_string()),
            notes: notes.map(str::to_string),
            sites: vec![SITE.to_string()],
            ..Entry::default()
        }
    }

    #[test]
    fn a_passwordless_uuid_item_with_notes_is_a_note() {
        let mut entry = stub("My custom title", Some("the body"));
        classify_stub(&mut entry);
        assert_eq!(entry.kind, EntryKind::Note);
        assert_eq!(entry.sites, vec!["My custom title".to_string()]);
        assert!(entry.url.is_none());
    }

    #[test]
    fn a_credit_title_with_notes_stays_a_card() {
        let mut entry = stub("Credit Card", Some("the body"));
        classify_stub(&mut entry);
        assert_eq!(entry.kind, EntryKind::Card);
    }

    #[test]
    fn a_secure_note_title_is_a_note_and_a_bare_stub_stays_a_login() {
        let mut note = stub("Secure Note", None);
        classify_stub(&mut note);
        assert_eq!(note.kind, EntryKind::Note);

        let mut associated = stub("example.com", None);
        associated.password = Some("secret".to_string());
        classify_stub(&mut associated);
        assert_eq!(associated.kind, EntryKind::Login);
        assert_eq!(associated.sites, vec![SITE.to_string()]);
    }
}
