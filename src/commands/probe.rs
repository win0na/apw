use crate::auth::anisette::Anisette;
use crate::commands::join::block_on;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::octagon::escrow::Escrow;
use crate::output;
use crate::vault;

/// Non-destructive escrow auth probe. GETRECORDS spends no attempt.
pub fn escrow(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let account = snapshot
        .account
        .clone()
        .or_else(|| config.account.clone())
        .ok_or_else(|| Error::Invalid("the snapshot has no account".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;
    let escrow_url = session
        .escrow_proxy_url
        .clone()
        .ok_or_else(|| Error::Message("the session has no escrow URL".into()))?;

    let records = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let escrow = Escrow::new(
            &escrow_url,
            &account,
            &session.dsid,
            &session.adsid,
            &session.pet,
            &session.mme_auth_token,
            &session.cloudkit_token,
            &identity,
        );
        escrow.list_records().await
    })?;

    if std::env::var_os("APW_DEBUG").is_some() {
        for (label, value) in &records {
            let keys: Vec<&str> = value
                .as_dictionary()
                .map(|dict| dict.keys().map(String::as_str).collect())
                .unwrap_or_default();
            eprintln!("record {label}: {keys:?}");
        }
    }

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([{
            "records": records.len(),
            "escrow": escrow_url,
        }])));
    } else {
        println!("escrow auth ok: {} records", records.len());
    }
    Ok(())
}

pub fn settings(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let services = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        crate::auth::icloud::account_settings(&identity, &session.dsid, &session.mme_auth_token)
            .await
    })?;

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([{
            "names": services.names,
            "escrow": services.escrow_proxy_url,
            "cloudkit_url": services.ckdatabasews_url,
            "has_cloudkit_token": services.cloudkit_token.is_some(),
        }])));
    } else {
        println!("services: {}", services.names.join(", "));
        println!("escrow: {:?}", services.escrow_proxy_url);
        println!("cloudkit token: {}", services.cloudkit_token.is_some());
    }
    Ok(())
}

pub fn zone(paths: &Paths, config: &mut Config, zone: &str, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let changes = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = crate::cloudkit::Gateway::bootstrap(
            &session,
            &mac,
            crate::cloudkit::CONTAINER,
            crate::cloudkit::Scope::Private,
        )
        .await?;
        let mut token: Option<Vec<u8>> = None;
        let mut total = 0usize;
        let mut pages = 0usize;
        loop {
            let page = gateway.record_sync(zone, None, token.as_deref()).await?;
            total += page.records.len();
            pages += 1;
            eprintln!(
                "page {pages}: {} records, status {}, token {:?}",
                page.records.len(),
                page.status,
                page.token.as_ref().map(Vec::len)
            );
            if page.status == 1 {
                match page.token {
                    Some(next) if Some(&next) != token.as_ref() => token = Some(next),
                    _ => break,
                }
            } else {
                break;
            }
            if pages >= 5 {
                break;
            }
        }
        Ok::<_, crate::error::Error>((total, pages))
    })?;
    let (total, pages) = changes;

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([{
            "zone": zone,
            "records": total,
            "pages": pages,
        }])));
    } else {
        println!("{zone}: {total} records over {pages} pages");
    }
    Ok(())
}

/// Print the size of a zone's PCS protection blobs.
pub fn zoneinfo(paths: &Paths, config: &mut Config, zone: &str, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let container =
        std::env::var("APW_PROBE_CONTAINER").unwrap_or_else(|_| crate::cloudkit::CONTAINER.into());
    let bundle = std::env::var("APW_PROBE_BUNDLE")
        .unwrap_or_else(|_| crate::cloudkit::BUNDLE_RECORDS.into());
    let scope = match std::env::var("APW_PROBE_SCOPE").as_deref() {
        Ok("shared") => crate::cloudkit::Scope::Shared,
        _ => crate::cloudkit::Scope::Private,
    };
    let (info, owner) = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = crate::cloudkit::Gateway::bootstrap_with_bundle(
            &session, &mac, &container, scope, &bundle,
        )
        .await?;
        let page = gateway.zone_changes(None).await?;
        if std::env::var_os("APW_DEBUG").is_some() {
            let names: Vec<&str> = page
                .zones
                .iter()
                .map(|info| info.name.as_str())
                .take(20)
                .collect();
            eprintln!("zones: {} {:?}", page.zones.len(), names);
        }
        let found = page
            .zones
            .into_iter()
            .find(|info| info.name == zone)
            .ok_or_else(|| Error::NoResults(format!("no zone named {zone}")))?;
        let info = gateway.zone_retrieve(zone, &found.owner).await?;
        Ok::<_, Error>((info, found.owner))
    })?;

    // APW_DUMP_PROTECTIONS writes the raw PCS blobs for the protection codec.
    if std::env::var_os("APW_DUMP_PROTECTIONS").is_some() {
        let dir = std::path::Path::new("/tmp/opencode/apw-p1");
        std::fs::create_dir_all(dir)?;
        for (name, blob) in [
            ("zone", info.protection_info.as_deref()),
            ("record", info.record_protection_info.as_deref()),
        ] {
            if let Some(bytes) = blob {
                let path = dir.join(format!("{}-{name}.bin", info.name));
                std::fs::write(&path, bytes)?;
                eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());
            }
        }
    }

    let row = serde_json::json!({
        "zone": info.name,
        "owner": owner,
        "protection_info": info.protection_info.as_ref().map(Vec::len),
        "record_protection_info": info.record_protection_info.as_ref().map(Vec::len),
    });
    if output::use_json(json) {
        output::print_json(&output::success(row));
    } else {
        println!("{}", serde_json::to_string_pretty(&row).unwrap_or_default());
    }
    Ok(())
}

pub fn tlks(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let peer = snapshot
        .peer
        .clone()
        .ok_or_else(|| Error::Auth("run `apw join` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let results = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = crate::cloudkit::Gateway::bootstrap(
            &session,
            &mac,
            crate::cloudkit::CONTAINER,
            crate::cloudkit::Scope::Private,
        )
        .await?;
        let mut out = Vec::new();
        for name in [
            "fetchRecoverableTlkshares",
            "fetchRecoverableTLKShares",
            "fetchRecoverableTlkShares",
        ] {
            let mut request = crate::wire::Writer::new();
            request.string(1, &peer.id);
            match gateway.invoke(name, request.as_slice()).await {
                Ok(result) => out.push(serde_json::json!({"name": name, "bytes": result.len()})),
                Err(error) => {
                    out.push(serde_json::json!({"name": name, "error": error.to_string()}))
                }
            }
        }
        Ok::<_, crate::error::Error>(out)
    })?;

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([results])));
    } else {
        for result in results {
            println!("{result}");
        }
    }
    Ok(())
}

/// Count what the snapshot actually holds, split by access group.
pub fn stats(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let mut groups: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for entry in &snapshot.entries {
        let agrp = entry.agrp.clone().unwrap_or_else(|| "<none>".into());
        *groups.entry(agrp).or_default() += 1;
    }

    let mut unique: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    let mut duplicates = 0usize;
    for entry in snapshot
        .entries
        .iter()
        .filter(|entry| entry.kind == crate::model::EntryKind::Login)
    {
        let key = (
            entry.domain().to_lowercase(),
            entry.username.clone().unwrap_or_default().to_lowercase(),
        );
        if !unique.insert(key) {
            duplicates += 1;
        }
    }

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([{
            "total": snapshot.entries.len(),
            "logins": snapshot.login_count(),
            "passkeys": snapshot.passkey_count(),
            "groups": groups,
            "unique_logins": unique.len(),
            "duplicate_rows": duplicates,
        }])));
    } else {
        println!("total entries: {}", snapshot.entries.len());
        println!("logins: {}", snapshot.login_count());
        println!("passkeys: {}", snapshot.passkey_count());
        for (agrp, count) in &groups {
            println!("  {agrp}: {count}");
        }
        println!("unique logins: {}", unique.len());
        println!("duplicate rows: {duplicates}");
    }
    Ok(())
}

/// List zones in both database scopes. Read-only; no records are fetched.
pub fn zones(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let zones = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let mut out = Vec::new();
        for scope in [
            crate::cloudkit::Scope::Private,
            crate::cloudkit::Scope::Shared,
        ] {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!("probe: bootstrap {scope:?}");
            }
            let gateway = match crate::cloudkit::Gateway::bootstrap(
                &session,
                &mac,
                crate::cloudkit::SHARED_CONTAINER,
                scope,
            )
            .await
            {
                Ok(gateway) => gateway,
                Err(error) => {
                    eprintln!("probe: {scope:?} bootstrap failed: {error}");
                    continue;
                }
            };
            let mut token: Option<Vec<u8>> = None;
            let mut pages = 0;
            loop {
                let page = match gateway.zone_changes(token.as_deref()).await {
                    Ok(page) => page,
                    Err(error) => {
                        eprintln!("probe: {scope:?} zone sync failed: {error}");
                        break;
                    }
                };
                pages += 1;
                for zone in page.zones {
                    out.push(serde_json::json!({
                        "scope": format!("{scope:?}"),
                        "name": zone.name,
                        "owner": zone.owner,
                        "change": zone.change_type,
                    }));
                }
                if page.status == 2 {
                    break;
                }
                match page.token {
                    Some(next) if Some(&next) != token.as_ref() => token = Some(next),
                    _ => break,
                }
                if pages >= 5 {
                    break;
                }
            }
        }
        Ok::<_, crate::error::Error>(out)
    })?;

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([{ "zones": zones }])));
    } else {
        for zone in &zones {
            println!(
                "{} {} owner={} change={}",
                zone["scope"].as_str().unwrap_or("?"),
                zone["name"].as_str().unwrap_or("?"),
                zone["owner"].as_str().unwrap_or("?"),
                zone["change"]
            );
        }
    }
    Ok(())
}

/// Inspect one group zone: protection blobs and record inventory.
pub fn group(paths: &Paths, config: &mut Config, zone: &str, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let report = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = crate::cloudkit::Gateway::bootstrap_with_bundle(
            &session,
            &mac,
            crate::cloudkit::SHARED_CONTAINER,
            crate::cloudkit::Scope::Private,
            crate::cloudkit::BUNDLE_SHARING,
        )
        .await?;
        let owner = gateway.user_id().to_string();
        let zone_info = gateway.zone_retrieve(zone, &owner).await?;

        let mut records = Vec::new();
        let mut token: Option<Vec<u8>> = None;
        let mut status = 0;
        let mut pages = 0;
        loop {
            let page = gateway
                .record_sync(zone, Some(&owner), token.as_deref())
                .await?;
            status = status.max(page.status);
            pages += 1;
            records.extend(
                page.records
                    .iter()
                    .map(|record| format!("{}/{}", record.name, record.record_type)),
            );
            if std::env::var_os("APW_DUMP_PROTECTIONS").is_some() {
                let dir = std::path::Path::new("/tmp/opencode/apw-p1");
                std::fs::create_dir_all(dir)?;
                for record in &page.records {
                    if std::env::var_os("APW_DEBUG").is_some() {
                        let fields: Vec<(&str, &str)> = record
                            .fields
                            .iter()
                            .map(|(name, value)| {
                                let kind = match value {
                                    crate::cloudkit::FieldValue::Bytes(_) => "bytes",
                                    crate::cloudkit::FieldValue::Text(_) => "text",
                                    crate::cloudkit::FieldValue::Int(_) => "int",
                                    crate::cloudkit::FieldValue::Double(_) => "double",
                                    crate::cloudkit::FieldValue::Date(_) => "date",
                                    crate::cloudkit::FieldValue::Reference(_) => "reference",
                                };
                                (name.as_str(), kind)
                            })
                            .collect();
                        eprintln!("record {} fields: {fields:?}", record.name);
                    }
                    for (field, value) in &record.fields {
                        let bytes = match value {
                            crate::cloudkit::FieldValue::Bytes(bytes) => Some(bytes.clone()),
                            crate::cloudkit::FieldValue::Text(text) => {
                                Some(text.as_bytes().to_vec())
                            }
                            crate::cloudkit::FieldValue::Int(number) => {
                                Some(number.to_be_bytes().to_vec())
                            }
                            _ => None,
                        };
                        if let Some(bytes) = bytes {
                            let name = format!("{}-{}-{field}.bin", zone, record.name);
                            std::fs::write(dir.join(&name), &bytes)?;
                            eprintln!("wrote {name} ({} bytes)", bytes.len());
                        }
                    }
                }
            }
            if page.status != 1 || pages >= 5 {
                break;
            }
            match page.token {
                Some(next) if Some(&next) != token.as_ref() => token = Some(next),
                _ => break,
            }
        }
        Ok::<_, crate::error::Error>(serde_json::json!({
            "zone": zone_info.name,
            "owner": zone_info.owner,
            "protection_bytes": zone_info.protection_info.as_ref().map(Vec::len),
            "record_protection_bytes": zone_info.record_protection_info.as_ref().map(Vec::len),
            "pages": pages,
            "status": status,
            "records": records,
        }))
    })?;

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([report])));
    } else {
        println!("{report}");
    }
    Ok(())
}

/// Re-fetch the service map and `cloudKitToken`, then persist the session.
pub fn refresh(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let mut snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let refreshed = crate::auth::refresh_services(config, &session)?;
    snapshot.session = Some(refreshed.clone());
    vault::save(paths, config, &snapshot)?;

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([{
            "dsid": refreshed.dsid,
            "cloudkit_len": refreshed.cloudkit_token.len(),
            "cloudkit_url": refreshed.ckdatabasews_url,
            "escrow_url": refreshed.escrow_proxy_url,
        }])));
    } else {
        println!("services refreshed for dsid {}", refreshed.dsid);
    }
    Ok(())
}

/// Print the key structure of stored item plists without values. Notes and
/// cards keep their text in `v_Data`, so only types and lengths are shown.
pub fn structure(
    paths: &Paths,
    config: &mut Config,
    kind: Option<&str>,
    limit: usize,
    json: bool,
) -> Result<()> {
    use base64::Engine;

    let wanted = match kind.map(str::to_lowercase).as_deref() {
        None => None,
        Some("login") => Some(crate::model::EntryKind::Login),
        Some("note") => Some(crate::model::EntryKind::Note),
        Some("card") => Some(crate::model::EntryKind::Card),
        Some("wifi") => Some(crate::model::EntryKind::Wifi),
        Some("passkey") => Some(crate::model::EntryKind::Passkey),
        Some(other) => {
            return Err(Error::Invalid(format!(
                "unknown kind {other}; use login, note, card, wifi or passkey"
            )))
        }
    };

    let snapshot = vault::load(paths, config)?;
    let mut rows = Vec::new();
    for entry in &snapshot.entries {
        if wanted.is_some_and(|kind| entry.kind != kind) {
            continue;
        }
        let Some(record) = &entry.record else {
            continue;
        };
        let Some(plist) = record.plist.as_deref() else {
            continue;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(plist) else {
            continue;
        };
        let Ok(value) = plist::from_bytes::<plist::Value>(&bytes) else {
            continue;
        };
        rows.push(serde_json::json!({
            "id": entry.id,
            "kind": format!("{:?}", entry.kind).to_lowercase(),
            "record_type": record.item_type,
            "entry_agrp": entry.agrp,
            "entry_title": entry.title,
            "entry_kind": format!("{:?}", entry.kind),
            "notes_len": entry.notes.as_ref().map(String::len),
            "metadata": record.metadata.as_deref().and_then(|encoded| {
                let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
                let value = plist::from_bytes::<plist::Value>(&bytes).ok()?;
                Some(describe_plist(&value))
            }),
            "keys": describe_plist(&value),
        }));
        if rows.len() >= limit {
            break;
        }
    }

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::Value::Array(rows)));
    } else if rows.is_empty() {
        println!("no stored {} records with a plist", kind.unwrap_or("item"));
    } else {
        for row in &rows {
            println!(
                "{} {} {}",
                row["id"].as_str().unwrap_or(""),
                row["kind"].as_str().unwrap_or(""),
                row["record_type"].as_str().unwrap_or("")
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&row["keys"]).unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn describe_plist(value: &plist::Value) -> serde_json::Value {
    use plist::Value;
    match value {
        Value::String(text) if text.len() <= 80 => {
            serde_json::json!(format!("string[{}]={text}", text.len()))
        }
        Value::String(text) => serde_json::json!(format!("string[{}]", text.len())),
        Value::Data(bytes) => serde_json::json!(format!("data[{}]", bytes.len())),
        Value::Integer(number) => serde_json::json!(format!("int({number})")),
        Value::Real(number) => serde_json::json!(format!("real({number})")),
        Value::Boolean(flag) => serde_json::json!(format!("bool({flag})")),
        Value::Date(date) => serde_json::json!(format!("date({})", date.to_xml_format())),
        Value::Array(items) => serde_json::json!({
            "array": items.len(),
            "first": items.first().map(describe_plist),
        }),
        Value::Dictionary(dict) => {
            let mut map = serde_json::Map::new();
            for (key, value) in dict {
                let described = match (key.as_str(), value) {
                    ("sha1", plist::Value::Data(bytes)) => {
                        serde_json::json!(format!("sha1[{}]", hex(bytes)))
                    }
                    _ => describe_plist(value),
                };
                map.insert(key.clone(), described);
            }
            serde_json::Value::Object(map)
        }
        _ => serde_json::json!("uid"),
    }
}

/// Print one record's fields as stored on the server. Text is shown; bytes are
/// shown as length only, which is enough to compare a written item with one
/// Apple wrote.
pub fn record(
    paths: &Paths,
    config: &mut Config,
    zone: &str,
    name: &str,
    json: bool,
) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let record = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = crate::cloudkit::Gateway::bootstrap(
            &session,
            &mac,
            crate::cloudkit::CONTAINER,
            crate::cloudkit::Scope::Private,
        )
        .await?;
        let (record, matched) = gateway.retrieve_record(zone, None, name, None).await?;
        Ok::<_, Error>((record, matched))
    })?;
    let (record, matched) = record;

    let fields: serde_json::Map<String, serde_json::Value> = record
        .fields
        .iter()
        .map(|(key, value)| {
            let described = match value {
                crate::cloudkit::FieldValue::Text(text) if text.len() <= 60 => {
                    serde_json::json!(format!("text={text}"))
                }
                crate::cloudkit::FieldValue::Text(text) => {
                    serde_json::json!(format!("text[{}]", text.len()))
                }
                crate::cloudkit::FieldValue::Bytes(bytes) => {
                    serde_json::json!(format!("bytes[{}]", bytes.len()))
                }
                crate::cloudkit::FieldValue::Int(number) => {
                    serde_json::json!(format!("int={number}"))
                }
                crate::cloudkit::FieldValue::Double(number) => {
                    serde_json::json!(format!("double={number}"))
                }
                crate::cloudkit::FieldValue::Date(date) => {
                    serde_json::json!(format!("date={date:?}"))
                }
                crate::cloudkit::FieldValue::Reference(target) => {
                    serde_json::json!(format!("ref={target}"))
                }
            };
            (key.clone(), described)
        })
        .collect();

    let body = serde_json::json!([{
        "name": record.name,
        "type": record.record_type,
        "etag": record.etag,
        "zone": record.zone,
        "owner": record.owner,
        "etag_match": matched,
        "protection_info": record.protection_info.as_ref().map(Vec::len),
        "pcs_key": record.pcs_key.as_ref().map(Vec::len),
        "share_info": record.share_info.is_some(),
        "fields": fields,
    }]);
    if output::use_json(json) {
        output::print_json(&output::success(body));
    } else {
        println!(
            "{} {} etag={:?}",
            record.name, record.record_type, record.etag
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&body[0]["fields"]).unwrap_or_default()
        );
    }
    Ok(())
}
