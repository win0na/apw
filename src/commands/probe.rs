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
        .ok_or_else(|| Error::Invalid("run `apw login` first".into()))?;
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
        .ok_or_else(|| Error::Invalid("run `apw login` first".into()))?;
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
        .ok_or_else(|| Error::Invalid("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let changes = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = crate::cloudkit::Gateway::bootstrap(&session, &mac).await?;
        let mut token: Option<Vec<u8>> = None;
        let mut total = 0usize;
        let mut pages = 0usize;
        loop {
            let page = gateway.record_sync(zone, token.as_deref()).await?;
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

pub fn tlks(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Invalid("run `apw login` first".into()))?;
    let peer = snapshot
        .peer
        .clone()
        .ok_or_else(|| Error::Invalid("run `apw join` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let results = block_on(async {
        let identity = Anisette::new(&url).identity().await?;
        let mac = Anisette::new(&url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = crate::cloudkit::Gateway::bootstrap(&session, &mac).await?;
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
