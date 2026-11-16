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
