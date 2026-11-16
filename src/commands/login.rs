use crate::config::{self, Config, Paths};
use crate::error::{Error, Result};
use crate::model::Vault;
use crate::output;
use crate::vault;

#[allow(clippy::too_many_arguments)]
pub fn run(
    paths: &Paths,
    config: &mut Config,
    anisette_url: Option<String>,
    account: Option<String>,
    refresh: bool,
    join: bool,
    code: Option<String>,
    json: bool,
) -> Result<()> {
    if let Some(url) = anisette_url {
        config.anisette_url = Some(url);
    }
    if let Some(account) = account {
        config.account = Some(account);
    }

    if config.anisette_url().is_none() {
        return Err(Error::Invalid(
            "set --anisette-url or APW_ANISETTE_URL".into(),
        ));
    }

    let account = config
        .account
        .clone()
        .ok_or_else(|| Error::Invalid("set --account or an account in the config".into()))?;

    config.save(paths)?;

    if refresh {
        return refresh_services(paths, config, &account, json);
    }

    let mut snapshot = if paths.snapshot_file.exists() {
        vault::load(paths, config)?
    } else {
        Vault::default()
    };
    let previous = snapshot.session.clone();

    let mut session = crate::auth::login(config, &account, code)?;
    // A profile can return a reduced service map. Keep the URLs we already
    // discovered rather than dropping a working escrow or CloudKit endpoint.
    if let Some(previous) = previous {
        if session.escrow_proxy_url.is_none() {
            session.escrow_proxy_url = previous.escrow_proxy_url;
        }
        if session.ckdatabasews_url.is_none() {
            session.ckdatabasews_url = previous.ckdatabasews_url;
        }
    }
    snapshot.account = Some(account.clone());
    snapshot.session = Some(session.clone());
    vault::save(paths, config, &snapshot)?;

    let mut state = config::load_state(paths)?;
    state.account = Some(account.clone());
    state.source = Some("icloud".into());
    state.entries = snapshot.login_count() as u32;
    state.passkeys = snapshot.passkey_count() as u32;
    state.groups = snapshot.groups.len() as u32;
    state.last_status = Some("logged-in".into());
    state.failures = 0;
    config::save_state(paths, &state)?;

    if join {
        crate::commands::join::run(
            paths,
            config,
            std::env::var("APW_ESCROW_PASSCODE").ok(),
            json,
        )?;
        return Ok(());
    }

    let result = serde_json::json!({
        "account": account,
        "dsid": session.dsid,
        "adsid": session.adsid,
        "cloudkit": session.ckdatabasews_url,
        "escrow": session.escrow_proxy_url,
        "snapshot": paths.snapshot_file,
    });

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([result])));
    } else {
        println!("signed in as {account}");
        println!("run `apw join` to read the keychain");
        println!("snapshot {}", paths.snapshot_file.display());
    }
    Ok(())
}

fn refresh_services(paths: &Paths, config: &mut Config, account: &str, json: bool) -> Result<()> {
    let mut snapshot = vault::load(paths, config)?;
    let mut session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Invalid("run `apw login` first".into()))?;
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;

    let services = crate::commands::join::block_on(async {
        let identity = crate::auth::anisette::Anisette::new(&url)
            .identity()
            .await?;
        crate::auth::icloud::account_settings(&identity, &session.dsid, &session.mme_auth_token)
            .await
    })?;

    session.ckdatabasews_url = services.ckdatabasews_url.clone();
    session.escrow_proxy_url = services.escrow_proxy_url.clone();
    snapshot.session = Some(session.clone());
    vault::save(paths, config, &snapshot)?;

    let result = serde_json::json!({
        "account": account,
        "cloudkit": session.ckdatabasews_url,
        "escrow": session.escrow_proxy_url,
        "services": services.names,
    });
    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([result])));
    } else {
        println!("cloudkit {}", session.ckdatabasews_url.unwrap_or_default());
        println!("escrow {}", session.escrow_proxy_url.unwrap_or_default());
    }
    Ok(())
}
