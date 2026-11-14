use crate::config::{self, Config, Paths};
use crate::error::{Error, Result};
use crate::model::Vault;
use crate::output;
use crate::vault;

pub fn run(
    paths: &Paths,
    config: &mut Config,
    anisette_url: Option<String>,
    account: Option<String>,
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

    let session = crate::auth::login(config, &account)?;

    let mut snapshot = if paths.snapshot_file.exists() {
        vault::load(paths, config)?
    } else {
        Vault::default()
    };
    snapshot.account = Some(account.clone());
    snapshot.session = Some(session.clone());
    vault::save(paths, config, &snapshot)?;

    let mut state = config::load_state(paths)?;
    state.account = Some(account.clone());
    state.source = Some("icloud".into());
    state.entries = snapshot.entries.len() as u32;
    state.groups = snapshot.groups.len() as u32;
    state.last_status = Some("logged-in".into());
    state.failures = 0;
    config::save_state(paths, &state)?;

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
        println!("snapshot {}", paths.snapshot_file.display());
    }
    Ok(())
}
