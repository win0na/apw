use std::io::{IsTerminal, Write};

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
    no_join: bool,
    json: bool,
) -> Result<()> {
    if let Some(url) = anisette_url {
        config.anisette_url = Some(url);
    }
    if let Some(account) = account {
        config.account = Some(account);
    }

    let account = match config.account.clone() {
        Some(account) => account,
        None if std::io::stdin().is_terminal() => {
            eprint!("Apple ID: ");
            std::io::stderr().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let account = line.trim().to_string();
            if account.is_empty() {
                return Err(Error::Invalid("the account is empty".into()));
            }
            account
        }
        None => {
            return Err(Error::Invalid(
                "set --account or an account in the config".into(),
            ))
        }
    };
    config.account = Some(account.clone());

    // Resolve the snapshot key before any network work so a missing key fails
    // early. The escrow passcode is independent of it.
    vault::prepare(paths, config)?;

    let anisette = config.anisette_url.clone();
    let saved_account = config.account.clone();
    let salt = config.kdf_salt.clone();
    *config = Config::update(paths, |disk| {
        disk.anisette_url = anisette;
        disk.account = saved_account;
        disk.kdf_salt = salt;
    })?;

    if refresh {
        return refresh_services(paths, config, &account, json);
    }

    let mut snapshot = if paths.snapshot_file.exists() {
        vault::load(paths, config)?
    } else {
        Vault::default()
    };
    let previous = snapshot.session.clone();

    let code = std::env::var("APW_2FA_CODE")
        .ok()
        .filter(|value| !value.is_empty());
    let mut session = crate::auth::login(config, paths, &account, code)?;
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
    config::save_state(paths, &state)?;

    let had_peer = snapshot.peer.is_some();
    let should_join = join_plan(join, no_join, had_peer, state.failures);

    let joined = if should_join {
        Some(crate::commands::join::perform(paths, config)?)
    } else {
        None
    };

    let synced = should_join || had_peer;
    if synced {
        crate::commands::sync::run_silent(paths, config)?;
    }

    let state = config::load_state(paths)?;
    if session.escrow_proxy_url.is_none() {
        eprintln!(
            "warning: Apple returned no keychainsync service, so this session cannot join the \ntrust (see docs/troubleshooting.md)"
        );
    }
    let result = serde_json::json!({
        "account": account,
        "dsid": session.dsid,
        "adsid": session.adsid,
        "cloudkit": session.ckdatabasews_url,
        "escrow": session.escrow_proxy_url,
        "peer": joined.as_ref().map(|joined| &joined.peer),
        "sponsor": joined.as_ref().map(|joined| &joined.sponsor),
        "restore_point": joined.as_ref().map(|joined| joined.restore_point),
        "entries": state.entries,
        "logins": state.logins,
        "passkeys": state.passkeys,
        "wifi": state.wifi,
        "groups": state.groups,
        "shared_entries": state.shared_entries,
        "snapshot": paths.snapshot_file,
    });

    if output::use_json(json) {
        output::print_json(&output::success(result));
    } else {
        println!("signed in as {account}");
        if let Some(joined) = &joined {
            println!("joined the trust as {}", joined.peer);
        }
        if synced {
            println!(
                "synced {} logins, {} passkeys, and {} Wi-Fi networks",
                state.logins, state.passkeys, state.wifi
            );
        } else {
            println!("run `apw join` to read the keychain");
        }
        println!("snapshot {}", paths.snapshot_file.display());
    }
    Ok(())
}

fn refresh_services(paths: &Paths, config: &mut Config, account: &str, json: bool) -> Result<()> {
    let mut snapshot = vault::load(paths, config)?;
    let mut session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    // The macOS client info carries the full service map. When Apple refuses
    // it, the default identity still answers with a reduced one, so merge
    // rather than give up on the whole refresh.
    let identities = crate::auth::identity::IdentitySource::from_config(config, paths);
    let services = crate::commands::join::block_on(async {
        let mut services = crate::auth::icloud::Webservices::default();
        let mut first_error = None;
        if let Ok(identity) = identities.identity_for(Some("macos")).await {
            match crate::auth::icloud::account_settings(
                &identity,
                &session.dsid,
                &session.mme_auth_token,
            )
            .await
            {
                Ok(found) => services = found,
                Err(error) => first_error = Some(error),
            }
        }
        if services.escrow_proxy_url.is_none() {
            let identity = identities.identity().await?;
            match crate::auth::icloud::account_settings(
                &identity,
                &session.dsid,
                &session.mme_auth_token,
            )
            .await
            {
                Ok(found) => services.fill_from(found),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) if services.names.is_empty() => Err(error),
            _ => Ok(services),
        }
    })?;

    // Keep a URL the new map omits; a reduced map answers successfully with
    // fewer services.
    session.ckdatabasews_url = services
        .ckdatabasews_url
        .clone()
        .or_else(|| session.ckdatabasews_url.clone());
    session.escrow_proxy_url = services
        .escrow_proxy_url
        .clone()
        .or_else(|| session.escrow_proxy_url.clone());
    snapshot.session = Some(session.clone());
    vault::save(paths, config, &snapshot)?;

    let result = serde_json::json!({
        "account": account,
        "cloudkit": session.ckdatabasews_url,
        "escrow": session.escrow_proxy_url,
        "services": services.names,
    });
    if output::use_json(json) {
        output::print_json(&output::success(result));
    } else {
        println!("cloudkit {}", session.ckdatabasews_url.unwrap_or_default());
        println!("escrow {}", session.escrow_proxy_url.unwrap_or_default());
    }
    Ok(())
}

/// Join on first login; keep later logins cheap unless forced.
///
/// A failed join leaves `failures >= 1` behind, so a login stops retrying on
/// its own. `--join` still forces the attempt.
fn join_plan(force: bool, no_join: bool, has_peer: bool, failures: u32) -> bool {
    force || (!no_join && !has_peer && failures == 0)
}

#[cfg(test)]
mod tests {
    use super::join_plan;

    #[test]
    fn joins_a_fresh_account() {
        assert!(join_plan(false, false, false, 0));
    }

    #[test]
    fn skips_an_joined_account() {
        assert!(!join_plan(false, false, true, 0));
    }

    #[test]
    fn stops_auto_joining_after_a_failure() {
        assert!(!join_plan(false, false, false, 1));
        assert!(!join_plan(false, false, false, 3));
    }

    #[test]
    fn forced_join_ignores_failures() {
        assert!(join_plan(true, false, false, 2));
    }

    #[test]
    fn no_join_wins_unless_forced() {
        assert!(!join_plan(false, true, false, 0));
        assert!(join_plan(true, true, false, 0));
    }
}
