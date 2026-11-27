use std::future::Future;
use std::io::IsTerminal;

use base64::Engine;

use crate::auth::identity::IdentitySource;
use crate::cloudkit::Gateway;
use crate::config::{self, Config, Paths};
use crate::error::{Error, Result};
use crate::model::PeerState;
use crate::octagon::{self, escrow::Escrow, Peer};
use crate::output;
use crate::vault;

/// Join the Octagon trust with the escrow passcode.
///
/// This spends one of the ten escrow attempts.
pub fn run(paths: &Paths, config: &mut Config, json: bool) -> Result<()> {
    let joined = perform(paths, config)?;

    let result = serde_json::json!({
        "peer": joined.peer,
        "sponsor": joined.sponsor,
        "restore_point": joined.restore_point,
        "account": joined.account,
    });
    if output::use_json(json) {
        output::print_json(&output::success(result));
    } else {
        println!("joined the trust as {}", joined.peer);
        println!("run `apw sync` to read the keychain");
    }
    Ok(())
}

/// The result of a join, so `login` can report it in its own envelope.
pub struct Joined {
    pub account: String,
    pub peer: String,
    pub sponsor: String,
    pub restore_point: usize,
}

pub fn perform(paths: &Paths, config: &mut Config) -> Result<Joined> {
    let passcode = match std::env::var("APW_ESCROW_PASSCODE")
        .ok()
        .filter(|value| !value.is_empty())
    {
        Some(passcode) => passcode,
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(Error::Invalid(
                    "set APW_ESCROW_PASSCODE or run this command in a terminal".into(),
                ));
            }
            rpassword::prompt_password("Escrow passcode: ")?
        }
    };
    perform_with_passcode(paths, config, &passcode)
}

/// Join with an explicit escrow passcode, for callers that collect it themselves.
pub fn perform_with_passcode(paths: &Paths, config: &mut Config, passcode: &str) -> Result<Joined> {
    if passcode.is_empty() {
        return Err(Error::Invalid("the escrow passcode is empty".into()));
    }
    match perform_inner(paths, config, passcode) {
        Ok(joined) => {
            let mut state = config::load_state(paths)?;
            state.failures = 0;
            state.last_status = Some("joined".into());
            config::save_state(paths, &state)?;
            Ok(joined)
        }
        Err(error) => {
            // Count the failure so `login` stops retrying on its own. A state
            // write failure must not hide the join error.
            if let Ok(mut state) = config::load_state(paths) {
                state.failures = state.failures.saturating_add(1);
                state.last_status = Some("join-failed".into());
                let _ = config::save_state(paths, &state);
            }
            Err(error)
        }
    }
}

fn perform_inner(paths: &Paths, config: &mut Config, passcode: &str) -> Result<Joined> {
    if !paths.snapshot_file.exists() {
        return Err(Error::Auth("run `apw login` first".into()));
    }
    let mut snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Auth("run `apw login` first".into()))?;
    let account = snapshot
        .account
        .clone()
        .or_else(|| config.account.clone())
        .ok_or_else(|| Error::Invalid("the snapshot has no account".into()))?;
    let identities = IdentitySource::from_config(config, paths);
    let escrow_url = session.escrow_proxy_url.clone().ok_or_else(|| {
        Error::Message(
            "the session has no escrow URL; run `apw login --refresh` to re-read the \
                 service map"
                .into(),
        )
    })?;

    let (peer, trust, sponsor) = block_on(async {
        let identity = identities.identity().await?;
        let mac = identities
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = Gateway::bootstrap(
            &session,
            &mac,
            crate::cloudkit::CONTAINER,
            crate::cloudkit::Scope::Private,
        )
        .await?;
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
        let peer = Peer::generate(&octagon::machine_id(), "MacBookPro18,3")?;
        let (trust, _bottle, sponsor) = octagon::join(
            &gateway,
            &escrow,
            &peer,
            passcode.as_bytes(),
            &session.adsid,
        )
        .await?;
        Ok::<_, Error>((peer, trust, sponsor))
    })?;

    snapshot.peer = Some(PeerState {
        id: peer.id.clone(),
        signing_key: encode(&peer.keys.signing_x963()),
        encryption_key: encode(&peer.keys.encryption_x963()),
        permanent: encode(&peer.permanent),
        permanent_signature: encode(&peer.permanent_signature),
        sponsor_id: Some(sponsor.peer_id.clone()),
        sponsor_encryption_key: Some(encode(&sponsor.keys.encryption_x963())),
        restore_point: encode(&trust.restore_point),
    });
    vault::save(paths, config, &snapshot)?;

    Ok(Joined {
        account,
        peer: peer.id,
        sponsor: sponsor.peer_id,
        restore_point: trust.restore_point.len(),
    })
}

pub fn block_on<F, T>(future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
