use std::future::Future;
use std::io::IsTerminal;

use base64::Engine;

use crate::auth::anisette::Anisette;
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
pub fn run(paths: &Paths, config: &mut Config, passcode: Option<String>, json: bool) -> Result<()> {
    if !paths.snapshot_file.exists() {
        return Err(Error::Invalid("run `apw login` first".into()));
    }
    let mut snapshot = vault::load(paths, config)?;
    let session = snapshot
        .session
        .clone()
        .ok_or_else(|| Error::Invalid("run `apw login` first".into()))?;
    let account = snapshot
        .account
        .clone()
        .or_else(|| config.account.clone())
        .ok_or_else(|| Error::Invalid("the snapshot has no account".into()))?;
    let anisette_url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set an anisette URL in the config".into()))?;
    let escrow_url = session
        .escrow_proxy_url
        .clone()
        .ok_or_else(|| Error::Message("the session has no escrow URL".into()))?;

    let passcode = match passcode {
        Some(passcode) => passcode,
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(Error::Invalid(
                    "pass --passcode or run this command in a terminal".into(),
                ));
            }
            rpassword::prompt_password("Escrow passcode: ")?
        }
    };
    if passcode.is_empty() {
        return Err(Error::Invalid("the escrow passcode is empty".into()));
    }

    let (peer, trust, sponsor) = block_on(async {
        let identity = Anisette::new(&anisette_url).identity().await?;
        let mac = Anisette::new(&anisette_url)
            .identity_for(Some("macos"))
            .await
            .unwrap_or_else(|_| identity.clone());
        let gateway = Gateway::bootstrap(&session, &mac).await?;
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

    let mut state = config::load_state(paths)?;
    state.last_status = Some("joined".into());
    config::save_state(paths, &state)?;

    let result = serde_json::json!({
        "peer": peer.id,
        "sponsor": sponsor.peer_id,
        "restore_point": trust.restore_point.len(),
        "account": account,
    });
    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([result])));
    } else {
        println!("joined the trust as {}", peer.id);
        println!("run `apw sync` to read the keychain");
    }
    Ok(())
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
