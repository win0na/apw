//! Apple ID sign-in: anisette identity, GSA SRP, two-factor, and token exchange.

pub mod anisette;
pub mod gsa;
pub mod icloud;
pub mod srp;
pub mod twofa;

use plist::Value;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::model::Session;

use self::anisette::Identity;
use self::gsa::Status;
use self::srp::SrpClient;

pub fn login(config: &Config, account: &str, code: Option<String>) -> Result<Session> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(login_async(config, account, code))
}

async fn login_async(config: &Config, account: &str, code: Option<String>) -> Result<Session> {
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set --anisette-url or APW_ANISETTE_URL".into()))?;

    let anisette = anisette::Anisette::new(&url);
    let mut identity = anisette.identity().await?;
    // Account settings and CloudKit want the macOS profile; GSA, delegates and
    // escrow want the Windows one. A single-backend server falls back.
    let mac = anisette
        .identity_for(Some("macos"))
        .await
        .unwrap_or_else(|_| identity.clone());

    let password = match std::env::var("APW_PASSWORD") {
        Ok(password) if !password.is_empty() => password,
        _ => read_secret("Apple ID password: ")?,
    };

    let (status, spd, mut pet) = authenticate(&anisette, &mut identity, account, &password).await?;
    // Apple may send a trusted-device code during the SRP exchange without
    // setting `au`; `hsc: 409` means one is already on its way.
    let code_sent = status.hsc == Some(409) && status.au.is_none();
    // Prefer a PET from `spd`; only force a 2FA cycle when neither source has one.
    let spd_pet = gsa::spd_fields(&spd).ok().and_then(|fields| fields.pet);
    let needs_pet = pet.is_none() && spd_pet.is_none();
    let spd = if status.au.is_some() || code_sent || needs_pet {
        if status.au.as_deref() == Some("secondaryAuth") {
            return Err(Error::Message(
                "Apple asked for SMS two-factor, which this build does not support yet".into(),
            ));
        }

        let fields = gsa::idms_fields(&spd)?;
        let token = twofa::identity_token(&fields.adsid, &fields.gs_idms_token);
        if !code_sent {
            twofa::request_trusted_device(&token, &identity).await?;
        }

        let code = match &code {
            Some(code) if !code.is_empty() => code.clone(),
            _ => read_secret("two-factor code: ")?,
        };
        let submitted = twofa::submit_trusted_device(&code, &token, &identity).await?;

        let (status, spd, refreshed) =
            authenticate(&anisette, &mut identity, account, &password).await?;
        if status.au.is_some() || status.hsc == Some(409) {
            return Err(Error::Message(
                "two-factor is still required after the code was accepted".into(),
            ));
        }
        pet = submitted.or(refreshed).or(pet);
        spd
    } else {
        spd
    };

    let fields = gsa::spd_fields(&spd)?;
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "pet source: header={} spd={}",
            pet.as_ref().map(String::len).unwrap_or(0),
            fields.pet.as_ref().map(String::len).unwrap_or(0)
        );
    }
    // The `spd` token is the canonical GSA PET; the PE header is a fallback.
    let pet = fields.pet.or(pet).ok_or_else(|| {
        Error::Message("GSA returned no PET; sign in again or check the account".into())
    })?;
    let delegates = icloud::login_delegates(&identity, account, &fields.adsid, &pet).await?;
    let services =
        icloud::account_settings(&mac, &delegates.dsid, &delegates.mme_auth_token).await?;
    Ok(Session {
        adsid: fields.adsid,
        dsid: delegates.dsid,
        pet,
        mme_auth_token: delegates.mme_auth_token,
        cloudkit_token: delegates.cloudkit_token,
        ckdatabasews_url: services.ckdatabasews_url,
        escrow_proxy_url: services.escrow_proxy_url,
        logged_in_at: chrono::Utc::now(),
    })
}

fn read_secret(prompt: &str) -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};

    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt)
            .map_err(|error| Error::Message(format!("cannot read input: {error}")));
    }
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

async fn authenticate(
    anisette: &anisette::Anisette,
    identity: &mut Identity,
    account: &str,
    password: &str,
) -> Result<(Status, Value, Option<String>)> {
    let srp = SrpClient::new();

    for _ in 0..2 {
        let gsa = gsa::Gsa::new(identity.clone());
        let init = gsa.init(account, srp.public()).await?;

        if init.status.hsc == Some(434) || init.status.ec == -22421 {
            if let Some(machine_data) = &init.status.md_data {
                // Not every anisette server exposes resync; a fresh identity
                // is enough to retry when it does not.
                let _ = anisette.resync(machine_data).await;
                *identity = anisette.identity().await?;
                continue;
            }
        }

        if !init.status.ok() {
            return Err(Error::Message(init.status.message()));
        }

        let proof = srp.prove(
            account,
            password,
            &init.salt,
            init.iterations,
            init.scheme,
            &init.server_public,
        )?;
        let complete = gsa.complete(account, &init.continuation, &proof.m1).await?;

        if !complete.status.ok() {
            return Err(Error::Message(complete.status.message()));
        }
        if complete.m2 != proof.m2 {
            return Err(Error::Message(
                "server did not prove the SRP session key".into(),
            ));
        }

        let spd = complete
            .spd
            .ok_or_else(|| Error::Message("GSA returned no spd".into()))?;
        return Ok((
            complete.status,
            gsa::decrypt_spd(&proof.key, &spd)?,
            complete.pet,
        ));
    }

    Err(Error::Message(
        "GSA identity resync did not settle; run login again".into(),
    ))
}
