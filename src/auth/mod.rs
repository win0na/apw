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

pub fn login(config: &Config, account: &str) -> Result<Session> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(login_async(config, account))
}

async fn login_async(config: &Config, account: &str) -> Result<Session> {
    let url = config
        .anisette_url()
        .ok_or_else(|| Error::Invalid("set --anisette-url or APW_ANISETTE_URL".into()))?;

    let anisette = anisette::Anisette::new(&url);
    let mut identity = anisette.identity().await?;

    let password = rpassword::prompt_password("Apple ID password: ")
        .map_err(|error| Error::Message(format!("cannot read the password: {error}")))?;

    let (status, spd) = authenticate(&anisette, &mut identity, account, &password).await?;
    let spd = if status.au.is_some() {
        let fields = gsa::spd_fields(&spd)?;
        let token = twofa::identity_token(&fields.adsid, &fields.gs_idms_token);
        twofa::request_trusted_device(&token, &identity).await?;

        let code = rpassword::prompt_password("two-factor code: ")
            .map_err(|error| Error::Message(format!("cannot read the code: {error}")))?;
        twofa::submit_trusted_device(&code, &token, &identity).await?;

        let (status, spd) = authenticate(&anisette, &mut identity, account, &password).await?;
        if status.au.is_some() {
            return Err(Error::Message(
                "two-factor is still required after the code was accepted".into(),
            ));
        }
        spd
    } else {
        spd
    };

    let fields = gsa::spd_fields(&spd)?;
    let delegates = icloud::login_delegates(&identity, account, &fields.adsid, &fields.pet).await?;
    let services =
        icloud::account_settings(&identity, &delegates.dsid, &delegates.mme_auth_token).await?;

    Ok(Session {
        adsid: fields.adsid,
        dsid: delegates.dsid,
        pet: fields.pet,
        mme_auth_token: delegates.mme_auth_token,
        cloudkit_token: delegates.cloudkit_token,
        ckdatabasews_url: services.ckdatabasews_url,
        escrow_proxy_url: services.escrow_proxy_url,
        logged_in_at: chrono::Utc::now(),
    })
}

async fn authenticate(
    anisette: &anisette::Anisette,
    identity: &mut Identity,
    account: &str,
    password: &str,
) -> Result<(Status, Value)> {
    let srp = SrpClient::new();

    for _ in 0..2 {
        let gsa = gsa::Gsa::new(identity.clone());
        let init = gsa.init(account, srp.public()).await?;

        if init.status.hsc == Some(434) || init.status.ec == -22421 {
            if let Some(machine_data) = &init.status.md_data {
                anisette.resync(machine_data).await?;
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
        return Ok((complete.status, gsa::decrypt_spd(&proof.key, &spd)?));
    }

    Err(Error::Message(
        "GSA identity resync did not settle; run login again".into(),
    ))
}
