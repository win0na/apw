//! Apple ID sign-in: anisette identity, GSA SRP, two-factor, and token exchange.

pub mod gsa;
pub mod icloud;
pub mod identity;
pub mod srp;
pub mod twofa;

use plist::Value;

use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::model::Session;

use self::gsa::Status;
use self::identity::{Identity, IdentitySource};
use self::srp::SrpClient;

/// Where a password sign-in stopped: finished, or waiting for a trusted-device code.
#[derive(Clone)]
pub enum LoginStart {
    Done(Box<Session>),
    /// The macOS identity was asked for a code.
    NeedCode(Box<TwoFactor>),
}

/// The platform of the identity that actually completed the sign-in. It can be
/// Windows even when the macOS chain was requested, because Apple 5xx replies
/// and a missing macOS identity both fall back to Windows.
fn chain_platform(identity: &Identity) -> &'static str {
    match identity.platform {
        Some(crate::adi::Platform::Mac) => "macos",
        _ => "windows",
    }
}

/// The state a two-factor submission needs, including the password for the SRP replay.
#[derive(Clone)]
pub struct TwoFactor {
    identities: IdentitySource,
    identity: Identity,
    account: String,
    password: String,
    identity_token: String,
    pet: Option<String>,
}

pub fn login(
    config: &Config,
    paths: &Paths,
    account: &str,
    mut code: Option<String>,
) -> Result<Session> {
    let password = match std::env::var("APW_PASSWORD") {
        Ok(password) if !password.is_empty() => password,
        _ => read_secret("Apple ID password: ")?,
    };
    let mut next = login_start(config, paths, account, &password)?;
    loop {
        match next {
            LoginStart::Done(session) => return Ok(*session),
            LoginStart::NeedCode(flow) => {
                let code = match code.take().filter(|code| !code.is_empty()) {
                    Some(code) => code,
                    None => std::env::var("APW_2FA_CODE")
                        .ok()
                        .filter(|code| !code.is_empty())
                        .map_or_else(|| read_secret("two-factor code: "), Ok)?,
                };
                next = submit_two_factor(*flow, &code)?;
            }
        }
    }
}

/// Sign in with explicit credentials, stopping before the two-factor code.
pub fn login_start(
    config: &Config,
    paths: &Paths,
    account: &str,
    password: &str,
) -> Result<LoginStart> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(login_start_async(config, paths, account, password))
}

async fn login_start_async(
    config: &Config,
    paths: &Paths,
    account: &str,
    password: &str,
) -> Result<LoginStart> {
    let identities = IdentitySource::from_config(config, paths);
    // The macOS chain yields the modern service map, the cloudKitToken, and the
    // PET the escrow proxy accepts. Fall back to Windows only when Apple or the
    // configured server cannot serve a macOS identity.
    let mut identity = match identities.identity_for(Some("macos")).await {
        Ok(identity) => identity,
        Err(error) => {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!("adi: macOS identity unavailable: {error}");
            }
            identities.identity().await?
        }
    };

    let (status, spd, pet) =
        authenticate_any_identity(&identities, &mut identity, account, password).await?;
    // Apple may send a trusted-device code during the SRP exchange without
    // setting `au`; `hsc: 409` means one is already on its way.
    let code_sent = status.hsc == Some(409) && status.au.is_none();
    // Prefer a PET from `spd`; only force a 2FA cycle when neither source has one.
    let spd_pet = gsa::spd_fields(&spd).ok().and_then(|fields| fields.pet);
    let needs_pet = pet.is_none() && spd_pet.is_none();
    if status.au.is_some() || code_sent || needs_pet {
        if status.au.as_deref() == Some("secondaryAuth") {
            return Err(Error::Message(
                "Apple asked for SMS two-factor, which this build does not support yet".into(),
            ));
        }

        let fields = gsa::idms_fields(&spd)?;
        let identity_token = twofa::identity_token(&fields.adsid, &fields.gs_idms_token);
        if !code_sent {
            twofa::request_trusted_device(&identity_token, &identity).await?;
        }
        return Ok(LoginStart::NeedCode(Box::new(TwoFactor {
            identities,
            identity,
            account: account.to_string(),
            password: password.to_string(),
            identity_token,
            pet,
        })));
    }

    // The signed-in identity already holds a PET here: the branch above forces
    // a code when it does not. The escrow proxy accepts it with the same
    // platform claim, so no second machine identity is needed.
    let signed_in_as = chain_platform(&identity);
    let escrow = spd_pet
        .clone()
        .or_else(|| pet.clone())
        .map(|pet| (pet, signed_in_as));
    finish_login(&identities, &mut identity, account, spd, pet, escrow)
        .await
        .map(|session| LoginStart::Done(Box::new(session)))
}

/// Submit the trusted-device code and finish the sign-in.
pub fn submit_two_factor(flow: TwoFactor, code: &str) -> Result<LoginStart> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(submit_two_factor_async(flow, code))
}

async fn submit_two_factor_async(flow: TwoFactor, code: &str) -> Result<LoginStart> {
    let identities = flow.identities;
    let mut identity = flow.identity;
    // The pre-replay identity mints the submitted PET and any PET carried in
    // from the first exchange; the replay can swap platforms on a 5xx.
    let mint_platform = chain_platform(&identity);
    let submitted = twofa::submit_trusted_device(code, &flow.identity_token, &identity).await?;
    let (status, spd, refreshed) =
        authenticate_any_identity(&identities, &mut identity, &flow.account, &flow.password)
            .await?;
    if status.au.is_some() || status.hsc == Some(409) {
        return Err(Error::Message(
            "two-factor is still required after the code was accepted".into(),
        ));
    }
    let refreshed_platform = chain_platform(&identity);
    let (pet, pet_platform) = if let Some(pet) = submitted {
        (Some(pet), mint_platform)
    } else if let Some(pet) = refreshed {
        (Some(pet), refreshed_platform)
    } else {
        (flow.pet, mint_platform)
    };
    let escrow = pet.clone().map(|pet| (pet, pet_platform));
    finish_login(&identities, &mut identity, &flow.account, spd, pet, escrow)
        .await
        .map(|session| LoginStart::Done(Box::new(session)))
}

async fn finish_login(
    identities: &identity::IdentitySource,
    identity: &mut Identity,
    account: &str,
    spd: Value,
    pet: Option<String>,
    escrow: Option<(String, &'static str)>,
) -> Result<Session> {
    let fields = gsa::spd_fields(&spd)?;
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "pet source: header={} spd={}",
            pet.as_ref().map(String::len).unwrap_or(0),
            fields.pet.as_ref().map(String::len).unwrap_or(0)
        );
    }
    // The `spd` token is the canonical GSA PET; the PE header is a fallback.
    let chain_pet = fields.pet.or(pet).ok_or_else(|| {
        Error::Message("GSA returned no PET; sign in again or check the account".into())
    })?;
    let delegates = icloud::login_delegates(identity, account, &fields.adsid, &chain_pet).await?;
    // A platform mismatch here is recoverable: the caller keeps the service
    // URLs and tokens from the previous session.
    let mut services =
        icloud::account_settings(identity, &delegates.dsid, &delegates.mme_auth_token)
            .await
            .unwrap_or_default();
    // A Windows identity gets a reduced service map, which drops the
    // keychainsync entry that carries the escrow proxy URL. This call is
    // authorized by the DSID and mmeAuthToken, not the machine identity, so ask
    // again with the macOS client info the GSA exchange had to skip.
    if services.escrow_proxy_url.is_none() {
        if let Ok(cloud) = identities.identity_for(Some("macos")).await {
            if let Ok(richer) =
                icloud::account_settings(&cloud, &delegates.dsid, &delegates.mme_auth_token).await
            {
                services.fill_from(richer);
            }
        }
    }
    // The escrow proxy only accepts a PET with the platform claim that minted
    // it. The caller selected a matching identity before this function runs.
    let (pet, escrow_platform) = match escrow {
        Some((pet, platform)) => (pet, platform),
        None => (chain_pet, chain_platform(identity)),
    };
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!("escrow pet: len={}", pet.len());
    }

    Ok(Session {
        adsid: fields.adsid,
        dsid: delegates.dsid,
        pet,
        mme_auth_token: delegates.mme_auth_token,
        cloudkit_token: services
            .cloudkit_token
            .clone()
            .unwrap_or(delegates.cloudkit_token),
        ckdatabasews_url: services.ckdatabasews_url,
        escrow_proxy_url: services.escrow_proxy_url,
        escrow_platform: Some(escrow_platform.to_string()),
        logged_in_at: chrono::Utc::now(),
    })
}

/// Re-fetch the service map and `cloudKitToken` with the stored session.
/// This is the only password-free renewal: `mmeAuthToken` itself cannot be
/// reissued without a fresh PET, and a PET only comes from a password login.
pub fn refresh_services(config: &Config, paths: &Paths, session: &Session) -> Result<Session> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(refresh_services_async(config, paths, session))
}

pub async fn refresh_services_async(
    config: &Config,
    paths: &Paths,
    session: &Session,
) -> Result<Session> {
    let identities = IdentitySource::from_config(config, paths);
    // The map must come from the platform that minted the token: Apple binds
    // `mmeAuthToken` to the device identity, so a Windows-minted session answers
    // 401 for a macOS client. Try macOS first, then merge the default identity's
    // map when Apple refuses it.
    let mut services = icloud::Webservices::default();
    let mut first_error = None;
    if let Ok(identity) = identities.identity_for(Some("macos")).await {
        match icloud::account_settings(&identity, &session.dsid, &session.mme_auth_token).await {
            Ok(found) => services = found,
            Err(error) => first_error = Some(error),
        }
    }
    if services.escrow_proxy_url.is_none() {
        let identity = identities.identity().await?;
        match icloud::account_settings(&identity, &session.dsid, &session.mme_auth_token).await {
            Ok(found) => services.fill_from(found),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = first_error {
        if services.names.is_empty() {
            return Err(error);
        }
    }

    let mut next = session.clone();
    if let Some(token) = services.cloudkit_token {
        next.cloudkit_token = token;
    }
    next.ckdatabasews_url = services
        .ckdatabasews_url
        .or_else(|| session.ckdatabasews_url.clone());
    next.escrow_proxy_url = services
        .escrow_proxy_url
        .or_else(|| session.escrow_proxy_url.clone());
    Ok(next)
}

pub fn is_auth_error(error: &Error) -> bool {
    let text = error.to_string().to_lowercase();
    text.contains("401") || text.contains("unauthorized")
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

/// A macOS identity can be rejected by Apple's edge with a 5xx even though the
/// same server answers with a Windows identity. Retry the SRP exchange once with
/// the Windows identity before giving up; the service map is then whatever that
/// identity yields, which is what a Windows-only anisette server gives anyway.
async fn authenticate_any_identity(
    identities: &identity::IdentitySource,
    identity: &mut Identity,
    account: &str,
    password: &str,
) -> Result<(Status, Value, Option<String>)> {
    match authenticate(identities, identity, account, password).await {
        Err(error) if matches!(&error, Error::GsaStatus(status) if status.is_server_error()) => {
            *identity = identities.identity().await?;
            authenticate(identities, identity, account, password).await
        }
        result => result,
    }
}

async fn authenticate(
    identities: &identity::IdentitySource,
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
                // is enough to retry when it does not. Drop and re-fetch only
                // the platform that failed.
                let platform = identity.platform;
                let _ = identities.resync(machine_data, platform).await;
                *identity = match platform {
                    Some(platform) => identities.identity_for(Some(platform.name())).await?,
                    None => identities.identity().await?,
                };
                continue;
            }
        }

        if !init.status.ok() {
            return Err(Error::Message(init.status.message()));
        }
        let Some(body) = init.body else {
            return Err(Error::Message("GSA returned no SRP challenge".into()));
        };

        let proof = srp.prove(
            account,
            password,
            &body.salt,
            body.iterations,
            body.scheme,
            &body.server_public,
        )?;
        let complete = gsa.complete(account, &body.continuation, &proof.m1).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(platform: Option<crate::adi::Platform>) -> Identity {
        Identity {
            headers: std::collections::BTreeMap::new(),
            client_info: String::new(),
            user_agent: String::new(),
            platform,
        }
    }

    #[test]
    fn the_escrow_claim_follows_the_identity_that_signed_in() {
        use crate::adi::Platform;
        assert_eq!(chain_platform(&identity(Some(Platform::Mac))), "macos");
        assert_eq!(
            chain_platform(&identity(Some(Platform::Windows))),
            "windows"
        );
        assert_eq!(chain_platform(&identity(None)), "windows");
    }
}
