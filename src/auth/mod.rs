//! Apple ID sign-in: anisette identity, GSA SRP, two-factor, and token exchange.

pub mod gsa;
pub mod icloud;
pub mod identity;
pub mod srp;
pub mod twofa;

use std::io::IsTerminal;

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
    NeedCode(Box<TwoFactor>),
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
    code: Option<String>,
) -> Result<Session> {
    let password = match std::env::var("APW_PASSWORD") {
        Ok(password) if !password.is_empty() => password,
        _ => read_secret("Apple ID password: ")?,
    };
    match login_start(
        config,
        paths,
        account,
        &password,
        std::io::stdin().is_terminal(),
    )? {
        LoginStart::Done(session) => Ok(*session),
        LoginStart::NeedCode(flow) => {
            let code = match code.filter(|code| !code.is_empty()) {
                Some(code) => code,
                None => std::env::var("APW_2FA_CODE")
                    .ok()
                    .filter(|code| !code.is_empty())
                    .map_or_else(
                        || read_secret("two-factor code for the macOS identity: "),
                        Ok,
                    )?,
            };
            submit_two_factor(*flow, &code, std::io::stdin().is_terminal())
        }
    }
}

/// Sign in with explicit credentials, stopping before the two-factor code.
pub fn login_start(
    config: &Config,
    paths: &Paths,
    account: &str,
    password: &str,
    interactive: bool,
) -> Result<LoginStart> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(login_start_async(
        config,
        paths,
        account,
        password,
        interactive,
    ))
}

async fn login_start_async(
    config: &Config,
    paths: &Paths,
    account: &str,
    password: &str,
    interactive: bool,
) -> Result<LoginStart> {
    let identities = IdentitySource::from_config(config, paths);
    // The macOS chain is the primary one: it yields the modern service map and
    // the cloudKitToken. The Windows chain supplies the escrow PET and is
    // fetched lazily, so a broken Windows identity cannot abort this chain.
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

    let escrow_pet = escrow_pet(
        &identities,
        account,
        password,
        std::env::var("APW_2FA_CODE_WINDOWS").ok(),
        interactive,
    )
    .await?;
    finish_login(&identities, &mut identity, account, spd, pet, escrow_pet)
        .await
        .map(|session| LoginStart::Done(Box::new(session)))
}

/// Submit the trusted-device code and finish the sign-in.
pub fn submit_two_factor(flow: TwoFactor, code: &str, interactive: bool) -> Result<Session> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(submit_two_factor_async(flow, code, interactive))
}

async fn submit_two_factor_async(
    flow: TwoFactor,
    code: &str,
    interactive: bool,
) -> Result<Session> {
    let identities = flow.identities;
    let mut identity = flow.identity;
    let submitted = twofa::submit_trusted_device(code, &flow.identity_token, &identity).await?;
    let (status, spd, refreshed) =
        authenticate_any_identity(&identities, &mut identity, &flow.account, &flow.password)
            .await?;
    if status.au.is_some() || status.hsc == Some(409) {
        return Err(Error::Message(
            "two-factor is still required after the code was accepted".into(),
        ));
    }
    let pet = submitted.or(refreshed).or(flow.pet);
    let escrow_pet = escrow_pet(
        &identities,
        &flow.account,
        &flow.password,
        std::env::var("APW_2FA_CODE_WINDOWS").ok(),
        interactive,
    )
    .await?;
    finish_login(
        &identities,
        &mut identity,
        &flow.account,
        spd,
        pet,
        escrow_pet,
    )
    .await
}

async fn finish_login(
    identities: &identity::IdentitySource,
    identity: &mut Identity,
    account: &str,
    spd: Value,
    pet: Option<String>,
    escrow_pet: Option<String>,
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
    let pet = fields.pet.or(pet).ok_or_else(|| {
        Error::Message("GSA returned no PET; sign in again or check the account".into())
    })?;
    let delegates = icloud::login_delegates(identity, account, &fields.adsid, &pet).await?;
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
    // The escrow proxy only accepts the PET minted by the Windows chain.
    // `escrow_pet` minted that one before this function runs.
    let pet = escrow_pet.unwrap_or(pet);
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

/// Mint the Windows-chain PET the escrow proxy accepts.
///
/// A Windows machine that Apple has not seen before answers the SRP with
/// `hsc: 409` and no PET, so ask for that machine's own two-factor code and
/// submit it. Without this the session keeps the macOS PET, which the escrow
/// proxy rejects with `-3001`.
///
/// A failure to obtain the Windows identity is not fatal: the caller keeps the
/// macOS PET and `join` reports the missing escrow token. A code that Apple
/// accepts but answers without a PET is fatal, because the session would store
/// a token the escrow proxy rejects.
async fn escrow_pet(
    identities: &identity::IdentitySource,
    account: &str,
    password: &str,
    mut code: Option<String>,
    interactive: bool,
) -> Result<Option<String>> {
    let debug = std::env::var_os("APW_DEBUG").is_some();
    let mut windows = match identities.identity_for(None).await {
        Ok(identity) => identity,
        Err(error) => {
            if debug {
                eprintln!("escrow pet: windows identity unavailable: {error}");
            }
            return Ok(None);
        }
    };
    let (status, spd, header_pet) =
        match authenticate(identities, &mut windows, account, password).await {
            Ok(result) => result,
            Err(error) => {
                if debug {
                    eprintln!("escrow pet: windows sign-in failed: {error}");
                }
                return Ok(None);
            }
        };
    let spd_pet = gsa::spd_fields(&spd).ok().and_then(|fields| fields.pet);
    if status.au.as_deref() == Some("secondaryAuth") {
        return Err(Error::Message(
            "Apple asked for SMS two-factor, which this build does not support yet".into(),
        ));
    }
    if status.au.is_none() && status.hsc != Some(409) {
        return Ok(spd_pet.or(header_pet));
    }

    let fields = gsa::idms_fields(&spd)?;
    let identity_token = twofa::identity_token(&fields.adsid, &fields.gs_idms_token);
    if status.hsc != Some(409) {
        twofa::request_trusted_device(&identity_token, &windows).await?;
    }
    let code = match code.take().filter(|code| !code.trim().is_empty()) {
        Some(code) => code,
        None if interactive => read_secret("two-factor code for the Windows identity: ")?,
        None => {
            return Err(Error::Message(
                "the Windows identity needs its own two-factor code; run `apw login` from a \
                 terminal or set APW_2FA_CODE_WINDOWS"
                    .into(),
            ));
        }
    };
    let pet = twofa::submit_trusted_device(&code, &identity_token, &windows).await?;
    match pet.or(spd_pet).or(header_pet) {
        Some(pet) => Ok(Some(pet)),
        None => Err(Error::Message(
            "Apple accepted the Windows code but returned no escrow PET; run `apw login` again"
                .into(),
        )),
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
