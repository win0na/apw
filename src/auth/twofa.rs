//! Two-factor prompts on the GSA endpoints.
//!
//! The trusted-device code is pushed with a GET, then submitted in the
//! `security-code` header. Verification is implicit: the caller repeats the
//! SRP legs and looks for `Status.au` to be gone.

use std::time::Duration;

use base64::Engine;
use plist::Value;

use crate::auth::anisette::Identity;
use crate::error::{Error, Result};

pub fn identity_token(adsid: &str, idms_token: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{adsid}:{idms_token}"))
}

pub async fn request_trusted_device(identity_token: &str, identity: &Identity) -> Result<()> {
    let response = client()?
        .get(format!("{}/auth/verify/trusteddevice", base()))
        .headers(headers(identity_token, identity)?)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::Message(format!(
            "cannot request a two-factor code: HTTP {}",
            response.status()
        )))
    }
}

pub async fn submit_trusted_device(
    code: &str,
    identity_token: &str,
    identity: &Identity,
) -> Result<Option<String>> {
    let response = client()?
        .get(format!("{}/grandslam/GsService2/validate", base()))
        .headers(headers(identity_token, identity)?)
        .header("security-code", code)
        .send()
        .await?;

    let status = response.status();
    let pet = crate::auth::gsa::pet_from_headers(response.headers());
    let body = response.bytes().await?;
    if !status.is_success() {
        return Err(Error::Message(format!(
            "two-factor submission answered HTTP {status}"
        )));
    }
    if body.is_empty() {
        return Ok(pet);
    }

    let value = plist::Value::from_reader_xml(&body[..])?;
    let error = value
        .as_dictionary()
        .and_then(|dict| dict.get("ec"))
        .and_then(Value::as_signed_integer)
        .unwrap_or(0);
    if error != 0 {
        let message = value
            .as_dictionary()
            .and_then(|dict| dict.get("em"))
            .and_then(Value::as_string)
            .unwrap_or("two-factor code rejected");
        return Err(Error::Message(message.to_string()));
    }
    Ok(pet)
}

fn headers(identity_token: &str, identity: &Identity) -> Result<reqwest::header::HeaderMap> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    let mut headers = HeaderMap::new();
    for (name, value) in &identity.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::Message(format!("invalid header name {name}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| Error::Message(format!("invalid header value for {name}")))?;
        headers.insert(name, value);
    }

    headers.insert("Content-Type", HeaderValue::from_static("text/x-xml-plist"));
    headers.insert("Accept", HeaderValue::from_static("text/x-xml-plist"));
    headers.insert("User-Agent", HeaderValue::from_static("Xcode"));
    headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
    headers.insert(
        "X-Apple-Identity-Token",
        HeaderValue::from_str(identity_token)
            .map_err(|_| Error::Message("invalid identity token".into()))?,
    );
    headers.insert(
        "X-Apple-App-Info",
        HeaderValue::from_static("com.apple.gs.xcode.auth"),
    );
    headers.insert(
        "X-Xcode-Version",
        HeaderValue::from_static("27.0 (27A5218g)"),
    );
    headers.insert(
        "X-Mme-Client-Info",
        HeaderValue::from_str(&identity.client_info)
            .map_err(|_| Error::Message("invalid client info".into()))?,
    );
    Ok(headers)
}

fn base() -> String {
    std::env::var("APW_GSA_BASE")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "https://gsa.apple.com".to_string())
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .http1_only()
        .pool_max_idle_per_host(0)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| {
            Error::Message(format!("cannot create the two-factor HTTP client: {error}"))
        })
}
