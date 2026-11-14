//! Token exchange after GSA login.
//!
//! `loginDelegates` trades the PET for `mmeAuthToken` and `cloudKitToken`;
//! `get_account_settings` returns the per-service URLs, including the
//! CloudKit database and the escrow proxy.

use base64::Engine;
use plist::{Dictionary, Value};
use rand::RngCore;

use crate::auth::anisette::Identity;
use crate::error::{Error, Result};

pub struct Delegates {
    pub dsid: String,
    pub mme_auth_token: String,
    pub cloudkit_token: String,
}

#[derive(Debug, Default)]
pub struct Webservices {
    pub ckdatabasews_url: Option<String>,
    pub escrow_proxy_url: Option<String>,
}

pub async fn login_delegates(
    identity: &Identity,
    apple_id: &str,
    adsid: &str,
    pet: &str,
) -> Result<Delegates> {
    let mut body = Dictionary::new();
    body.insert("apple-id".into(), Value::String(apple_id.into()));

    let mut delegates = Dictionary::new();
    delegates.insert(
        "com.apple.mobileme".into(),
        Value::Dictionary(Dictionary::new()),
    );
    body.insert("delegates".into(), Value::Dictionary(delegates));
    body.insert("password".into(), Value::String(pet.into()));
    body.insert("client-id".into(), Value::String(uuid_v4()));

    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &Value::Dictionary(body))?;

    let authorization =
        base64::engine::general_purpose::STANDARD.encode(format!("{apple_id}:{pet}"));
    let response = client()
        .post(format!("{}/setup/iosbuddy/loginDelegates", setup_base()))
        .headers(base_headers(identity)?)
        .header("Authorization", format!("Basic {authorization}"))
        .header("X-Apple-ADSID", adsid)
        .header("Content-Type", "text/x-xml-plist")
        .header(
            "User-Agent",
            "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        )
        .body(bytes)
        .send()
        .await?;

    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        return Err(Error::Message(format!(
            "loginDelegates answered HTTP {status}"
        )));
    }
    let value = plist::Value::from_reader_xml(&body[..])?;
    parse_delegates(&value)
}

pub async fn account_settings(
    identity: &Identity,
    dsid: &str,
    mme_auth_token: &str,
) -> Result<Webservices> {
    let authorization =
        base64::engine::general_purpose::STANDARD.encode(format!("{dsid}:{mme_auth_token}"));

    let response = client()
        .post(format!("{}/setup/get_account_settings", setup_base()))
        .headers(base_headers(identity)?)
        .header("Authorization", format!("Basic {authorization}"))
        .send()
        .await?;

    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        return Err(Error::Message(format!(
            "get_account_settings answered HTTP {status}"
        )));
    }
    let value = plist::Value::from_reader_xml(&body[..])?;
    Ok(parse_webservices(&value))
}

fn parse_delegates(value: &Value) -> Result<Delegates> {
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::Message("loginDelegates response is not a dictionary".into()))?;

    let dsid = dict
        .get("dsid")
        .and_then(scalar_string)
        .ok_or_else(|| Error::Message("loginDelegates response has no dsid".into()))?;

    let service = dict
        .get("delegates")
        .and_then(Value::as_dictionary)
        .and_then(|delegates| delegates.get("com.apple.mobileme"))
        .and_then(Value::as_dictionary)
        .ok_or_else(|| Error::Message("loginDelegates response has no mobileme delegate".into()))?;

    let status = service
        .get("status")
        .and_then(Value::as_signed_integer)
        .unwrap_or(0);
    if status != 0 {
        let message = service
            .get("status-message")
            .and_then(Value::as_string)
            .unwrap_or("mobileme delegate failed");
        return Err(Error::Message(message.to_string()));
    }

    let tokens = service
        .get("service-data")
        .and_then(Value::as_dictionary)
        .and_then(|data| data.get("tokens"))
        .and_then(Value::as_dictionary)
        .ok_or_else(|| Error::Message("loginDelegates response has no tokens".into()))?;

    Ok(Delegates {
        dsid,
        mme_auth_token: token(tokens, "mmeAuthToken")?,
        cloudkit_token: token(tokens, "cloudKitToken")?,
    })
}

fn parse_webservices(value: &Value) -> Webservices {
    let Some(webservices) = value
        .as_dictionary()
        .and_then(|dict| dict.get("webservices"))
        .and_then(Value::as_dictionary)
    else {
        return Webservices::default();
    };

    let ckdatabasews_url = webservices
        .get("ckdatabasews")
        .and_then(Value::as_dictionary)
        .and_then(|service| service.get("url"))
        .and_then(Value::as_string)
        .map(str::to_string);

    let escrow_proxy_url = webservices
        .get("KeychainSync")
        .and_then(Value::as_dictionary)
        .and_then(|service| service.get("escrowProxyUrl"))
        .and_then(Value::as_string)
        .map(str::to_string);

    Webservices {
        ckdatabasews_url,
        escrow_proxy_url,
    }
}

fn token(tokens: &Dictionary, name: &str) -> Result<String> {
    tokens
        .get(name)
        .and_then(Value::as_string)
        .map(str::to_string)
        .ok_or_else(|| Error::Message(format!("token response has no {name}")))
}

fn scalar_string(value: &Value) -> Option<String> {
    if let Some(text) = value.as_string() {
        return Some(text.to_string());
    }
    value
        .as_signed_integer()
        .map(|number| number.to_string())
        .or_else(|| value.as_unsigned_integer().map(|number| number.to_string()))
}

fn base_headers(identity: &Identity) -> Result<reqwest::header::HeaderMap> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    let mut headers = HeaderMap::new();
    for (name, value) in &identity.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::Message(format!("invalid header name {name}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| Error::Message(format!("invalid header value for {name}")))?;
        headers.insert(name, value);
    }
    headers.insert(
        "X-Mme-Client-Info",
        HeaderValue::from_str(&identity.client_info)
            .map_err(|_| Error::Message("invalid client info".into()))?,
    );
    Ok(headers)
}

fn setup_base() -> String {
    std::env::var("APW_SETUP_ENDPOINT")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "https://setup.icloud.com".to_string())
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
