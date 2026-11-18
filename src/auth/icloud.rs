//! Token exchange after GSA login.
//!
//! `loginDelegates` trades the PET for `mmeAuthToken` and `cloudKitToken`;
//! `get_account_settings` returns the per-service URLs, including the
//! CloudKit database and the escrow proxy.

use std::time::Duration;

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
    pub cloudkit_token: Option<String>,
    pub names: Vec<String>,
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
    delegates.insert(
        "com.apple.Dataclass.CloudKit".into(),
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
        .header(
            "X-Mme-Client-Info",
            crate::auth::anisette::with_service(
                &identity.client_info,
                crate::auth::anisette::AOSKIT_SERVICE,
            ),
        )
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
    if std::env::var_os("APW_DEBUG").is_some() {
        if let Some(dict) = value.as_dictionary() {
            eprintln!("settings top-level: {:?}", dict.keys().collect::<Vec<_>>());
            if let Some(tokens) = dict.get("tokens").and_then(Value::as_dictionary) {
                eprintln!("settings tokens: {:?}", tokens.keys().collect::<Vec<_>>());
            }
            if let Some(mm) = dict
                .get("com.apple.mobileme")
                .and_then(Value::as_dictionary)
            {
                eprintln!("settings mobileme: {:?}", mm.keys().collect::<Vec<_>>());
            }
            if let Some(delegates) = dict.get("delegates").and_then(Value::as_dictionary) {
                eprintln!(
                    "settings delegates: {:?}",
                    delegates.keys().collect::<Vec<_>>()
                );
            }
        }
    }
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

    let mme_auth_token = token(tokens, "mmeAuthToken")?;
    // The CloudKit delegate carries its own token; some accounts omit it from
    // the mobileme delegate.
    let cloudkit_token = dict
        .get("delegates")
        .and_then(Value::as_dictionary)
        .and_then(|delegates| delegates.get("com.apple.Dataclass.CloudKit"))
        .and_then(Value::as_dictionary)
        .and_then(|delegate| delegate.get("service-data"))
        .and_then(Value::as_dictionary)
        .and_then(|data| data.get("tokens"))
        .and_then(Value::as_dictionary)
        .and_then(|tokens| token(tokens, "cloudKitToken").ok())
        .or_else(|| token(tokens, "cloudKitToken").ok())
        .unwrap_or_else(|| mme_auth_token.clone());
    Ok(Delegates {
        dsid,
        mme_auth_token,
        cloudkit_token,
    })
}

fn parse_webservices(value: &Value) -> Webservices {
    let Some(dict) = value.as_dictionary() else {
        return Webservices::default();
    };

    let mut names = Vec::new();
    let mut ckdatabasews_url = None;
    let mut escrow_proxy_url = None;

    for root in ["webservices", "com.apple.mobileme"] {
        let Some(services) = dict.get(root).and_then(Value::as_dictionary) else {
            continue;
        };
        for (name, value) in services {
            names.push(name.clone());
            let Some(service) = value.as_dictionary() else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if std::env::var_os("APW_DEBUG").is_some() && lower.contains("keychainsync") {
                eprintln!(
                    "keychainsync keys: {:?}",
                    service.keys().collect::<Vec<_>>()
                );
                for (key, value) in service {
                    let key_lower = key.to_ascii_lowercase();
                    if key_lower.contains("group")
                        || key_lower.contains("zone")
                        || key_lower.contains("share")
                    {
                        eprintln!("  {key}: {value:?}");
                    }
                }
            }
            let escrow = lower.contains("keychainsync") || lower.contains("escrow");
            let url = if escrow {
                service
                    .get("escrowProxyUrl")
                    .and_then(Value::as_string)
                    .or_else(|| service.get("url").and_then(Value::as_string))
            } else {
                service
                    .get("url")
                    .and_then(Value::as_string)
                    .or_else(|| service.get("escrowProxyUrl").and_then(Value::as_string))
            };
            let Some(url) = url else {
                continue;
            };
            if lower.contains("ckdatabasews") && ckdatabasews_url.is_none() {
                ckdatabasews_url = Some(url.to_string());
            }
            if escrow && escrow_proxy_url.is_none() {
                escrow_proxy_url = Some(url.to_string());
            }
        }
    }

    let cloudkit_token = dict
        .get("tokens")
        .and_then(Value::as_dictionary)
        .and_then(|tokens| tokens.get("cloudKitToken"))
        .and_then(Value::as_string)
        .map(str::to_string);

    Webservices {
        ckdatabasews_url,
        escrow_proxy_url,
        cloudkit_token,
        names,
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
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
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
