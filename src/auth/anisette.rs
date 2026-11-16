//! Client for an anisette-v3-server.
//!
//! The server returns Apple's device identity headers as a flat JSON object.
//! `GET /` returns the current headers; `GET /v3/client_info` returns the
//! matching client info and user agent; `POST /v1/resync` repairs a stale
//! machine identity after GSA answers `hsc: 434`.

use std::collections::BTreeMap;

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

pub const FALLBACK_CLIENT_INFO: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
pub const FALLBACK_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";

#[derive(Debug, Clone)]
pub struct Identity {
    pub headers: BTreeMap<String, String>,
    pub client_info: String,
    pub user_agent: String,
}

/// Keep the platform and OS tokens from a client-info string and replace the
/// service identity. Apple checks the platform against the ADI backend.
pub fn with_service(client_info: &str, service: &str) -> String {
    let mut parts = Vec::new();
    let mut rest = client_info.trim();
    while let Some(start) = rest.find('<') {
        let Some(end) = rest[start..].find('>') else {
            break;
        };
        parts.push(&rest[start..start + end + 1]);
        rest = &rest[start + end + 1..];
        if parts.len() == 2 {
            break;
        }
    }
    if parts.len() == 2 {
        format!("{} {} <{service}>", parts[0], parts[1])
    } else {
        format!("<{service}>")
    }
}

pub const AOSKIT_SERVICE: &str = "com.apple.AOSKit/282 (com.apple.accountsd/113)";
pub const SBD_SERVICE: &str = "com.apple.AuthKit/1 (com.apple.sbd/638.100.48)";
pub const MAC_AOSKIT: &str =
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>";
pub const MAC_AUTHKIT: &str =
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
pub const MAC_CLOUDKIT: &str =
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>";

impl Identity {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

pub struct Anisette {
    base: String,
    client: reqwest::Client,
}

#[derive(Deserialize, Default)]
struct ClientInfo {
    #[serde(default)]
    client_info: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
}

impl Anisette {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn identity(&self) -> Result<Identity> {
        let headers = self.headers().await?;

        for required in ["X-Apple-I-MD", "X-Apple-I-MD-M"] {
            if !headers.contains_key(required) {
                return Err(Error::Message(format!(
                    "anisette server did not return {required}"
                )));
            }
        }

        let info = self.client_info().await.unwrap_or_default();
        Ok(Identity {
            headers,
            client_info: info
                .client_info
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| FALLBACK_CLIENT_INFO.to_string()),
            user_agent: info
                .user_agent
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| FALLBACK_USER_AGENT.to_string()),
        })
    }

    async fn headers(&self) -> Result<BTreeMap<String, String>> {
        let response = self
            .client
            .get(format!("{}/", self.base))
            .send()
            .await?
            .error_for_status()?;
        let value: BTreeMap<String, Value> = response.json().await?;

        Ok(value
            .into_iter()
            .filter_map(|(key, value)| match value {
                Value::String(text) => Some((key, text)),
                Value::Number(number) => Some((key, number.to_string())),
                _ => None,
            })
            .collect())
    }

    async fn client_info(&self) -> Result<ClientInfo> {
        let response = self
            .client
            .get(format!("{}/v3/client_info", self.base))
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }

    pub async fn resync(&self, machine_data: &[u8]) -> Result<()> {
        let body = serde_json::json!({
            "sim": base64::engine::general_purpose::STANDARD.encode(machine_data),
        });
        self.client
            .post(format!("{}/v1/resync", self.base))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
