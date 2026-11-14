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
