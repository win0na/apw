//! Client for an anisette-v3-server.
//!
//! The server returns Apple's device identity headers as a flat JSON object.
//! `GET /` returns the current headers; `GET /v3/client_info` returns the
//! matching client info and user agent; `POST /v1/resync` repairs a stale
//! machine identity after GSA answers `hsc: 434`.

use std::collections::BTreeMap;
use std::time::Duration;

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

/// Apple's edge answers HTTP 503 to the literal `<macOS;` platform token and
/// accepts `<Mac OS X;` for the same machine. Servers built from recent assets
/// emit the rejected spelling, so rewrite it before any request leaves.
pub fn normalize_client_info(client_info: &str) -> String {
    client_info.replace("<macOS;", "<Mac OS X;")
}

pub struct Anisette {
    base: String,
    // Building the client fails on systems without a CA store. Keep the error
    // instead of panicking, as `reqwest::Client::new` does.
    client: std::result::Result<reqwest::Client, String>,
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
        let base = base.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| {
                format!("cannot create the HTTP client for the anisette server at {base}: {error}")
            });
        Self { base, client }
    }

    fn client(&self) -> Result<&reqwest::Client> {
        self.client
            .as_ref()
            .map_err(|error| Error::Message(error.clone()))
    }

    pub async fn identity(&self) -> Result<Identity> {
        self.identity_for(None).await
    }

    /// Fetch an identity from one backend (`?backend=macos|windows`) when the
    /// server hosts more than one.
    pub async fn identity_for(&self, backend: Option<&str>) -> Result<Identity> {
        let query = backend
            .map(|name| format!("?backend={name}"))
            .unwrap_or_default();
        let headers = self.headers(&query).await?;

        for required in ["X-Apple-I-MD", "X-Apple-I-MD-M"] {
            if !headers.contains_key(required) {
                return Err(Error::Message(format!(
                    "anisette server did not return {required}"
                )));
            }
        }

        let info = self.client_info(&query).await.unwrap_or_default();
        let client_info = normalize_client_info(
            &info
                .client_info
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| FALLBACK_CLIENT_INFO.to_string()),
        );
        let mut headers = headers;
        for (name, value) in headers.iter_mut() {
            if name.eq_ignore_ascii_case("X-MMe-Client-Info") {
                *value = normalize_client_info(value);
            }
        }
        Ok(Identity {
            headers,
            client_info,
            user_agent: info
                .user_agent
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| FALLBACK_USER_AGENT.to_string()),
        })
    }

    async fn headers(&self, query: &str) -> Result<BTreeMap<String, String>> {
        let response = self
            .client()?
            .get(format!("{}/{query}", self.base))
            .send()
            .await
            .map_err(|error| self.offline(error))?
            .error_for_status()
            .map_err(|error| self.offline(error))?;
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

    fn offline(&self, error: impl std::fmt::Display) -> Error {
        Error::Message(format!(
            "cannot use the anisette server at {}: {error}\nstart it with:\n  \
             podman run -d --name apw-anisette --network host -v apw-anisette:/data \
             ghcr.io/fdkevin0/anisette-server-rs:0.2.1 --backend windows",
            self.base
        ))
    }

    async fn client_info(&self, query: &str) -> Result<ClientInfo> {
        let response = self
            .client()?
            .get(format!("{}/v3/client_info{query}", self.base))
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }

    pub async fn resync(&self, machine_data: &[u8]) -> Result<()> {
        let body = serde_json::json!({
            "sim": base64::engine::general_purpose::STANDARD.encode(machine_data),
        });
        self.client()?
            .post(format!("{}/v1/resync", self.base))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_client_info;

    #[test]
    fn the_macos_platform_token_is_relabelled() {
        assert_eq!(
            normalize_client_info(
                "<MacBookPro16,2> <macOS;26.7.1;25G241> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
            ),
            "<MacBookPro16,2> <Mac OS X;26.7.1;25G241> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
    }

    #[test]
    fn other_platforms_are_left_alone() {
        let windows =
            "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>";
        assert_eq!(normalize_client_info(windows), windows);
        let old =
            "<MacBookPro13,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
        assert_eq!(normalize_client_info(old), old);
    }
}
