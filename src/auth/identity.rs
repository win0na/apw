//! Device identity for Apple's GrandSlam gateway.
//!
//! Two sources are supported:
//!
//! - an explicit anisette-v3-server (`anisette_url` or `APW_ANISETTE_URL`).
//!   The server returns Apple's device identity headers as a flat JSON object.
//! - the native ADI implementation in [`crate::adi`]. The first use provisions
//!   a profile against GSA and stores it under the state directory; later uses
//!   rebuild the OTP headers from that profile.
//!
//! `GET /` returns the remote current headers; `GET /v3/client_info` returns the
//! matching client info and user agent; `POST /v1/resync` repairs a stale
//! machine identity after GSA answers `hsc: 434`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use data_encoding::{HEXLOWER, HEXUPPER};
use plist::Value;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::adi::{self, Entropy, Platform, Profile, Provisioning};
use crate::config::{write_private, Config, Paths};
use crate::error::{Error, Result};

pub const FALLBACK_CLIENT_INFO: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
pub const FALLBACK_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";

const MAC_CLIENT_INFO: &str =
    "<MacBookPro18,3> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
const MAC_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
const MAC_APP_NAME: &str = "akd";

const WINDOWS_CLIENT_INFO: &str =
    "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>";
const WINDOWS_USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";
const WINDOWS_APP_NAME: &str = "Setup";

const GSA_LOOKUP: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const STATE_VERSION: u32 = 1;

#[derive(Clone)]
pub struct Identity {
    pub headers: BTreeMap<String, String>,
    pub client_info: String,
    pub user_agent: String,
    /// The native platform that minted this identity; `None` for a remote server.
    pub platform: Option<Platform>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("client_info", &self.client_info)
            .field("user_agent", &self.user_agent)
            .field("platform", &self.platform)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
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
/// emit the rejected spelling, so rewrite it before any account request leaves.
/// The provisioning endpoints accept the original spelling.
pub fn normalize_client_info(client_info: &str) -> String {
    client_info.replace("<macOS;", "<Mac OS X;")
}

#[derive(Clone)]
pub struct IdentitySource {
    source: Source,
}

#[derive(Clone)]
enum Source {
    Remote {
        base: String,
        // Building the client fails on systems without a CA store. Keep the
        // error instead of panicking, as `reqwest::Client::new` does.
        client: std::result::Result<reqwest::Client, String>,
    },
    Native {
        paths: Paths,
        client: std::result::Result<reqwest::Client, String>,
    },
}

#[derive(Deserialize, Default)]
struct ClientInfo {
    #[serde(default)]
    client_info: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
}

impl IdentitySource {
    pub fn new(base: &str) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| {
                format!("cannot create the HTTP client for the anisette server at {base}: {error}")
            });
        Self {
            source: Source::Remote { base, client },
        }
    }

    /// Use the configured server when there is one, otherwise the native ADI
    /// implementation.
    pub fn from_config(config: &Config, paths: &Paths) -> Self {
        match config.anisette_url() {
            Some(base) => Self::new(&base),
            None => Self::native(paths),
        }
    }

    fn native(paths: &Paths) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| format!("cannot create the HTTP client for native ADI: {error}"));
        Self {
            source: Source::Native {
                paths: paths.clone(),
                client,
            },
        }
    }

    fn client(&self) -> Result<&reqwest::Client> {
        let client = match &self.source {
            Source::Remote { client, .. } | Source::Native { client, .. } => client,
        };
        client
            .as_ref()
            .map_err(|error| Error::Message(error.clone()))
    }

    pub async fn identity(&self) -> Result<Identity> {
        self.identity_for(None).await
    }

    /// Fetch an identity from one backend (`?backend=macos|windows`) when the
    /// server hosts more than one. The native source has one profile per
    /// platform.
    pub async fn identity_for(&self, backend: Option<&str>) -> Result<Identity> {
        match &self.source {
            Source::Remote { .. } => self.remote_identity(backend).await,
            Source::Native { paths, .. } => {
                let platform = platform_for(backend);
                self.native_identity(paths, platform).await
            }
        }
    }

    async fn remote_identity(&self, backend: Option<&str>) -> Result<Identity> {
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
            platform: None,
            user_agent: info
                .user_agent
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| FALLBACK_USER_AGENT.to_string()),
        })
    }

    async fn headers(&self, query: &str) -> Result<BTreeMap<String, String>> {
        let Source::Remote { base, .. } = &self.source else {
            return Err(Error::Message(
                "the anisette server is not configured".into(),
            ));
        };
        let response = self
            .client()?
            .get(format!("{base}/{query}"))
            .send()
            .await
            .map_err(|error| offline(base, error))?
            .error_for_status()
            .map_err(|error| offline(base, error))?;
        let value: BTreeMap<String, serde_json::Value> = response.json().await?;

        Ok(value
            .into_iter()
            .filter_map(|(key, value)| match value {
                serde_json::Value::String(text) => Some((key, text)),
                serde_json::Value::Number(number) => Some((key, number.to_string())),
                _ => None,
            })
            .collect())
    }

    async fn client_info(&self, query: &str) -> Result<ClientInfo> {
        let Source::Remote { base, .. } = &self.source else {
            return Err(Error::Message(
                "the anisette server is not configured".into(),
            ));
        };
        let response = self
            .client()?
            .get(format!("{base}/v3/client_info{query}"))
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }

    pub async fn resync(&self, machine_data: &[u8], platform: Option<Platform>) -> Result<()> {
        match &self.source {
            // Apple asks for a resync when its copy of the device data is
            // stale. apw cannot replay that state, so drop the stored identity
            // and let the next request provision a fresh one. Only the chain
            // that failed is dropped; the other keeps its trusted code state.
            Source::Native { paths, .. } => {
                let platforms: &[Platform] = match platform {
                    Some(Platform::Mac) => &[Platform::Mac],
                    Some(Platform::Windows) => &[Platform::Windows],
                    None => &[Platform::Mac, Platform::Windows],
                };
                for platform in platforms {
                    let path = state_path(paths, *platform);
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(())
            }
            Source::Remote { base, .. } => {
                let body = serde_json::json!({
                    "sim": base64::engine::general_purpose::STANDARD.encode(machine_data),
                });
                self.client()?
                    .post(format!("{base}/v1/resync"))
                    .json(&body)
                    .send()
                    .await?
                    .error_for_status()?;
                Ok(())
            }
        }
    }

    async fn native_identity(&self, paths: &Paths, platform: Platform) -> Result<Identity> {
        let path = state_path(paths, platform);
        let state = match AdiState::load(&path, platform)? {
            Some(state) => state,
            None => {
                if std::env::var_os("APW_DEBUG").is_some() {
                    eprintln!("adi: provisioning a native {} identity", platform.name());
                }
                let state = self.provision(platform).await?;
                state.save(&path)?;
                state
            }
        };
        state.identity(platform)
    }

    /// Provision a fresh Apple device identity from GSA, following the
    /// `provision()` exchange in apple-auth's `src/client/client.cpp`.
    async fn provision(&self, platform: Platform) -> Result<AdiState> {
        let kind = DeviceKind::for_platform(platform);
        let (mut identity, hardware) = new_device(platform, kind);

        let seconds = u32::try_from(chrono::Utc::now().timestamp()).map_err(|_| {
            Error::Message("the system clock is outside the ADI provisioning range".into())
        })?;

        let lookup = self
            .provision_request(GSA_LOOKUP, None, kind, &identity)
            .await?;
        let urls = lookup
            .as_dictionary()
            .and_then(|dict| dict.get("urls"))
            .and_then(Value::as_dictionary)
            .ok_or_else(|| {
                Error::Message("the native ADI lookup response has no service URLs".into())
            })?;
        let start_url = urls
            .get("midStartProvisioning")
            .and_then(Value::as_string)
            .ok_or_else(|| {
                Error::Message("the native ADI lookup response has no start URL".into())
            })?;
        let finish_url = urls
            .get("midFinishProvisioning")
            .and_then(Value::as_string)
            .ok_or_else(|| {
                Error::Message("the native ADI lookup response has no finish URL".into())
            })?;

        let started = self
            .provision_request(start_url, Some(&empty_request()), kind, &identity)
            .await?;
        let started = started
            .as_dictionary()
            .and_then(|dict| dict.get("Response"))
            .and_then(Value::as_dictionary)
            .ok_or_else(|| Error::Message("the native ADI start response has no body".into()))?;
        check_status(started)?;
        let challenge = binary_field(started, "spim")?;

        let mut session =
            Provisioning::new(&challenge, &hardware, seconds, platform, Entropy::random())
                .map_err(adi_error)?;
        let cpim = base64::engine::general_purpose::STANDARD.encode(session.request());

        let finished = self
            .provision_request(finish_url, Some(&finish_request(&cpim)), kind, &identity)
            .await?;
        let finished = finished
            .as_dictionary()
            .and_then(|dict| dict.get("Response"))
            .and_then(Value::as_dictionary)
            .ok_or_else(|| Error::Message("the native ADI finish response has no body".into()))?;
        check_status(finished)?;

        let ptm = binary_field(finished, "ptm")?;
        let trust = binary_field(finished, "tk")?;
        let trust_key: [u8; 16] = trust.try_into().map_err(|_| {
            Error::Message("the native ADI finish response has a malformed trust key".into())
        })?;
        let profile = session.finish(&ptm, &trust_key).map_err(adi_error)?;
        identity.routing_info = routing_info(finished)?;

        Ok(AdiState::from_profile(platform, identity, &profile))
    }

    async fn provision_request(
        &self,
        url: &str,
        body: Option<&plist::Value>,
        kind: DeviceKind,
        identity: &DeviceIdentity,
    ) -> Result<plist::Value> {
        use reqwest::header::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", header(&identity.user_agent, "user agent")?);
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert("X-Mme-Device-Id", header(&identity.device_id, "device id")?);
        headers.insert(
            "X-Apple-I-MD-LU",
            header(&identity.local_user_hash, "local user hash")?,
        );
        headers.insert(
            "X-MMe-Client-Info",
            header(&identity.client_info, "client info")?,
        );
        headers.insert(
            "X-Apple-Client-App-Name",
            HeaderValue::from_static(kind.app_name),
        );
        headers.insert(
            "X-Apple-I-Client-Time",
            header(&utc_timestamp(), "client time")?,
        );
        headers.insert("X-Apple-I-TimeZone", HeaderValue::from_static("UTC"));
        headers.insert("X-Apple-Locale", HeaderValue::from_static("en_US"));

        let request = match body {
            Some(value) => {
                let mut bytes = Vec::new();
                plist::to_writer_xml(&mut bytes, value)?;
                self.client()?.post(url).body(bytes)
            }
            None => self.client()?.get(url),
        };
        let response = request.headers(headers).send().await.map_err(|error| {
            Error::Message(format!(
                "the native ADI provisioning request to {url} failed: {error}"
            ))
        })?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(Error::Message(format!(
                "the native ADI provisioning endpoint answered HTTP {status}"
            )));
        }
        Ok(plist::Value::from_reader_xml(&bytes[..])?)
    }
}

fn offline(base: &str, error: impl std::fmt::Display) -> Error {
    Error::Message(format!(
        "cannot use the anisette server at {base}: {error}\nset APW_ANISETTE_URL or configure \
         anisette_url to a reachable anisette server"
    ))
}

fn platform_for(backend: Option<&str>) -> Platform {
    match backend {
        Some("macos") => Platform::Mac,
        _ => Platform::Windows,
    }
}

#[derive(Clone, Copy)]
struct DeviceKind {
    client_info: &'static str,
    user_agent: &'static str,
    app_name: &'static str,
}

impl DeviceKind {
    fn for_platform(platform: Platform) -> Self {
        match platform {
            Platform::Mac => Self {
                client_info: MAC_CLIENT_INFO,
                user_agent: MAC_USER_AGENT,
                app_name: MAC_APP_NAME,
            },
            Platform::Windows => Self {
                client_info: WINDOWS_CLIENT_INFO,
                user_agent: WINDOWS_USER_AGENT,
                app_name: WINDOWS_APP_NAME,
            },
        }
    }
}

/// A fresh device identity plus the 20 random bytes used as the ADI hardware id.
fn new_device(platform: Platform, kind: DeviceKind) -> (DeviceIdentity, [u8; 20]) {
    let device_id = uuid_v4();
    let local_user_hash = match platform {
        Platform::Mac => base64::engine::general_purpose::STANDARD.encode(device_id.as_bytes()),
        Platform::Windows => {
            let mut seed = [0_u8; 32];
            rand::thread_rng().fill(&mut seed);
            HEXUPPER.encode(Sha256::digest(seed).as_slice())
        }
    };
    let mut hardware = [0_u8; 20];
    rand::thread_rng().fill(&mut hardware);

    let identity = DeviceIdentity {
        device_id,
        local_user_hash,
        hardware_hash: HEXLOWER.encode(&hardware),
        routing_info: String::new(),
        client_info: kind.client_info.to_string(),
        user_agent: kind.user_agent.to_string(),
    };
    (identity, hardware)
}

fn uuid_v4() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = HEXUPPER.encode(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn utc_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn state_path(paths: &Paths, platform: Platform) -> PathBuf {
    paths
        .state_dir
        .join("adi")
        .join(format!("{}.json", platform.name()))
}

fn empty_request() -> plist::Value {
    let mut root = plist::Dictionary::new();
    root.insert(
        "Header".into(),
        plist::Value::Dictionary(plist::Dictionary::new()),
    );
    root.insert(
        "Request".into(),
        plist::Value::Dictionary(plist::Dictionary::new()),
    );
    plist::Value::Dictionary(root)
}

fn finish_request(cpim: &str) -> plist::Value {
    let mut request = plist::Dictionary::new();
    request.insert("cpim".into(), plist::Value::String(cpim.to_string()));
    let mut root = plist::Dictionary::new();
    root.insert(
        "Header".into(),
        plist::Value::Dictionary(plist::Dictionary::new()),
    );
    root.insert("Request".into(), plist::Value::Dictionary(request));
    plist::Value::Dictionary(root)
}

fn check_status(response: &plist::Dictionary) -> Result<()> {
    let code = response
        .get("Status")
        .and_then(Value::as_dictionary)
        .and_then(|status| status.get("ec"))
        .and_then(Value::as_signed_integer)
        .ok_or_else(|| {
            Error::Message("the native ADI provisioning response has no status code".into())
        })?;
    if code != 0 {
        return Err(Error::Message(format!(
            "Apple rejected native ADI provisioning (code {code})"
        )));
    }
    Ok(())
}

fn binary_field(response: &plist::Dictionary, key: &str) -> Result<Vec<u8>> {
    let value = response.get(key).ok_or_else(|| {
        Error::Message(format!("the native ADI provisioning response has no {key}"))
    })?;
    match value {
        plist::Value::Data(bytes) => Ok(bytes.clone()),
        plist::Value::String(text) => base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| {
                Error::Message(format!(
                    "the native ADI provisioning response has an invalid {key}"
                ))
            }),
        _ => Err(Error::Message(format!(
            "the native ADI provisioning response has an invalid {key}"
        ))),
    }
}

fn routing_info(response: &plist::Dictionary) -> Result<String> {
    match response.get("X-Apple-I-MD-RINFO") {
        Some(plist::Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(plist::Value::Integer(number)) => Ok(number.to_string()),
        _ => Err(Error::Message(
            "the native ADI provisioning response has no routing information".into(),
        )),
    }
}

fn header(value: &str, label: &str) -> Result<reqwest::header::HeaderValue> {
    reqwest::header::HeaderValue::from_str(value)
        .map_err(|_| Error::Message(format!("the native ADI {label} is not a valid header")))
}

fn adi_error(error: adi::Error) -> Error {
    Error::Message(format!("native ADI: {error}"))
}

fn decode_hex<const N: usize>(field: &str, label: &str) -> Result<[u8; N]> {
    let bytes = HEXLOWER
        .decode(field.as_bytes())
        .map_err(|_| Error::Message(format!("the native ADI state has an invalid {label}")))?;
    bytes.try_into().map_err(|_| {
        Error::Message(format!(
            "the native ADI state has a {label} of the wrong length"
        ))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AdiState {
    version: u32,
    platform: String,
    identity: DeviceIdentity,
    profile: StoredProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DeviceIdentity {
    device_id: String,
    local_user_hash: String,
    hardware_hash: String,
    routing_info: String,
    client_info: String,
    user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredProfile {
    machine_id: String,
    secondary: String,
    encrypted_seed: String,
    extra_data: String,
    option: Option<u32>,
}

impl AdiState {
    fn load(path: &Path, platform: Platform) -> Result<Option<Self>> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let state: Self = serde_json::from_str(&text).map_err(|error| {
            Error::Message(format!(
                "cannot read the native ADI state at {}: {error}",
                path.display()
            ))
        })?;
        if state.version != STATE_VERSION {
            return Err(Error::Message(format!(
                "the native ADI state at {} has an unsupported version",
                path.display()
            )));
        }
        if state.platform != platform.name() {
            return Err(Error::Message(format!(
                "the native ADI state at {} is for {}, not {}",
                path.display(),
                state.platform,
                platform.name()
            )));
        }
        Ok(Some(state))
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let bytes = serde_json::to_vec(self)?;
        write_private(path, &bytes)
    }

    fn from_profile(platform: Platform, identity: DeviceIdentity, profile: &Profile) -> Self {
        Self {
            version: STATE_VERSION,
            platform: platform.name().to_string(),
            identity,
            profile: StoredProfile {
                machine_id: HEXLOWER.encode(&profile.machine_id),
                secondary: base64::engine::general_purpose::STANDARD.encode(&profile.secondary),
                encrypted_seed: HEXLOWER.encode(&profile.encrypted_seed),
                extra_data: HEXLOWER.encode(&profile.extra_data),
                option: profile.option,
            },
        }
    }

    fn profile(&self, platform: Platform) -> Result<Profile> {
        let machine_id = decode_hex(&self.profile.machine_id, "machine id")?;
        let secondary = base64::engine::general_purpose::STANDARD
            .decode(&self.profile.secondary)
            .map_err(|_| {
                Error::Message("the native ADI state has an invalid secondary state".into())
            })?;
        let encrypted_seed = decode_hex(&self.profile.encrypted_seed, "encrypted seed")?;
        let extra_data = decode_hex(&self.profile.extra_data, "extra data")?;
        Profile::from_parts(
            machine_id,
            secondary,
            encrypted_seed,
            extra_data,
            self.profile.option,
            platform,
        )
        .map_err(adi_error)
    }

    fn identity(&self, platform: Platform) -> Result<Identity> {
        let profile = self.profile(platform)?;
        let counter = adi::time_counter(chrono::Utc::now().timestamp()).map_err(adi_error)?;
        let client_info = normalize_client_info(&self.identity.client_info);

        let mut headers = BTreeMap::new();
        headers.insert("X-Apple-I-MD".into(), profile.otp_header(counter));
        headers.insert("X-Apple-I-MD-M".into(), profile.machine_id_header());
        headers.insert(
            "X-Apple-I-MD-LU".into(),
            self.identity.local_user_hash.clone(),
        );
        headers.insert(
            "X-Apple-I-MD-RINFO".into(),
            self.identity.routing_info.clone(),
        );
        headers.insert("X-Mme-Device-Id".into(), self.identity.device_id.clone());
        headers.insert("X-MMe-Client-Info".into(), client_info.clone());
        headers.insert("X-Apple-I-Client-Time".into(), utc_timestamp());
        headers.insert("X-Apple-I-TimeZone".into(), "UTC".into());
        headers.insert("X-Apple-Locale".into(), "en_US".into());

        Ok(Identity {
            headers,
            client_info,
            user_agent: self.identity.user_agent.clone(),
            platform: Some(platform),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_hex, normalize_client_info, platform_for, AdiState, DeviceIdentity, IdentitySource,
        Source, MAC_CLIENT_INFO, STATE_VERSION,
    };
    use crate::adi::Platform;
    use crate::config::{Config, Paths};

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

    #[test]
    fn the_backend_chooses_the_native_platform() {
        assert_eq!(platform_for(Some("macos")), Platform::Mac);
        assert_eq!(platform_for(Some("windows")), Platform::Windows);
        assert_eq!(platform_for(None), Platform::Windows);
    }

    #[test]
    fn a_config_without_a_url_uses_native_adi() {
        if std::env::var_os("APW_ANISETTE_URL").is_some() {
            return;
        }
        let paths = paths();
        let identities = IdentitySource::from_config(&Config::default(), &paths);
        assert!(matches!(identities.source, Source::Native { .. }));
    }

    #[test]
    fn a_configured_url_uses_the_remote_server() {
        let paths = paths();
        let config = Config {
            anisette_url: Some("http://127.0.0.1:6969".into()),
            ..Config::default()
        };
        let identities = IdentitySource::from_config(&config, &paths);
        assert!(matches!(identities.source, Source::Remote { .. }));
    }

    #[test]
    fn the_state_file_round_trips_through_json() {
        let profile = crate::adi::Profile::from_parts(
            [0x11; 60],
            vec![0x22; Platform::Mac.secondary_len()],
            [0x33; 32],
            [0; 8],
            None,
            Platform::Mac,
        )
        .unwrap();
        let identity = DeviceIdentity {
            device_id: "19FFDEED-97ED-35AE-14DF-819F442D6E99".into(),
            local_user_hash: "MTlGRkRFRUQtOTdFRC0zNUFFLTE0REYtODE5RjQ0MkQ2RTk5".into(),
            hardware_hash: "00".repeat(20),
            routing_info: "17106176".into(),
            client_info: MAC_CLIENT_INFO.into(),
            user_agent: "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0".into(),
        };
        let state = AdiState::from_profile(Platform::Mac, identity.clone(), &profile);

        let json = serde_json::to_string(&state).unwrap();
        let loaded: AdiState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, STATE_VERSION);
        assert_eq!(loaded.platform, "macos");
        assert_eq!(loaded.identity, identity);

        let restored = loaded.profile(Platform::Mac).unwrap();
        assert_eq!(restored.machine_id, profile.machine_id);
        assert_eq!(restored.secondary, profile.secondary);
        assert_eq!(restored.encrypted_seed, profile.encrypted_seed);
        assert_eq!(restored.extra_data, profile.extra_data);
        assert_eq!(restored.option, profile.option);
        assert_eq!(restored.platform, Platform::Mac);
    }

    #[test]
    fn the_state_schema_matches_the_documented_shape() {
        let profile = crate::adi::Profile::from_parts(
            [0x11; 60],
            vec![0x22; Platform::Windows.secondary_len()],
            [0x33; 32],
            [0; 8],
            None,
            Platform::Windows,
        )
        .unwrap();
        let identity = DeviceIdentity {
            device_id: "AAAA".into(),
            local_user_hash: "BBBB".into(),
            hardware_hash: "00".repeat(20),
            routing_info: "17106176".into(),
            client_info: super::WINDOWS_CLIENT_INFO.into(),
            user_agent: "akd/1.0 CFNetwork/808.1.4".into(),
        };
        let state = AdiState::from_profile(Platform::Windows, identity, &profile);
        let value: serde_json::Value = serde_json::to_value(&state).unwrap();

        assert_eq!(value["version"], 1);
        assert_eq!(value["platform"], "windows");
        for key in [
            "device_id",
            "local_user_hash",
            "hardware_hash",
            "routing_info",
            "client_info",
            "user_agent",
        ] {
            assert!(value["identity"][key].is_string(), "identity.{key}");
        }
        assert_eq!(value["profile"]["machine_id"].as_str().unwrap().len(), 120);
        assert!(value["profile"]["secondary"].is_string());
        assert_eq!(
            value["profile"]["encrypted_seed"].as_str().unwrap().len(),
            64
        );
        assert_eq!(value["profile"]["extra_data"].as_str().unwrap().len(), 16);
        assert!(value["profile"]["option"].is_null());
    }

    #[test]
    fn the_state_file_is_private_and_reloads() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/adi/macos.json");
        let profile = crate::adi::Profile::from_parts(
            [0x11; 60],
            vec![0x22; Platform::Mac.secondary_len()],
            [0x33; 32],
            [0; 8],
            None,
            Platform::Mac,
        )
        .unwrap();
        let state = AdiState::from_profile(
            Platform::Mac,
            DeviceIdentity {
                device_id: "AAAA".into(),
                local_user_hash: "BBBB".into(),
                hardware_hash: "00".repeat(20),
                routing_info: "17106176".into(),
                client_info: MAC_CLIENT_INFO.into(),
                user_agent: "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0".into(),
            },
            &profile,
        );
        state.save(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = AdiState::load(&path, Platform::Mac).unwrap().unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn the_adi_state_lives_under_the_state_directory() {
        let paths = paths();
        assert_eq!(
            super::state_path(&paths, Platform::Mac),
            paths.state_dir.join("adi/macos.json")
        );
        assert_eq!(
            super::state_path(&paths, Platform::Windows),
            paths.state_dir.join("adi/windows.json")
        );
    }

    #[test]
    fn a_nonzero_option_and_extra_data_are_accepted() {
        // These fields live in the ADI state body and do not choose the
        // envelope, so they must not change the proof.
        let profile = |extra_data, option| {
            crate::adi::Profile::from_parts(
                [0x11; 60],
                vec![0x22; Platform::Mac.secondary_len()],
                [0x33; 32],
                extra_data,
                option,
                Platform::Mac,
            )
            .unwrap()
        };
        let baseline = profile([0; 8], None).otp_header(12345);
        assert_eq!(profile([1; 8], None).otp_header(12345), baseline);
        assert_eq!(profile([0; 8], Some(7)).otp_header(12345), baseline);
    }

    #[test]
    fn a_hex_field_of_the_wrong_length_is_rejected() {
        assert!(decode_hex::<60>("00", "machine id").is_err());
        assert!(decode_hex::<1>("zz", "machine id").is_err());
    }

    fn paths() -> Paths {
        let dir = tempfile::tempdir().unwrap();
        // Leak the temp dir so the Paths inside the test stay valid; the
        // process exits after the test.
        let root = dir.keep();
        Paths {
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            snapshot_file: root.join("data/snapshot.bin"),
            state_dir: root.join("state"),
            state_file: root.join("state/state.json"),
        }
    }
}
