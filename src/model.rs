use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    Success = 0,
    GenericError = 1,
    InvalidParam = 2,
    NoResults = 3,
    ServerError = 100,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    #[serde(default = "Vault::version_default")]
    pub version: u32,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub generated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub source: Source,
    #[serde(default)]
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub session: Option<Session>,
    #[serde(default)]
    pub peer: Option<PeerState>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            version: Self::version_default(),
            account: None,
            generated_at: None,
            source: Source::default(),
            entries: Vec::new(),
            groups: Vec::new(),
            session: None,
            peer: None,
        }
    }
}

/// The Octagon peer this device uses to read the keychain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerState {
    pub id: String,
    /// X9.63 P-384 private key, base64.
    pub signing_key: String,
    /// X9.63 P-384 private key, base64.
    pub encryption_key: String,
    /// Signed permanent info, base64.
    pub permanent: String,
    pub permanent_signature: String,
    #[serde(default)]
    pub sponsor_id: Option<String>,
    /// The recovered sponsor's encryption key, base64 X9.63.
    #[serde(default)]
    pub sponsor_encryption_key: Option<String>,
    #[serde(default)]
    pub restore_point: String,
}

impl Vault {
    fn version_default() -> u32 {
        1
    }

    /// Passwords the user can read, excluding passkeys and key material.
    pub fn login_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Login)
            .count()
    }

    /// Every item that is not a passkey; the app's All count minus passkeys.
    pub fn item_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.kind != EntryKind::Passkey)
            .count()
    }

    pub fn passkey_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Passkey)
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    #[default]
    Fixture,
    Icloud,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Fixture => f.write_str("fixture"),
            Source::Icloud => f.write_str("icloud"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Entry {
    pub id: String,
    #[serde(default)]
    pub kind: EntryKind,
    /// The keychain access group the record came from.
    #[serde(default)]
    pub agrp: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub sites: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub totp: Option<Totp>,
    #[serde(default)]
    pub passkey: Option<Passkey>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Entry {
    pub fn domain(&self) -> String {
        if let Some(site) = self.sites.first() {
            return site.clone();
        }
        let Some(url) = self.url.as_deref() else {
            return String::new();
        };
        let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
        rest.split('/').next().unwrap_or(rest).to_string()
    }

    pub fn label(&self) -> String {
        self.title
            .clone()
            .or_else(|| self.username.clone())
            .unwrap_or_else(|| self.domain())
    }

    pub fn matches(&self, query: &str) -> bool {
        let needle = query.to_lowercase();
        let domain = self.domain();
        let haystack = [
            self.title.as_deref(),
            self.url.as_deref(),
            self.username.as_deref(),
            Some(domain.as_str()),
        ];
        haystack
            .iter()
            .flatten()
            .any(|value| value.to_lowercase().contains(&needle))
            || self
                .sites
                .iter()
                .any(|site| site.to_lowercase().contains(&needle))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    #[default]
    Login,
    Note,
    Passkey,
    Card,
    Wifi,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Totp {
    pub secret: String,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "Totp::digits_default")]
    pub digits: u32,
    #[serde(default = "Totp::period_default")]
    pub period: u64,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub account_name: Option<String>,
}

impl Totp {
    fn digits_default() -> u32 {
        6
    }

    fn period_default() -> u64 {
        30
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Passkey {
    #[serde(default)]
    pub relying_party: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Fold `com.apple.password-manager` metadata records into the login they
/// describe. The sidecar points at its login by record id, or by domain and
/// username when it was written without a parent reference.
pub fn merge_sidecars(logins: &mut [Entry], sidecars: Vec<Entry>) -> Vec<Entry> {
    let mut unmatched = Vec::new();
    for sidecar in sidecars {
        let domain = sidecar.domain();
        let index = logins
            .iter()
            .position(|login| login.id == domain)
            .or_else(|| {
                logins.iter().position(|login| {
                    login.domain().eq_ignore_ascii_case(&domain)
                        && match (&login.username, &sidecar.username) {
                            (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
                            _ => true,
                        }
                })
            });
        let Some(index) = index else {
            unmatched.push(sidecar);
            continue;
        };
        let login = &mut logins[index];
        let login_domain = login.domain();
        let placeholder = login.title.as_deref().is_none_or(|title| {
            title == login_domain
                || title.starts_with("Password Manager Metadata")
                || title.ends_with(" ()")
        });
        if placeholder {
            login.title = sidecar.title;
        }
        if login.notes.is_none() {
            login.notes = sidecar.notes;
        }
        if login.totp.is_none() {
            login.totp = sidecar.totp;
        }
        if login.username.is_none() {
            login.username = sidecar.username;
        }
    }
    unmatched
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub shared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub adsid: String,
    pub dsid: String,
    pub pet: String,
    pub mme_auth_token: String,
    pub cloudkit_token: String,
    #[serde(default)]
    pub ckdatabasews_url: Option<String>,
    #[serde(default)]
    pub escrow_proxy_url: Option<String>,
    pub logged_in_at: chrono::DateTime<chrono::Utc>,
}
