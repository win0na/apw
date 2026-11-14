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
        }
    }
}

impl Vault {
    fn version_default() -> u32 {
        1
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub shared: bool,
}
