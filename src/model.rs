use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    Success = 0,
    GenericError = 1,
    InvalidParam = 2,
    NoResults = 3,
    Auth = 4,
    Network = 5,
    Locked = 6,
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

    /// Every item that is not a passkey or a Wi-Fi network; the app's All
    /// count minus those two tabs.
    pub fn item_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| !matches!(entry.kind, EntryKind::Passkey | EntryKind::Wifi))
            .count()
    }

    pub fn wifi_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Wifi)
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

    /// The name Apple Passwords stores for the entry, or an empty string.
    /// This never falls back to the domain: a host is not a name.
    pub fn name(&self) -> String {
        let domain = self.domain();
        let title = self.title.as_deref().unwrap_or("").trim();
        let user = self.username.as_deref().unwrap_or("");
        if title.is_empty()
            || title == domain
            || title == format!("{domain} ({user})")
            || title == format!("{domain} ()")
            || title.starts_with("Password Manager Metadata")
        {
            return String::new();
        }
        title.to_string()
    }

    /// The name to show in a terminal. Falls back to the domain when Apple
    /// stored no name, so a table row still identifies the account.
    pub fn display_name(&self) -> String {
        let name = self.name();
        if name.is_empty() {
            self.domain()
        } else {
            name
        }
    }

    /// Safari records "never save for this site" as a login-shaped item with
    /// this label. It has no password and is not shown in Apple Passwords.
    pub fn is_placeholder(&self) -> bool {
        self.username
            .as_deref()
            .is_some_and(|user| user.trim().eq_ignore_ascii_case("Passwords not saved"))
            || self.title.as_deref().is_some_and(|title| {
                title
                    .trim_end()
                    .to_lowercase()
                    .ends_with("(passwords not saved)")
            })
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

/// Whether a sidecar's username can be attributed to a login's username. Two
/// known usernames must agree; a missing username on either side says nothing,
/// so the pairing is still possible.
fn usernames_compatible(login: Option<&str>, sidecar: Option<&str>) -> bool {
    match (login, sidecar) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => true,
    }
}

/// Whether two hosts name the same site, allowing a subdomain on either side.
fn same_site(left: &str, right: &str) -> bool {
    let left = left.trim_start_matches("www.").to_lowercase();
    let right = right.trim_start_matches("www.").to_lowercase();
    left == right || left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

/// The single login a sidecar's domain and username identify, if the match is
/// unambiguous. An exact host wins; a parent/subdomain match is the fallback.
fn unique_domain_match(logins: &[Entry], sidecar: &Entry) -> Option<usize> {
    let domain = sidecar.domain();
    // A sidecar with no domain must not attach itself to a domain-less note
    // just because both sides agree on "nothing".
    if domain.is_empty() {
        return None;
    }
    let username = sidecar.username.as_deref();
    let unique = |same: &dyn Fn(&str) -> bool| {
        let mut candidates = logins.iter().enumerate().filter(|(_, login)| {
            same(&login.domain()) && usernames_compatible(login.username.as_deref(), username)
        });
        let (index, _) = candidates.next()?;
        candidates.next().is_none().then_some(index)
    };
    unique(&|login| login.eq_ignore_ascii_case(&domain))
        .or_else(|| unique(&|login| same_site(login, &domain)))
}

/// Fold `com.apple.password-manager` metadata records into the login they
/// describe. The sidecar points at its login by record id, or by domain and
/// username when it was written without a parent reference. A domain-only
/// match is used only when exactly one login can be meant; otherwise the
/// sidecar is left unmatched rather than guessed onto an account.
pub fn merge_sidecars(logins: &mut [Entry], sidecars: Vec<Entry>) -> Vec<Entry> {
    let mut unmatched = Vec::new();
    for sidecar in sidecars {
        let domain = sidecar.domain();
        let index = logins
            .iter()
            .position(|login| login.id == domain)
            .or_else(|| unique_domain_match(logins, &sidecar));
        let Some(index) = index else {
            unmatched.push(sidecar);
            continue;
        };
        let login = &mut logins[index];
        // The sidecar title is the user's name for the login. Apple writes it
        // only when the name was changed, and it wins over the item label.
        if let Some(title) = sidecar.title.as_deref().map(str::trim).filter(|title| {
            !title.is_empty()
                && !title.starts_with("Password Manager Metadata")
                && !title.ends_with(" ()")
        }) {
            login.title = Some(title.to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: &str, domain: &str, username: &str) -> Entry {
        Entry {
            id: id.to_string(),
            title: Some(domain.to_string()),
            sites: vec![domain.to_string()],
            username: Some(username.to_string()),
            ..Entry::default()
        }
    }

    fn sidecar(id: &str, domain: &str, username: Option<&str>) -> Entry {
        Entry {
            id: id.to_string(),
            title: Some(format!("{domain} metadata")),
            notes: Some("from sidecar".to_string()),
            totp: Some(Totp {
                secret: "JBSWY3DPEHPK3PXP".to_string(),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                issuer: None,
                account_name: None,
            }),
            sites: vec![domain.to_string()],
            username: username.map(str::to_string),
            ..Entry::default()
        }
    }

    fn two_logins() -> Vec<Entry> {
        vec![
            login("id-alice", "example.com", "alice@example.com"),
            login("id-bob", "example.com", "bob@example.com"),
        ]
    }

    fn assert_untouched(entry: &Entry, domain: &str) {
        assert_eq!(entry.title.as_deref(), Some(domain));
        assert!(entry.notes.is_none());
        assert!(entry.totp.is_none());
    }

    #[test]
    fn name_does_not_fall_back_to_the_domain() {
        let entry = login("id-solo", "example.com", "solo@example.com");
        assert_eq!(entry.name(), "");
        assert_eq!(entry.display_name(), "example.com");
    }

    #[test]
    fn sidecar_title_wins_over_an_item_label() {
        let mut logins = vec![login("id-google", "accounts.google.com", "me@gmail.com")];
        let mut metadata = sidecar("sidecar", "accounts.google.com", Some("me@gmail.com"));
        metadata.title = Some("Google".to_string());

        let unmatched = merge_sidecars(&mut logins, vec![metadata]);

        assert!(unmatched.is_empty());
        assert_eq!(logins[0].title.as_deref(), Some("Google"));
        assert_eq!(logins[0].name(), "Google");
    }

    #[test]
    fn metadata_label_is_not_used_as_a_name() {
        let mut logins = vec![login("id-solo", "example.com", "solo@example.com")];
        let mut metadata = sidecar("sidecar", "example.com", None);
        metadata.title =
            Some("Password Manager Metadata: example.com (solo@example.com)".to_string());

        merge_sidecars(&mut logins, vec![metadata]);

        assert_eq!(logins[0].title.as_deref(), Some("example.com"));
        assert_eq!(logins[0].name(), "");
    }

    #[test]
    fn negative_placeholder_is_not_a_name() {
        let mut entry = login("id-solo", "accounts.google.com", "Passwords not saved");
        entry.title = Some("accounts.google.com (Passwords not saved)".to_string());
        assert!(entry.is_placeholder());
        assert_eq!(entry.name(), "");
    }

    #[test]
    fn sidecar_joins_a_subdomain_of_the_same_site() {
        let mut logins = vec![login("id-google", "accounts.google.com", "me@gmail.com")];
        let mut metadata = sidecar("sidecar", "google.com", Some("me@gmail.com"));
        metadata.title = Some("Google".to_string());

        merge_sidecars(&mut logins, vec![metadata]);

        assert_eq!(logins[0].title.as_deref(), Some("Google"));
        assert_eq!(logins[0].display_name(), "Google");
    }

    #[test]
    fn ambiguous_domain_without_username_leaves_logins_untouched() {
        let mut logins = two_logins();
        let unmatched = merge_sidecars(&mut logins, vec![sidecar("sidecar", "example.com", None)]);

        for entry in &logins {
            assert_untouched(entry, "example.com");
        }
        assert_eq!(unmatched.len(), 1);
        assert_eq!(unmatched[0].id, "sidecar");
    }

    #[test]
    fn ambiguous_domain_with_username_merges_only_the_named_login() {
        let mut logins = two_logins();
        let unmatched = merge_sidecars(
            &mut logins,
            vec![sidecar("sidecar", "example.com", Some("bob@example.com"))],
        );

        assert!(unmatched.is_empty());
        assert_untouched(&logins[0], "example.com");
        assert_eq!(logins[0].username.as_deref(), Some("alice@example.com"));
        let bob = &logins[1];
        assert_eq!(bob.title.as_deref(), Some("example.com metadata"));
        assert_eq!(bob.notes.as_deref(), Some("from sidecar"));
        assert!(bob.totp.is_some());
    }

    #[test]
    fn unique_login_on_domain_merges_without_username() {
        let mut logins = vec![login("id-solo", "example.com", "solo@example.com")];
        let unmatched = merge_sidecars(&mut logins, vec![sidecar("sidecar", "example.com", None)]);

        assert!(unmatched.is_empty());
        let solo = &logins[0];
        assert_eq!(solo.title.as_deref(), Some("example.com metadata"));
        assert_eq!(solo.notes.as_deref(), Some("from sidecar"));
        assert!(solo.totp.is_some());
    }

    #[test]
    fn parent_record_id_merges_despite_ambiguous_domain() {
        let mut logins = two_logins();
        // A sidecar addressed by its parent's record id: `domain()` yields the
        // login id, which the record-id branch matches first.
        let metadata = sidecar("sidecar", "id-bob", None);

        let unmatched = merge_sidecars(&mut logins, vec![metadata]);

        assert!(unmatched.is_empty());
        assert_untouched(&logins[0], "example.com");
        let bob = &logins[1];
        assert_eq!(bob.title.as_deref(), Some("id-bob metadata"));
        assert_eq!(bob.notes.as_deref(), Some("from sidecar"));
        assert!(bob.totp.is_some());
    }
}
