use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A fresh dashed uppercase UUID v4, matching the record names CloudKit uses.
pub fn record_name() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
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
        bytes[15],
    )
}

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
    /// Items in Apple's Recently Deleted, as of the last sync. Trash is rebuilt
    /// from the fetched records each sync and is never merged into `entries`.
    #[serde(default)]
    pub trash: Vec<TrashEntry>,
    /// Edits made locally that have not been pushed yet.
    #[serde(default)]
    pub pending: Vec<PendingOp>,
    /// Synckey record names keyed by `"<zone>:<class>"`. Names only, never key
    /// material.
    #[serde(default)]
    pub synckeys: std::collections::BTreeMap<String, String>,
    /// The journal of group zones an older `apw group create` made.
    ///
    /// Creating groups over raw CloudKit only produced zones Passwords.app never
    /// lists, so nothing writes this any more. Snapshots written before that
    /// change still carry it, and `apw group list` uses the names to label a
    /// zone whose protection does not open. It is not written again.
    #[serde(default, skip_serializing)]
    pub group_ops: Vec<GroupOp>,
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
            trash: Vec::new(),
            pending: Vec::new(),
            synckeys: std::collections::BTreeMap::new(),
            group_ops: Vec::new(),
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
    /// CloudKit addressing and payloads for a later push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<RecordMeta>,
}

/// What a later push needs to address and re-seal one keychain record.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct RecordMeta {
    pub zone: String,
    pub item_type: String,
    #[serde(default)]
    pub item_etag: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    /// Base64 of the decrypted login/item plist.
    #[serde(default)]
    pub plist: Option<String>,
    #[serde(default)]
    pub sidecar_name: Option<String>,
    #[serde(default)]
    pub sidecar_type: Option<String>,
    #[serde(default)]
    pub sidecar_etag: Option<String>,
    /// Base64 of the decrypted password-manager metadata dictionary (`v_Data`).
    #[serde(default)]
    pub metadata: Option<String>,
    /// Base64 of the decrypted outer sidecar item plist the metadata came from.
    #[serde(default)]
    pub sidecar_plist: Option<String>,
}

/// Apple's suffix on the access group of an item in Recently Deleted. Moving an
/// item to the trash appends it to `agrp`; restoring strips it again.
pub const RECENTLY_DELETED: &str = "-recently-deleted";

/// The access group of a password-manager metadata sidecar, trashed or not.
pub const PASSWORD_MANAGER_AGRP: &str = "com.apple.password-manager";

/// One item in Apple's Recently Deleted, kept apart from `entries` so a restore
/// can undo the move without reading the zone again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashEntry {
    /// The item as it reads outside the trash, with the same fields it had
    /// before the delete.
    pub entry: Entry,
    /// Addressing and payloads for the trashed record. `plist` is the trashed
    /// item plist, and the sidecar fields describe the trashed sidecar when the
    /// item has one.
    pub record: RecordMeta,
    /// The plist's `mdat`: when the item was moved to Recently Deleted.
    #[serde(default)]
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The kind of change a pending op records.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Create,
    Edit,
    Delete,
}

/// A local change that has not been pushed to CloudKit.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingOp {
    /// Uppercase uuid, as shown by `apw pending` and taken by `resolve`.
    pub id: String,
    pub kind: OpKind,
    /// The kind of entry being written, so push picks the right class key
    /// (`classC` in the WiFi zone). Old vaults load as a login.
    #[serde(default)]
    pub entry_kind: EntryKind,
    pub zone: String,
    #[serde(default)]
    pub owner: Option<String>,
    pub item_name: String,
    pub item_type: String,
    #[serde(default)]
    pub item_base: Option<String>,
    #[serde(default)]
    pub item_new: Option<String>,
    #[serde(default)]
    pub item_etag: Option<String>,
    pub item_dirty: bool,
    #[serde(default)]
    pub sidecar_name: Option<String>,
    #[serde(default)]
    pub sidecar_type: Option<String>,
    #[serde(default)]
    pub sidecar_base: Option<String>,
    #[serde(default)]
    pub sidecar_new: Option<String>,
    /// Base64 of the exact outer sidecar plist to send. Distinct from
    /// `sidecar_new`, which is the metadata dictionary carried in `v_Data`.
    #[serde(default)]
    pub sidecar_write: Option<String>,
    #[serde(default)]
    pub sidecar_etag: Option<String>,
    pub sidecar_dirty: bool,
    #[serde(default)]
    pub blocked: Option<String>,
    #[serde(default)]
    pub attempts: u32,
    /// RFC3339 time before which this op is not retried. Set after a transient
    /// failure so a failing server is not hammered on every sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt: Option<String>,
    /// Set by `resolve --local` to push a blocked op even if it was refused.
    #[serde(default)]
    pub force: bool,
    /// A queued edit that undoes a move to Recently Deleted. The item step is
    /// an ordinary edit, but the sidecar step compares and writes the outer
    /// plist the way a trash does, because only the outer plist carries `agrp`.
    #[serde(default)]
    pub restore: bool,
    /// Display label captured when the op was queued, e.g.
    /// `"Scratch Login (tester)"`.
    #[serde(default)]
    pub label: String,
}

/// The delay before retrying an op that has failed `attempts` times: 30s
/// doubling each time, capped at an hour. The first retry waits 30s and the
/// eighth and later wait the cap.
pub fn backoff(attempts: u32, now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    if attempts == 0 {
        return now;
    }
    let shift = attempts.saturating_sub(1).min(7);
    let seconds = 30u64.saturating_mul(1u64 << shift).min(3600);
    now + chrono::Duration::seconds(seconds as i64)
}

/// Whether the op may be pushed at `now`. A missing or unreadable
/// `next_attempt` counts as due, so a hand-edited vault never stalls.
pub fn is_due(op: &PendingOp, now: chrono::DateTime<chrono::Utc>) -> bool {
    op.next_attempt
        .as_deref()
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .is_none_or(|at| at <= now)
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
    /// Credential ID from the item plist's `alis`, when sync saw it.
    #[serde(default)]
    pub credential_id: Vec<u8>,
    /// Raw `v_Data`: `0x04 || X || Y || scalar`, 97 bytes, when sync saw it.
    /// The last 32 bytes are the P-256 private scalar the CXF export needs.
    #[serde(default)]
    pub private_key: Vec<u8>,
    /// User handle from the item plist's `atag`.
    #[serde(default)]
    pub user_handle: Vec<u8>,
    /// `atag.name`, the account name shown for the credential.
    #[serde(default)]
    pub user_name: Option<String>,
    /// `atag.displayName`, the account's display name.
    #[serde(default)]
    pub user_display_name: Option<String>,
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
        // The sidecar's CloudKit identity travels with it so a later push can
        // rewrite the metadata record the merged view came from.
        if let Some(sidecar_record) = sidecar.record {
            let sidecar_name = sidecar.id;
            let sidecar_type = sidecar_record
                .sidecar_type
                .clone()
                .or_else(|| Some(sidecar_record.item_type.clone()))
                .filter(|value| !value.is_empty());
            let sidecar_etag = sidecar_record
                .sidecar_etag
                .clone()
                .or_else(|| sidecar_record.item_etag.clone());
            let metadata = sidecar_record.metadata.clone();
            let sidecar_plist = sidecar_record.sidecar_plist.clone();
            match &mut login.record {
                Some(record) => {
                    record.sidecar_name = Some(sidecar_name);
                    record.sidecar_type = sidecar_type;
                    record.sidecar_etag = sidecar_etag;
                    if metadata.is_some() {
                        record.metadata = metadata;
                    }
                    if sidecar_plist.is_some() {
                        record.sidecar_plist = sidecar_plist;
                    }
                }
                None => {
                    login.record = Some(RecordMeta {
                        zone: sidecar_record.zone,
                        item_type: String::new(),
                        sidecar_name: Some(sidecar_name),
                        sidecar_type,
                        sidecar_etag,
                        metadata,
                        sidecar_plist,
                        ..RecordMeta::default()
                    });
                }
            }
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

/// How far an owner-side group creation got.
///
/// Only read now, from snapshots written before group creation was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupPhase {
    /// The zone was created (or is about to be); the zoneshare is not saved.
    Created,
    /// The zoneshare record was saved, so the group is usable.
    Shared,
}

/// One group zone an older `apw group create` made.
///
/// Only read now, from snapshots written before group creation was removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupOp {
    /// The zone name, `group-<UPPER UUID>`.
    pub zone: String,
    /// The name the user gave the group.
    pub name: String,
    pub phase: GroupPhase,
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
    /// Platform whose device identity minted `pet`. Escrow requests must carry
    /// that platform's client info, so this survives refreshes and restarts.
    #[serde(default)]
    pub escrow_platform: Option<String>,
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

    #[test]
    fn merge_moves_the_sidecar_record_onto_the_login() {
        let mut logins = vec![login("id-solo", "example.com", "solo@example.com")];
        logins[0].record = Some(RecordMeta {
            zone: "Passwords".to_string(),
            item_type: "item".to_string(),
            item_etag: Some("login-etag".to_string()),
            parent: Some("class-key".to_string()),
            ..RecordMeta::default()
        });
        let mut metadata = sidecar("sidecar-id", "example.com", None);
        metadata.record = Some(RecordMeta {
            zone: "Passwords".to_string(),
            item_type: "item".to_string(),
            sidecar_name: Some("sidecar-id".to_string()),
            sidecar_type: Some("item".to_string()),
            sidecar_etag: Some("sidecar-etag".to_string()),
            metadata: Some("bWV0YQ==".to_string()),
            ..RecordMeta::default()
        });

        merge_sidecars(&mut logins, vec![metadata]);

        let record = logins[0].record.as_ref().expect("login keeps its record");
        assert_eq!(record.zone, "Passwords");
        assert_eq!(record.item_type, "item");
        assert_eq!(record.item_etag.as_deref(), Some("login-etag"));
        assert_eq!(record.parent.as_deref(), Some("class-key"));
        assert_eq!(record.sidecar_name.as_deref(), Some("sidecar-id"));
        assert_eq!(record.sidecar_type.as_deref(), Some("item"));
        assert_eq!(record.sidecar_etag.as_deref(), Some("sidecar-etag"));
        assert_eq!(record.metadata.as_deref(), Some("bWV0YQ=="));
    }

    #[test]
    fn merge_creates_a_login_record_from_the_sidecar() {
        let mut logins = vec![login("id-solo", "example.com", "solo@example.com")];
        let mut metadata = sidecar("sidecar-id", "example.com", None);
        metadata.record = Some(RecordMeta {
            zone: "Passwords".to_string(),
            item_type: "item".to_string(),
            sidecar_etag: Some("sidecar-etag".to_string()),
            ..RecordMeta::default()
        });

        merge_sidecars(&mut logins, vec![metadata]);

        let record = logins[0].record.as_ref().expect("login gains a record");
        assert_eq!(record.zone, "Passwords");
        assert_eq!(record.item_type, "");
        assert_eq!(record.sidecar_name.as_deref(), Some("sidecar-id"));
        assert_eq!(record.sidecar_type.as_deref(), Some("item"));
        assert_eq!(record.sidecar_etag.as_deref(), Some("sidecar-etag"));
    }

    #[test]
    fn vault_round_trips_pending_ops_and_synckeys() {
        let mut vault = Vault::default();
        vault.pending.push(PendingOp {
            id: "9E107D9D-372B-4C81-8D21-A9C61E8F5D41".to_string(),
            kind: OpKind::Edit,
            entry_kind: EntryKind::Login,
            zone: "Passwords".to_string(),
            owner: None,
            item_name: "item-1".to_string(),
            item_type: "item".to_string(),
            item_base: Some("YmFzZQ==".to_string()),
            item_new: Some("bmV3".to_string()),
            item_etag: Some("etag-1".to_string()),
            item_dirty: true,
            sidecar_name: Some("sidecar-1".to_string()),
            sidecar_type: Some("item".to_string()),
            sidecar_base: Some("bWV0YQ==".to_string()),
            sidecar_new: Some("bmV3bWV0YQ==".to_string()),
            sidecar_write: Some("d3JpdGU=".to_string()),
            sidecar_etag: Some("etag-2".to_string()),
            sidecar_dirty: true,
            blocked: None,
            attempts: 1,
            next_attempt: None,
            force: false,
            restore: false,
            label: String::new(),
        });
        vault
            .synckeys
            .insert("Passwords:inet".to_string(), "synckey-1".to_string());

        let json = serde_json::to_string(&vault).expect("serialize");
        let back: Vault = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.version, 1);
        assert_eq!(back.pending, vault.pending);
        assert_eq!(back.synckeys, vault.synckeys);
        assert_eq!(back.pending[0].kind, OpKind::Edit);
    }

    #[test]
    fn pending_op_without_an_entry_kind_loads_as_a_login() {
        let json = r#"{
            "id": "op-1",
            "kind": "Edit",
            "zone": "Passwords",
            "item_name": "item-1",
            "item_type": "item",
            "item_dirty": true,
            "sidecar_dirty": false
        }"#;

        let op: PendingOp = serde_json::from_str(json).expect("old op loads");

        assert_eq!(op.entry_kind, EntryKind::Login);
        assert_eq!(op.kind, OpKind::Edit);
    }

    #[test]
    fn old_vault_json_loads_with_defaults() {
        let json = r#"{
            "version": 1,
            "account": "me@example.com",
            "entries": [{"id": "id-1", "title": "Example"}],
            "groups": [],
            "session": null,
            "peer": null
        }"#;

        let vault: Vault = serde_json::from_str(json).expect("old vault loads");

        assert!(vault.pending.is_empty());
        assert!(vault.synckeys.is_empty());
        assert!(vault.group_ops.is_empty());
        assert!(vault.entries[0].record.is_none());
        assert_eq!(vault.entries[0].id, "id-1");
    }

    fn op_with_next_attempt(next_attempt: Option<&str>) -> PendingOp {
        PendingOp {
            id: "op-1".to_string(),
            kind: OpKind::Edit,
            entry_kind: EntryKind::Login,
            zone: "Passwords".to_string(),
            owner: None,
            item_name: "item-1".to_string(),
            item_type: "item".to_string(),
            item_base: None,
            item_new: None,
            item_etag: None,
            item_dirty: true,
            sidecar_name: None,
            sidecar_type: None,
            sidecar_base: None,
            sidecar_new: None,
            sidecar_write: None,
            sidecar_etag: None,
            sidecar_dirty: false,
            blocked: None,
            attempts: 0,
            next_attempt: next_attempt.map(str::to_string),
            force: false,
            restore: false,
            label: String::new(),
        }
    }

    #[test]
    fn backoff_doubles_from_thirty_seconds_and_caps_at_an_hour() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let delay = |attempts| (backoff(attempts, now) - now).num_seconds();
        assert_eq!(delay(0), 0);
        assert_eq!(delay(1), 30);
        assert_eq!(delay(2), 60);
        assert_eq!(delay(3), 120);
        assert_eq!(delay(6), 960);
        assert_eq!(delay(7), 1920);
        assert_eq!(delay(8), 3600);
        assert_eq!(delay(u32::MAX), 3600);
    }

    #[test]
    fn an_op_is_due_unless_a_future_retry_is_set() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(is_due(&op_with_next_attempt(None), now));
        assert!(is_due(
            &op_with_next_attempt(Some("2025-12-31T23:59:59Z")),
            now
        ));
        assert!(is_due(
            &op_with_next_attempt(Some("2026-01-01T00:00:00Z")),
            now
        ));
        assert!(!is_due(
            &op_with_next_attempt(Some("2026-01-01T00:00:30Z")),
            now
        ));
        // An unreadable stamp is treated as due rather than as a stall.
        assert!(is_due(&op_with_next_attempt(Some("tomorrow")), now));
    }

    #[test]
    fn the_legacy_group_journal_loads_but_is_not_saved() {
        let json = r#"{
            "version": 1,
            "group_ops": [
                {"zone": "group-1111", "name": "Family", "phase": "created"},
                {"zone": "group-2222", "name": "Work", "phase": "shared"}
            ]
        }"#;

        let vault: Vault = serde_json::from_str(json).expect("old journal loads");
        assert_eq!(vault.group_ops.len(), 2);
        assert_eq!(vault.group_ops[0].phase, GroupPhase::Created);

        let json = serde_json::to_string(&vault).unwrap();
        assert!(
            !json.contains("group_ops"),
            "the retired journal is not written again"
        );
    }
}
