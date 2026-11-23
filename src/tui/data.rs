//! Read-only view model for the TUI: snapshot rows, counts and dashboard data.
//!
//! Nothing here prints or prompts. The interface only reads these values.

use chrono::{DateTime, Utc};

use crate::config::{load_state, Config, Paths, State};
use crate::error::Result;
use crate::model::{Entry, EntryKind, Group, PendingOp, Source, TrashEntry, Vault};
use crate::vault;

pub struct VaultView {
    pub vault: Vault,
    pub state: State,
    pub config: Config,
    pub paths: Paths,
    pub has_snapshot: bool,
}

impl VaultView {
    /// Load the snapshot and the state file before the terminal is taken over.
    pub fn load(paths: &Paths) -> Result<Self> {
        let mut config = Config::load(paths)?;
        let has_snapshot = paths.snapshot_file.is_file();
        let vault = if has_snapshot {
            vault::load(paths, &mut config)?
        } else {
            Vault {
                source: Source::Icloud,
                ..Vault::default()
            }
        };
        let state = load_state(paths)?;
        Ok(Self {
            vault,
            state,
            config,
            paths: paths.clone(),
            has_snapshot,
        })
    }

    /// Re-read the snapshot and state after a sync or a write.
    pub fn reload(&mut self) -> Result<()> {
        self.config = Config::load(&self.paths)?;
        self.vault = vault::load(&self.paths, &mut self.config)?;
        self.state = load_state(&self.paths)?;
        self.has_snapshot = true;
        Ok(())
    }

    pub fn account(&self) -> Option<&str> {
        self.state
            .account
            .as_deref()
            .or(self.vault.account.as_deref())
            .or(self.config.account.as_deref())
    }

    pub fn last_sync(&self) -> Option<DateTime<Utc>> {
        self.state.last_sync.or(self.vault.generated_at)
    }

    pub fn dashboard(&self, now: DateTime<Utc>) -> Dashboard {
        let phase = if !self.has_snapshot {
            DashboardPhase::NoSnapshot
        } else if self.vault.session.is_none() {
            DashboardPhase::SignedOut
        } else if self.vault.entries.is_empty() {
            DashboardPhase::Empty
        } else {
            DashboardPhase::Ready
        };
        let mut warnings = Vec::new();
        if phase == DashboardPhase::NoSnapshot {
            warnings.push("no local vault on disk; run login or sync".into());
        } else if phase == DashboardPhase::SignedOut {
            warnings.push("signed out; run login".into());
        } else if phase == DashboardPhase::Empty {
            warnings.push("vault is empty; run sync or add a login".into());
        }
        if !self.vault.pending.is_empty() {
            warnings.push(format!(
                "{} change{} waiting to sync",
                self.vault.pending.len(),
                plural(self.vault.pending.len())
            ));
        }
        if self.state.failures > 0 {
            warnings.push(format!(
                "{} failed push{}",
                self.state.failures,
                plural(self.state.failures as usize)
            ));
        }
        match self.last_sync() {
            None if phase != DashboardPhase::NoSnapshot => warnings.push("never synced".into()),
            Some(at) => {
                let age = now.signed_duration_since(at);
                if age.num_hours() >= 24 {
                    warnings.push(format!("snapshot is {}", relative(at, now)));
                }
            }
            None => {}
        }
        if self.vault.source == Source::Fixture {
            warnings.push("fixture data, not iCloud".into());
        }

        let mut recents: Vec<&Entry> = self
            .vault
            .entries
            .iter()
            .filter(|entry| !entry.is_placeholder() && entry.updated_at.is_some())
            .collect();
        recents.sort_by_key(|entry| std::cmp::Reverse(entry.updated_at));
        let recents = recents
            .into_iter()
            .take(6)
            .map(|entry| Row::from_entry(entry, Category::Logins))
            .collect();

        let mut activity = Vec::new();
        activity.push(match self.last_sync() {
            Some(at) => format!("last sync {}", relative(at, now)),
            None => "no sync yet".into(),
        });
        activity.push(format!(
            "{} items, {} pending",
            self.vault.entries.len(),
            self.vault.pending.len()
        ));
        if !self.vault.groups.is_empty() {
            let shared = self
                .vault
                .groups
                .iter()
                .filter(|group| group.shared)
                .count();
            activity.push(format!(
                "{} groups, {} shared",
                self.vault.groups.len(),
                shared
            ));
        }

        Dashboard {
            phase,
            account: self.account().map(str::to_string),
            last_sync: self.last_sync(),
            counts: vec![
                ("logins", self.vault.login_count()),
                ("notes", self.note_count()),
                ("wi-fi", self.vault.wifi_count()),
                ("passkeys", self.vault.passkey_count()),
                ("groups", self.vault.groups.len()),
                ("trash", self.vault.trash.len()),
                ("pending", self.vault.pending.len()),
            ],
            warnings,
            recents,
            activity,
        }
    }

    fn note_count(&self) -> usize {
        self.vault
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Note)
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardPhase {
    NoSnapshot,
    SignedOut,
    Empty,
    Ready,
}

pub struct Dashboard {
    pub phase: DashboardPhase,
    pub account: Option<String>,
    pub last_sync: Option<DateTime<Utc>>,
    pub counts: Vec<(&'static str, usize)>,
    pub warnings: Vec<String>,
    pub recents: Vec<Row>,
    pub activity: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    Logins,
    Notes,
    Wifi,
    Passkeys,
    Groups,
    Trash,
    Pending,
}

pub const CATEGORIES: [Category; 7] = [
    Category::Logins,
    Category::Notes,
    Category::Wifi,
    Category::Passkeys,
    Category::Groups,
    Category::Trash,
    Category::Pending,
];

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Logins => "Logins",
            Category::Notes => "Notes",
            Category::Wifi => "Wi-Fi",
            Category::Passkeys => "Passkeys",
            Category::Groups => "Groups",
            Category::Trash => "Trash",
            Category::Pending => "Pending",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Category::Logins => "logins",
            Category::Notes => "notes",
            Category::Wifi => "wifi",
            Category::Passkeys => "passkeys",
            Category::Groups => "groups",
            Category::Trash => "trash",
            Category::Pending => "pending",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        CATEGORIES
            .iter()
            .copied()
            .find(|category| category.key() == key)
    }

    pub fn index(self) -> usize {
        CATEGORIES
            .iter()
            .position(|category| *category == self)
            .unwrap_or(0)
    }

    pub fn count(self, view: &VaultView) -> usize {
        match self {
            Category::Logins => view.vault.login_count(),
            Category::Notes => view.note_count(),
            Category::Wifi => view.vault.wifi_count(),
            Category::Passkeys => view.vault.passkey_count(),
            Category::Groups => view.vault.groups.len(),
            Category::Trash => view.vault.trash.len(),
            Category::Pending => view.vault.pending.len(),
        }
    }

    pub fn rows(self, view: &VaultView, query: &str) -> Vec<Row> {
        let needle = query.trim().to_lowercase();
        let hit = |text: &str| needle.is_empty() || text.to_lowercase().contains(&needle);
        match self {
            Category::Groups => {
                let mut groups: Vec<Row> = view
                    .vault
                    .groups
                    .iter()
                    .filter(|group| hit(group.name.as_deref().unwrap_or(&group.id)))
                    .map(|group| Row::from_group(group, view))
                    .collect();
                groups.sort_by_key(|row| row.title.to_lowercase());
                groups
            }
            Category::Trash => {
                let mut rows: Vec<Row> = view
                    .vault
                    .trash
                    .iter()
                    .filter(|trash| {
                        hit(&trash.entry.display_name()) || trash.entry.matches(&needle)
                    })
                    .map(Row::from_trash)
                    .collect();
                rows.sort_by_key(|row| row.title.to_lowercase());
                rows
            }
            Category::Pending => {
                let mut rows: Vec<Row> = view
                    .vault
                    .pending
                    .iter()
                    .filter(|op| {
                        hit(&op.label) || hit(&op.item_name) || hit(&op.id) || hit(&op.zone)
                    })
                    .map(Row::from_pending)
                    .collect();
                rows.sort_by_key(|row| row.title.to_lowercase());
                rows
            }
            _ => {
                let mut entries: Vec<&Entry> = view
                    .vault
                    .entries
                    .iter()
                    .filter(|entry| self.holds(entry) && entry.matches(&needle))
                    .collect();
                entries.sort_by_key(|entry| entry.display_name().to_lowercase());
                entries
                    .into_iter()
                    .map(|entry| Row::from_entry(entry, self))
                    .collect()
            }
        }
    }

    fn holds(self, entry: &Entry) -> bool {
        match self {
            Category::Logins => entry.kind == EntryKind::Login && !entry.is_placeholder(),
            Category::Notes => entry.kind == EntryKind::Note,
            Category::Wifi => entry.kind == EntryKind::Wifi && !entry.is_placeholder(),
            Category::Passkeys => entry.kind == EntryKind::Passkey,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct Row {
    pub title: String,
    pub subtitle: String,
    pub trailing: String,
    pub source: RowSource,
}

#[derive(Clone)]
pub enum RowSource {
    Entry(Box<Entry>),
    Group(Box<Group>),
    Trash(Box<TrashEntry>),
    Pending(Box<PendingOp>),
}

impl Row {
    fn from_entry(entry: &Entry, category: Category) -> Self {
        let subtitle = entry
            .username
            .clone()
            .or_else(|| {
                let domain = entry.domain();
                (!domain.is_empty()).then_some(domain)
            })
            .unwrap_or_default();
        let trailing = entry
            .updated_at
            .map(|at| at.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        Self {
            title: entry.display_name(),
            subtitle,
            trailing,
            source: RowSource::Entry(Box::new(entry.clone())),
        }
        .with_category(category)
    }

    fn with_category(mut self, category: Category) -> Self {
        if matches!(self.source, RowSource::Entry(_)) {
            self.subtitle = match category {
                Category::Notes => self.subtitle,
                Category::Wifi => "network".to_string(),
                Category::Passkeys => "passkey".to_string(),
                _ => self.subtitle,
            };
        }
        self
    }

    fn from_group(group: &Group, view: &VaultView) -> Self {
        let items = view
            .vault
            .entries
            .iter()
            .filter(|entry| entry.group.as_deref() == Some(group.id.as_str()))
            .count();
        Self {
            title: group.name.clone().unwrap_or_else(|| group.id.clone()),
            subtitle: if group.shared { "shared" } else { "owned" }.to_string(),
            trailing: format!("{items} items"),
            source: RowSource::Group(Box::new(group.clone())),
        }
    }

    fn from_trash(trash: &TrashEntry) -> Self {
        Self {
            title: trash.entry.display_name(),
            subtitle: trash
                .entry
                .username
                .clone()
                .or_else(|| {
                    let domain = trash.entry.domain();
                    (!domain.is_empty()).then_some(domain)
                })
                .unwrap_or_default(),
            trailing: trash
                .deleted_at
                .map(|at| at.format("%Y-%m-%d").to_string())
                .unwrap_or_default(),
            source: RowSource::Trash(Box::new(trash.clone())),
        }
    }

    fn from_pending(op: &PendingOp) -> Self {
        let title = if op.label.is_empty() {
            op.item_name.clone()
        } else {
            op.label.clone()
        };
        Self {
            title,
            subtitle: format!("{:?}", op.kind).to_lowercase(),
            trailing: if op.blocked.is_some() {
                "blocked".to_string()
            } else if op.attempts > 0 {
                format!("{} tries", op.attempts)
            } else {
                "queued".to_string()
            },
            source: RowSource::Pending(Box::new(op.clone())),
        }
    }

    pub fn detail_rows(&self, now: DateTime<Utc>, reveal: bool) -> Vec<(String, String)> {
        match &self.source {
            RowSource::Entry(entry) => entry_details(entry, now, reveal),
            RowSource::Group(group) => vec![
                ("Name".into(), group.name.clone().unwrap_or_default()),
                ("Zone".into(), group.id.clone()),
                (
                    "Kind".into(),
                    if group.shared { "shared" } else { "owned" }.into(),
                ),
                ("Items".into(), self.trailing.clone()),
            ],
            RowSource::Trash(trash) => {
                let mut rows = vec![(
                    "Deleted".into(),
                    trash
                        .deleted_at
                        .map(|at| at.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "unknown".into()),
                )];
                rows.extend(entry_details(&trash.entry, now, reveal));
                rows
            }
            RowSource::Pending(op) => vec![
                ("Change".into(), format!("{:?}", op.kind).to_lowercase()),
                ("Item".into(), op.item_name.clone()),
                ("Zone".into(), op.zone.clone()),
                ("Attempts".into(), op.attempts.to_string()),
                (
                    "Next try".into(),
                    op.next_attempt.clone().unwrap_or_else(|| "now".into()),
                ),
                (
                    "Blocked".into(),
                    op.blocked.clone().unwrap_or_else(|| "no".into()),
                ),
                ("ID".into(), op.id.clone()),
            ],
        }
    }
}

fn entry_details(entry: &Entry, now: DateTime<Utc>, reveal: bool) -> Vec<(String, String)> {
    let password = if reveal {
        entry.password.clone().unwrap_or_default()
    } else {
        mask(entry.password.as_deref())
    };
    let mut rows = vec![
        ("Name".into(), entry.display_name()),
        ("Kind".into(), kind_label(entry.kind).into()),
        (
            "Username".into(),
            entry.username.clone().unwrap_or_default(),
        ),
        ("Password".into(), password),
    ];
    if let Some(totp) = &entry.totp {
        let code = crate::totp::generate(totp, std::time::SystemTime::now())
            .unwrap_or_else(|_| "unavailable".into());
        let left = crate::totp::seconds_remaining(totp, std::time::SystemTime::now());
        rows.push(("One-time code".into(), format!("{code}  {left}s")));
    }
    if let Some(url) = &entry.url {
        rows.push(("URL".into(), url.clone()));
    }
    if let Some(group) = &entry.group {
        rows.push(("Group".into(), group.clone()));
    }
    if !entry.sites.is_empty() {
        rows.push(("Sites".into(), entry.sites.join(", ")));
    }
    if let Some(at) = entry.updated_at {
        rows.push((
            "Updated".into(),
            format!("{} ({})", at.format("%Y-%m-%d %H:%M"), relative(at, now)),
        ));
    }
    if let Some(notes) = &entry.notes {
        if !notes.is_empty() {
            rows.push(("Notes".into(), notes.clone()));
        }
    }
    rows
}

pub fn kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Login => "login",
        EntryKind::Note => "note",
        EntryKind::Passkey => "passkey",
        EntryKind::Card => "card",
        EntryKind::Wifi => "wi-fi",
        EntryKind::Other => "other",
    }
}

pub fn mask(secret: Option<&str>) -> String {
    match secret {
        Some(value) if !value.is_empty() => "•".repeat(value.chars().count().clamp(8, 24)),
        _ => String::new(),
    }
}

pub fn relative(when: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let seconds = now.signed_duration_since(when).num_seconds().max(0);
    match seconds {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Algorithm, Totp};

    fn entry(id: &str, name: &str, kind: EntryKind) -> Entry {
        Entry {
            id: id.into(),
            kind,
            title: Some(name.into()),
            username: Some("alice".into()),
            password: Some("hunter2".into()),
            updated_at: Some(Utc::now()),
            ..Entry::default()
        }
    }

    fn test_paths() -> crate::config::Paths {
        let dir = tempfile::tempdir().unwrap().keep();
        crate::config::Paths {
            config_dir: dir.join("config"),
            config_file: dir.join("config/config.toml"),
            data_dir: dir.join("data"),
            snapshot_file: dir.join("data/snapshot.bin"),
            state_dir: dir.join("state"),
            state_file: dir.join("state/state.json"),
        }
    }

    fn view() -> VaultView {
        VaultView {
            vault: Vault {
                entries: vec![
                    entry("1", "Example", EntryKind::Login),
                    entry("2", "Recovery", EntryKind::Note),
                    entry("3", "Home", EntryKind::Wifi),
                    entry("4", "Passkey", EntryKind::Passkey),
                ],
                ..Vault::default()
            },
            state: State::default(),
            config: Config::default(),
            paths: test_paths(),
            has_snapshot: true,
        }
    }

    #[test]
    fn categories_hold_their_kinds() {
        let view = view();
        assert_eq!(Category::Logins.rows(&view, "").len(), 1);
        assert_eq!(Category::Notes.rows(&view, "").len(), 1);
        assert_eq!(Category::Wifi.rows(&view, "").len(), 1);
        assert_eq!(Category::Passkeys.rows(&view, "").len(), 1);
    }

    #[test]
    fn query_filters_rows() {
        let view = view();
        assert_eq!(Category::Logins.rows(&view, "exam").len(), 1);
        assert_eq!(Category::Logins.rows(&view, "nothing").len(), 0);
    }

    #[test]
    fn masks_secrets() {
        assert_eq!(mask(Some("short")).chars().count(), 8);
        assert_eq!(mask(None), "");
    }

    #[test]
    fn shows_a_live_code() {
        let mut entry = entry("1", "Example", EntryKind::Login);
        entry.totp = Some(Totp {
            secret: "JBSWY3DPEHPK3PXP".into(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account_name: None,
        });
        let details = entry_details(&entry, Utc::now(), false);
        let code = details
            .iter()
            .find(|(label, _)| label == "One-time code")
            .expect("code row");
        assert!(code.1.len() >= 6);
    }
}
