//! `apw group` — owner-only password groups.
//!
//! A create journals its zone before the first network call, so a failure can
//! resume the same zone instead of leaving an orphan behind. A delete only
//! touches a zone the journal says this tool created, and never runs as part of
//! a failure path.

use serde_json::json;

use crate::commands::join::block_on;
use crate::commands::sync;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::group_write;
use crate::groups;
use crate::model::{GroupOp, GroupPhase};
use crate::output::{self, Style};
use crate::vault;

/// Print the zone and name of the created group.
pub fn create(
    paths: &Paths,
    config: &mut Config,
    name: &str,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Invalid("a group name cannot be empty".into()));
    }

    let mut working = vault::load(paths, config)?;
    let zone = plan_create(&mut working.group_ops, name, !dry_run)?;

    if dry_run {
        if style.json {
            output::print_json(&output::success(json!({
                "dry_run": true,
                "zone": zone,
                "name": name,
            })));
        } else {
            println!("would create {zone} {name}");
        }
        return Ok(());
    }

    // The journal must exist before the network work: a create that dies after
    // `zone/save` resumes this zone on the next run.
    vault::save(paths, config, &working)?;

    let session = sync::group_session(paths, config)?;
    block_on(group_write::create(
        &session.gateway,
        &session.service_keys,
        &zone,
        name,
    ))?;

    if let Some(op) = working.group_ops.iter_mut().find(|op| op.zone == zone) {
        op.phase = GroupPhase::Shared;
    }
    working.session = Some(session.session);
    vault::save(paths, config, &working)?;

    if style.json {
        output::print_json(&output::success(json!({
            "zone": zone,
            "name": name,
        })));
    } else {
        println!("created {zone} {name}");
    }
    Ok(())
}

/// Delete one zone this tool created.
pub fn delete(
    paths: &Paths,
    config: &mut Config,
    target: &str,
    yes: bool,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    if !yes && !dry_run {
        return Err(Error::Invalid(
            "refusing to delete a group without --yes".into(),
        ));
    }

    let mut working = vault::load(paths, config)?;
    // A successful create may have dropped its journal entry; a zone still
    // counts as ours when its protection opens with this account's key.
    let journaled = working
        .group_ops
        .iter()
        .position(|op| matches_target(op, target));
    let (index, op, opened) = match journaled {
        Some(index) => (Some(index), working.group_ops[index].clone(), None),
        None => {
            let zone = resolve_zone(&working, target);
            let session = sync::group_session(paths, config)?;
            let owner = session.gateway.user_id().to_string();
            let info = block_on(session.gateway.zone_retrieve(&zone, &owner)).map_err(|error| {
                if crate::group_write::missing_zone(&error) {
                    Error::NoResults(format!("no zone named {zone}"))
                } else {
                    error
                }
            })?;
            let der = info
                .protection_info
                .as_deref()
                .ok_or_else(|| Error::Message(format!("zone {zone} has no protection info")))?;
            let protection = crate::pcs::Protection::parse(der)?;
            let ours = session.service_keys.iter().any(|key| {
                protection
                    .decode(std::slice::from_ref(&key.secret), false)
                    .is_ok()
            });
            if !ours {
                return Err(Error::NoResults(format!(
                    "zone {zone} does not open with this account's key; refusing to delete it"
                )));
            }
            (
                None,
                crate::model::GroupOp {
                    zone: zone.clone(),
                    name: target.to_string(),
                    phase: crate::model::GroupPhase::Shared,
                },
                Some(session),
            )
        }
    };

    if dry_run {
        if style.json {
            output::print_json(&output::success(json!({
                "dry_run": true,
                "zone": op.zone,
                "name": op.name,
            })));
        } else {
            println!("would delete {} {}", op.zone, op.name);
        }
        return Ok(());
    }

    let session = match opened {
        Some(session) => session,
        None => sync::group_session(paths, config)?,
    };
    block_on(session.gateway.delete_zone(&op.zone))?;

    let id = op.zone.trim_start_matches("group-").to_string();
    if let Some(index) = index {
        working.group_ops.remove(index);
    }
    working.groups.retain(|group| group.id != id);
    // Shared entries read from the deleted zone must not survive it.
    working
        .entries
        .retain(|entry| entry.group.as_deref() != Some(id.as_str()));
    working.session = Some(session.session);
    vault::save(paths, config, &working)?;

    if style.json {
        output::print_json(&output::success(json!({
            "deleted": op.zone,
            "name": op.name,
        })));
    } else {
        println!("deleted {} {}", op.zone, op.name);
    }
    Ok(())
}

/// Add one personal login to a group.
///
/// The item is sealed with the zone's record key, so the entries only appear in
/// the local snapshot after the next `apw sync` reads them back.
pub fn add(
    paths: &Paths,
    config: &mut Config,
    group: &str,
    query: Option<&str>,
    id: Option<&str>,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    let working = vault::load(paths, config)?;
    let zone = resolve_group_zone(&working, group)?;
    let entry = select_personal_login(&working, query, id)?;

    if dry_run {
        if style.json {
            output::print_json(&output::success(json!({
                "dry_run": true,
                "zone": zone,
                "id": entry.id,
                "name": entry.display_name(),
            })));
        } else {
            println!(
                "would add {} ({}) to {zone}",
                entry.display_name(),
                entry.id
            );
        }
        return Ok(());
    }

    let session = sync::group_session(paths, config)?;
    let owner = session.gateway.user_id().to_string();
    let keys = block_on(groups::zone_keys(
        &session.gateway,
        &zone,
        &owner,
        &session.service_keys,
    ))?;
    let record = block_on(group_write::add_item(
        &session.gateway,
        &zone,
        &keys.record_key,
        keys.record_tag.as_deref(),
        entry,
        chrono::Utc::now(),
    ))?;

    if style.json {
        output::print_json(&output::success(json!({
            "item": record,
            "zone": zone,
            "name": entry.display_name(),
        })));
    } else {
        println!("added {record} to {zone}");
    }
    Ok(())
}

/// Delete one shared item from a group.
pub fn remove(
    paths: &Paths,
    config: &mut Config,
    group: &str,
    item: &str,
    yes: bool,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    if !yes && !dry_run {
        return Err(Error::Invalid(
            "refusing to remove a shared item without --yes".into(),
        ));
    }

    let working = vault::load(paths, config)?;
    let zone = resolve_group_zone(&working, group)?;
    let record = resolve_item(&working, &zone, item)?;

    if dry_run {
        if style.json {
            output::print_json(&output::success(json!({
                "dry_run": true,
                "zone": zone,
                "item": record,
            })));
        } else {
            println!("would remove {record} from {zone}");
        }
        return Ok(());
    }

    let session = sync::group_session(paths, config)?;
    let owner = session.gateway.user_id().to_string();
    let keys = block_on(groups::zone_keys(
        &session.gateway,
        &zone,
        &owner,
        &session.service_keys,
    ))?;
    block_on(group_write::remove_item(
        &session.gateway,
        &zone,
        keys.record_tag.as_deref(),
        &record,
    ))?;

    if style.json {
        output::print_json(&output::success(json!({
            "removed": record,
            "zone": zone,
        })));
    } else {
        println!("removed {record} from {zone}");
    }
    Ok(())
}

/// List the group zones this account owns.
pub fn list(paths: &Paths, config: &mut Config, style: Style) -> Result<()> {
    let working = vault::load(paths, config)?;
    let session = sync::group_session(paths, config)?;
    let mut rows = block_on(groups::summaries(&session.gateway, &session.service_keys))?;

    // A zone whose protection does not open yet still has a name if this tool
    // journaled one.
    for row in &mut rows {
        if row.name.is_none() {
            row.name = working
                .group_ops
                .iter()
                .find(|op| op.zone == row.zone)
                .map(|op| op.name.clone());
        }
    }
    rows.sort_by(|left, right| left.zone.cmp(&right.zone));

    if style.json {
        let data: Vec<_> = rows
            .iter()
            .map(|row| {
                json!({
                    "zone": row.zone,
                    "name": row.name.clone().unwrap_or_default(),
                    "owner": row.owner,
                    "members": row.participants,
                })
            })
            .collect();
        output::print_json(&output::success(json!(data)));
        return Ok(());
    }

    if rows.is_empty() {
        println!("no groups");
        return Ok(());
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.zone.clone(),
                row.name.clone().unwrap_or_else(|| "-".into()),
                row.owner.clone(),
                row.participants.to_string(),
            ]
        })
        .collect();
    output::print_table_opts(
        &["ZONE", "NAME", "OWNER", "MEMBERS"],
        &table,
        style.no_header,
        style.wide,
    );
    Ok(())
}

/// The zone a create targets.
///
/// A `Created` entry for the same name is resumed, because a run that failed
/// after the zone save must not leave a second zone behind. `journal` false is
/// the dry-run path: it names a fresh zone and records nothing.
pub(crate) fn plan_create(ops: &mut Vec<GroupOp>, name: &str, journal: bool) -> Result<String> {
    if let Some(op) = ops
        .iter()
        .find(|op| op.name == name && op.phase == GroupPhase::Shared)
    {
        return Err(Error::Invalid(format!(
            "a group named {name:?} already exists (zone {})",
            op.zone
        )));
    }
    if let Some(op) = ops
        .iter()
        .find(|op| op.name == name && op.phase == GroupPhase::Created)
    {
        return Ok(op.zone.clone());
    }

    let zone = format!("group-{}", crate::model::record_name());
    if journal {
        ops.push(GroupOp {
            zone: zone.clone(),
            name: name.to_string(),
            phase: GroupPhase::Created,
        });
    }
    Ok(zone)
}

/// A delete accepts the zone, the bare UUID, or the group's name.
fn matches_target(op: &GroupOp, target: &str) -> bool {
    op.name == target
        || op.zone.eq_ignore_ascii_case(target)
        || op
            .zone
            .trim_start_matches("group-")
            .eq_ignore_ascii_case(target)
}

/// The zone a group command targets: a journaled name, a display name from the
/// last sync, a zone name, or a bare UUID.
fn resolve_group_zone(vault: &crate::model::Vault, target: &str) -> Result<String> {
    if let Some(op) = vault.group_ops.iter().find(|op| matches_target(op, target)) {
        return Ok(op.zone.clone());
    }
    let zone = resolve_zone(vault, target);
    if zone.starts_with("group-") {
        return Ok(zone);
    }
    Err(Error::NoResults(format!(
        "no group {target:?}; pass a group name, zone, or UUID"
    )))
}

/// Pick exactly one personal login from the vault.
///
/// A query that also matches a note, a Wi-Fi network, a passkey, or an entry
/// already in a group is refused rather than guessed around: adding the wrong
/// item to a shared group is not recoverable by the next sync.
fn select_personal_login<'a>(
    vault: &'a crate::model::Vault,
    query: Option<&str>,
    id: Option<&str>,
) -> Result<&'a crate::model::Entry> {
    match (query, id) {
        (None, None) => Err(Error::Invalid(
            "pass a query or --id to pick the login to add".into(),
        )),
        (Some(_), Some(_)) => Err(Error::Invalid(
            "pass either a query or --id, not both".into(),
        )),
        (None, Some(id)) => {
            let entry = vault
                .entries
                .iter()
                .find(|entry| entry.id == id)
                .ok_or_else(|| Error::NoResults(format!("no entry with id {id:?}")))?;
            ensure_personal_login(entry)?;
            Ok(entry)
        }
        (Some(query), None) => {
            let matches: Vec<&crate::model::Entry> = vault
                .entries
                .iter()
                .filter(|entry| entry.matches(query))
                .collect();
            if matches.is_empty() {
                return Err(Error::NoResults(format!("no login matches {query:?}")));
            }
            for entry in &matches {
                ensure_personal_login(entry)?;
            }
            match matches.as_slice() {
                [single] => Ok(single),
                _ => Err(Error::Invalid(format!(
                    "{} entries match {query:?}; narrow the query or use --id",
                    matches.len()
                ))),
            }
        }
    }
}

/// Refuse anything that is not a personal login.
fn ensure_personal_login(entry: &crate::model::Entry) -> Result<()> {
    if entry.kind != crate::model::EntryKind::Login {
        return Err(Error::Invalid(format!(
            "{} is a {}; only logins can be added to a group",
            entry.display_name(),
            kind_name(entry.kind)
        )));
    }
    if entry.group.is_some() {
        return Err(Error::Invalid(format!(
            "{} is already in a group; only a personal login can be added",
            entry.display_name()
        )));
    }
    Ok(())
}

fn kind_name(kind: crate::model::EntryKind) -> &'static str {
    use crate::model::EntryKind;
    match kind {
        EntryKind::Login => "login",
        EntryKind::Note => "note",
        EntryKind::Passkey => "passkey",
        EntryKind::Card => "card",
        EntryKind::Wifi => "Wi-Fi network",
        EntryKind::Other => "item",
    }
}

/// Resolve the record to delete: a record name, or an entry id or query from
/// the last sync that belongs to this group.
fn resolve_item(vault: &crate::model::Vault, zone: &str, item: &str) -> Result<String> {
    if item.starts_with("item-") {
        return Ok(item.to_string());
    }
    let group = zone.trim_start_matches("group-");
    let candidates: Vec<&crate::model::Entry> = vault
        .entries
        .iter()
        .filter(|entry| entry.group.as_deref() == Some(group))
        .collect();
    if let Some(found) = candidates.iter().find(|entry| entry.id == item) {
        return Ok(found.id.clone());
    }
    let matches: Vec<&crate::model::Entry> = candidates
        .into_iter()
        .filter(|entry| entry.matches(item))
        .collect();
    match matches.as_slice() {
        [single] => Ok(single.id.clone()),
        [] => Err(Error::NoResults(format!(
            "no item {item:?} in {zone}; run `apw sync` or pass the item record name"
        ))),
        _ => Err(Error::Invalid(format!(
            "{} items match {item:?}; pass the item record name",
            matches.len()
        ))),
    }
}

/// Accept a zone name, a bare UUID, or a group name from the vault.
fn resolve_zone(vault: &crate::model::Vault, target: &str) -> String {
    if target.starts_with("group-") {
        return target.to_string();
    }
    if let Some(group) = vault
        .groups
        .iter()
        .find(|group| group.name.as_deref() == Some(target))
    {
        return format!("group-{}", group.id);
    }
    if target.len() == 36 && target.chars().filter(|ch| *ch == '-').count() == 4 {
        return format!("group-{}", target.to_uppercase());
    }
    target.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dry_run_journals_nothing() {
        let mut ops = Vec::new();
        let zone = plan_create(&mut ops, "Family", false).unwrap();
        assert!(ops.is_empty(), "dry run leaves the journal empty");
        assert!(zone.starts_with("group-"));
        assert_eq!(zone.len(), "group-".len() + 36);

        let zone = plan_create(&mut ops, "Family", true).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].zone, zone);
        assert_eq!(ops[0].phase, GroupPhase::Created);
    }

    #[test]
    fn an_interrupted_create_resumes_its_zone() {
        let mut ops = vec![GroupOp {
            zone: "group-AAAA".into(),
            name: "Family".into(),
            phase: GroupPhase::Created,
        }];
        assert_eq!(plan_create(&mut ops, "Family", true).unwrap(), "group-AAAA");
        assert_eq!(ops.len(), 1, "no second zone is journaled");

        ops[0].phase = GroupPhase::Shared;
        assert!(plan_create(&mut ops, "Family", true).is_err());
        assert!(plan_create(&mut ops, "Work", true)
            .unwrap()
            .starts_with("group-"));
    }

    fn login(id: &str, site: &str, user: &str) -> crate::model::Entry {
        crate::model::Entry {
            id: id.into(),
            kind: crate::model::EntryKind::Login,
            sites: vec![site.into()],
            username: Some(user.into()),
            password: Some("secret".into()),
            ..crate::model::Entry::default()
        }
    }

    fn test_vault() -> crate::model::Vault {
        let entries = vec![
            login("login-1", "example.com", "alice"),
            login("login-2", "example.com", "bob"),
            crate::model::Entry {
                id: "note-1".into(),
                kind: crate::model::EntryKind::Note,
                title: Some("Secure Note".into()),
                notes: Some("body".into()),
                ..crate::model::Entry::default()
            },
            crate::model::Entry {
                id: "wifi-1".into(),
                kind: crate::model::EntryKind::Wifi,
                title: Some("HomeNet".into()),
                sites: vec!["HomeNet".into()],
                ..crate::model::Entry::default()
            },
            crate::model::Entry {
                group: Some("1111".into()),
                ..login("shared-1", "shared.example", "carol")
            },
        ];
        crate::model::Vault {
            entries,
            groups: vec![crate::model::Group {
                id: "1111".into(),
                name: Some("Family".into()),
                shared: true,
            }],
            group_ops: vec![GroupOp {
                zone: "group-2222".into(),
                name: "Work".into(),
                phase: GroupPhase::Shared,
            }],
            ..crate::model::Vault::default()
        }
    }

    #[test]
    fn a_note_or_wifi_network_is_refused() {
        let vault = test_vault();
        let error = select_personal_login(&vault, Some("Secure Note"), None).unwrap_err();
        assert!(error.to_string().contains("note"), "{error}");

        let error = select_personal_login(&vault, Some("HomeNet"), None).unwrap_err();
        assert!(error.to_string().contains("Wi-Fi"), "{error}");
    }

    #[test]
    fn an_entry_already_in_a_group_is_refused() {
        let vault = test_vault();
        let error = select_personal_login(&vault, Some("shared.example"), None).unwrap_err();
        assert!(error.to_string().contains("already in a group"), "{error}");
    }

    #[test]
    fn an_ambiguous_query_is_refused() {
        let vault = test_vault();
        let error = select_personal_login(&vault, Some("example.com"), None).unwrap_err();
        assert!(error.to_string().contains("2 entries match"), "{error}");
    }

    #[test]
    fn exactly_one_personal_login_is_selected() {
        let vault = test_vault();
        let entry = select_personal_login(&vault, Some("alice"), None).unwrap();
        assert_eq!(entry.id, "login-1");

        let entry = select_personal_login(&vault, None, Some("login-2")).unwrap();
        assert_eq!(entry.id, "login-2");
        assert_eq!(entry.username.as_deref(), Some("bob"));

        assert!(select_personal_login(&vault, None, Some("missing")).is_err());
        assert!(select_personal_login(&vault, None, None).is_err());
        assert!(select_personal_login(&vault, Some("alice"), Some("login-1")).is_err());
    }

    #[test]
    fn a_group_resolves_by_name_zone_or_uuid() {
        let vault = test_vault();
        assert_eq!(resolve_group_zone(&vault, "Work").unwrap(), "group-2222");
        assert_eq!(resolve_group_zone(&vault, "Family").unwrap(), "group-1111");
        assert_eq!(
            resolve_group_zone(&vault, "group-2222").unwrap(),
            "group-2222"
        );
        assert!(
            resolve_group_zone(&vault, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0000")
                .unwrap_err()
                .to_string()
                .contains("no group")
        );
    }

    #[test]
    fn a_remove_target_resolves_a_record_name_or_a_group_entry() {
        let mut vault = test_vault();
        vault.entries.push(crate::model::Entry {
            group: Some("2222".into()),
            ..login("item-ONE", "work.example", "dave")
        });
        let zone = "group-2222";

        assert_eq!(resolve_item(&vault, zone, "item-XYZ").unwrap(), "item-XYZ");
        assert_eq!(resolve_item(&vault, zone, "item-ONE").unwrap(), "item-ONE");
        assert_eq!(
            resolve_item(&vault, zone, "work.example").unwrap(),
            "item-ONE"
        );
        let error = resolve_item(&vault, zone, "nothing-here").unwrap_err();
        assert!(error.to_string().contains("no item"), "{error}");
        // A personal entry is not in the group and must not be deleted from it.
        assert!(resolve_item(&vault, zone, "login-1").is_err());
    }

    #[test]
    fn delete_matches_the_zone_the_uuid_or_the_name() {
        let op = GroupOp {
            zone: "group-AAAA-BBBB".into(),
            name: "Family".into(),
            phase: GroupPhase::Shared,
        };
        assert!(matches_target(&op, "group-AAAA-BBBB"));
        assert!(matches_target(&op, "group-aaaa-bbbb"));
        assert!(matches_target(&op, "AAAA-BBBB"));
        assert!(matches_target(&op, "Family"));
        assert!(!matches_target(&op, "Other"));
    }
}
