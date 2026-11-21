//! `apw group` — items in existing password groups.
//!
//! A group zone is created and deleted on an Apple device. Writing one over raw
//! CloudKit would make a zone Passwords.app never lists, so this surface only
//! lists the groups the account owns and moves items into and out of one.

use serde_json::json;

use crate::commands::join::block_on;
use crate::commands::sync;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::group_write;
use crate::groups;
use crate::output::{self, Style};
use crate::vault;

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
    // An unnamed zone with no participants is a leftover from an interrupted
    // create; it is inert and has nothing to show.
    rows.retain(|row| row.name.is_some() || row.participants > 0);
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

/// Show one group and every item the last sync placed in it.
///
/// Reads the snapshot, so it works offline and shows the same view `list
/// --group` filters, including notes and passkeys that `list` leaves out.
pub fn show(paths: &Paths, config: &mut Config, group: &str, style: Style) -> Result<()> {
    let working = vault::load(paths, config)?;
    let zone = resolve_group_zone(&working, group)?;
    let id = zone.trim_start_matches("group-");
    let name = working
        .groups
        .iter()
        .find(|found| found.id == id)
        .and_then(|found| found.name.clone())
        .or_else(|| {
            working
                .group_ops
                .iter()
                .find(|op| op.zone == zone)
                .map(|op| op.name.clone())
        });
    let mut entries: Vec<&crate::model::Entry> = working
        .entries
        .iter()
        .filter(|entry| entry.group.as_deref() == Some(id))
        .collect();
    entries.sort_by_key(|entry| entry.display_name().to_lowercase());

    if style.json {
        let items = entries
            .iter()
            .map(|entry| {
                let mut item = crate::commands::login_result(entry, false);
                item.as_object_mut()
                    .expect("object")
                    .insert("kind".into(), json!(kind_name(entry.kind)));
                item
            })
            .collect::<Vec<_>>();
        output::print_json(&output::success(json!({
            "zone": zone,
            "name": name,
            "items": items,
        })));
        return Ok(());
    }

    match &name {
        Some(name) => println!("{name} ({zone})"),
        None => println!("{zone}"),
    }
    if entries.is_empty() {
        println!("no items; run `apw sync` if the group changed");
        return Ok(());
    }
    let rows = entries
        .iter()
        .map(|entry| {
            vec![
                entry.display_name(),
                entry.username.clone().unwrap_or_default(),
                entry.domain(),
                kind_name(entry.kind).to_string(),
            ]
        })
        .collect::<Vec<_>>();
    output::print_table_opts(
        &["NAME", "USERNAME", "SITE", "KIND"],
        &rows,
        style.no_header,
        style.wide,
    );
    Ok(())
}

/// The zone a group command targets: a display name from the last sync, a zone
/// name, or a bare UUID.
fn resolve_group_zone(vault: &crate::model::Vault, target: &str) -> Result<String> {
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
}
