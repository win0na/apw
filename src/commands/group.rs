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
