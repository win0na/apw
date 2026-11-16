use crate::commands::login_result;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::model::EntryKind;
use crate::output;
use crate::vault;

pub fn list(
    paths: &Paths,
    config: &mut Config,
    query: Option<&str>,
    personal: bool,
    group: Option<&str>,
    json: bool,
) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let entries: Vec<_> = vault
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Login)
        .filter(|entry| query.is_none_or(|value| entry.matches(value)))
        .filter(|entry| !personal || entry.group.is_none())
        .filter(|entry| match group {
            Some(group) => entry
                .group
                .as_deref()
                .is_some_and(|value| value == group || value.starts_with(group)),
            None => true,
        })
        .collect();

    if output::use_json(json) {
        let results = entries
            .iter()
            .map(|entry| login_result(entry, false))
            .collect::<Vec<_>>();
        output::print_json(&output::success(results.into()));
        return Ok(());
    }

    let names: std::collections::HashMap<&str, &str> = vault
        .groups
        .iter()
        .map(|group| (group.id.as_str(), group.name.as_deref().unwrap_or("")))
        .collect();
    let rows = entries
        .iter()
        .map(|entry| {
            vec![
                entry.domain(),
                entry.username.clone().unwrap_or_default(),
                entry.title.clone().unwrap_or_default(),
                entry
                    .group
                    .as_deref()
                    .map(|id| names.get(id).copied().unwrap_or(id).to_string())
                    .unwrap_or_default(),
            ]
        })
        .collect::<Vec<_>>();
    output::print_table(&["DOMAIN", "USERNAME", "TITLE", "GROUP"], &rows);
    Ok(())
}

pub fn get(
    paths: &Paths,
    config: &mut Config,
    query: &str,
    username: Option<&str>,
    json: bool,
) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let entries: Vec<_> = vault
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Login)
        .filter(|entry| entry.matches(query))
        .filter(|entry| match username {
            Some(name) => entry
                .username
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(name)),
            None => true,
        })
        .collect();

    if entries.is_empty() {
        return Err(Error::NoResults(match username {
            Some(name) => format!("no login for {query} with username {name}"),
            None => format!("no login matches {query}"),
        }));
    }

    if output::use_json(json) {
        let results = entries
            .iter()
            .map(|entry| login_result(entry, true))
            .collect::<Vec<_>>();
        output::print_json(&output::success(results.into()));
        return Ok(());
    }

    for entry in entries {
        println!(
            "{}\t{}\t{}",
            entry.domain(),
            entry.username.clone().unwrap_or_default(),
            entry.password.clone().unwrap_or_default()
        );
    }
    Ok(())
}
