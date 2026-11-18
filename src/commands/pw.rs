use crate::commands::login_result;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::model::{Entry, EntryKind};
use crate::output::{self, Style};
use crate::vault;

pub fn list(
    paths: &Paths,
    config: &mut Config,
    query: Option<&str>,
    personal: bool,
    group: Option<&str>,
    style: Style,
) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let group = group.map(|query| resolve_group(&vault, query));
    let mut entries: Vec<_> = vault
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Login && !entry.is_placeholder())
        .filter(|entry| query.is_none_or(|value| entry.matches(value)))
        .filter(|entry| in_scope(entry, personal, group.as_deref()))
        .collect();
    entries.sort_by_key(|entry| entry.display_name().to_lowercase());

    if style.json {
        let data = entries
            .iter()
            .map(|entry| login_result(entry, false))
            .collect::<Vec<_>>();
        output::print_json(&output::success(data.into()));
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
                entry.display_name(),
                entry.username.clone().unwrap_or_default(),
                entry.domain(),
                entry
                    .group
                    .as_deref()
                    .map(|id| names.get(id).copied().unwrap_or(id).to_string())
                    .unwrap_or_default(),
            ]
        })
        .collect::<Vec<_>>();
    output::print_table_opts(
        &["NAME", "USERNAME", "DOMAIN", "GROUP"],
        &rows,
        style.no_header,
        style.wide,
    );
    Ok(())
}

pub fn wifi(paths: &Paths, config: &mut Config, query: Option<&str>, style: Style) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let mut entries: Vec<_> = vault
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Wifi && !entry.is_placeholder())
        .filter(|entry| query.is_none_or(|value| entry.matches(value)))
        .collect();
    entries.sort_by_key(|entry| entry.display_name().to_lowercase());

    if style.json {
        let data = entries
            .iter()
            .map(|entry| login_result(entry, false))
            .collect::<Vec<_>>();
        output::print_json(&output::success(data.into()));
        return Ok(());
    }

    let rows = entries
        .iter()
        .map(|entry| vec![entry.display_name()])
        .collect::<Vec<_>>();
    output::print_table_opts(&["NETWORK"], &rows, style.no_header, style.wide);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn get(
    paths: &Paths,
    config: &mut Config,
    query: &str,
    username: Option<&str>,
    group: Option<&str>,
    personal: bool,
    password_only: bool,
    style: Style,
) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let group = group.map(|query| resolve_group(&vault, query));
    let mut entries: Vec<_> = vault
        .entries
        .iter()
        .filter(|entry| matches!(entry.kind, EntryKind::Login | EntryKind::Wifi))
        .filter(|entry| entry.matches(query))
        .filter(|entry| in_scope(entry, personal, group.as_deref()))
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
            Some(name) => format!("no entry for {query} with username {name}"),
            None => format!("no entry matches {query}"),
        }));
    }

    entries.sort_by(|left, right| {
        let left_exact = exact(left, query);
        let right_exact = exact(right, query);
        right_exact.cmp(&left_exact).then_with(|| {
            left.display_name()
                .to_lowercase()
                .cmp(&right.display_name().to_lowercase())
        })
    });

    if style.json {
        let data = entries
            .iter()
            .map(|entry| login_result(entry, true))
            .collect::<Vec<_>>();
        output::print_json(&output::success(data.into()));
        return Ok(());
    }

    if password_only {
        for entry in &entries {
            println!("{}", entry.password.clone().unwrap_or_default());
        }
        return Ok(());
    }

    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            println!();
        }
        let mut rows = vec![("Name", entry.display_name())];
        if let Some(username) = entry.username.clone() {
            rows.push(("Username", username));
        }
        if entry.kind == EntryKind::Wifi {
            rows.push(("Network", entry.domain()));
        } else {
            rows.push(("Domain", entry.domain()));
        }
        rows.push((
            "Password",
            entry
                .password
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "(none)".into()),
        ));
        output::print_block(&rows);
    }
    Ok(())
}

fn exact(entry: &Entry, query: &str) -> bool {
    entry.name().eq_ignore_ascii_case(query)
        || entry.domain().eq_ignore_ascii_case(query)
        || entry
            .username
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(query))
}

/// Accept a group id, a unique id prefix, or the display name.
fn resolve_group(vault: &crate::model::Vault, query: &str) -> String {
    vault
        .groups
        .iter()
        .find(|group| group.id == query)
        .or_else(|| {
            vault.groups.iter().find(|group| {
                group
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(query))
            })
        })
        .or_else(|| {
            vault
                .groups
                .iter()
                .find(|group| group.id.starts_with(query))
        })
        .map(|group| group.id.clone())
        .unwrap_or_else(|| query.to_string())
}

fn in_scope(entry: &Entry, personal: bool, group: Option<&str>) -> bool {
    if personal && entry.group.is_some() {
        return false;
    }
    match group {
        Some(group) => entry
            .group
            .as_deref()
            .is_some_and(|value| value == group || value.starts_with(group)),
        None => true,
    }
}
