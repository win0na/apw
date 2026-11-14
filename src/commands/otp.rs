use crate::commands::otp_result;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::output;
use crate::totp;
use crate::vault;

pub fn list(paths: &Paths, config: &mut Config, query: Option<&str>, json: bool) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let now = std::time::SystemTime::now();

    let mut results = Vec::new();
    for entry in vault.entries.iter().filter(|entry| entry.totp.is_some()) {
        if let Some(value) = query {
            if !entry.matches(value) {
                continue;
            }
        }
        if let Some(secret) = &entry.totp {
            let code = totp::generate(secret, now)?;
            results.push(otp_result(entry, &code));
        }
    }

    if output::use_json(json) {
        output::print_json(&output::success(results.into()));
        return Ok(());
    }

    let rows = results
        .iter()
        .map(|result| {
            vec![
                result["domain"].as_str().unwrap_or_default().to_string(),
                result["username"].as_str().unwrap_or_default().to_string(),
                result["code"].as_str().unwrap_or_default().to_string(),
            ]
        })
        .collect::<Vec<_>>();
    output::print_table(&["DOMAIN", "USERNAME", "CODE"], &rows);
    Ok(())
}

pub fn get(paths: &Paths, config: &mut Config, query: &str, json: bool) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let now = std::time::SystemTime::now();

    let mut results = Vec::new();
    for entry in vault
        .entries
        .iter()
        .filter(|entry| entry.totp.is_some() && entry.matches(query))
    {
        if let Some(secret) = &entry.totp {
            let code = totp::generate(secret, now)?;
            results.push(otp_result(entry, &code));
        }
    }

    if results.is_empty() {
        return Err(Error::NoResults(format!(
            "no one-time code matches {query}"
        )));
    }

    if output::use_json(json) {
        output::print_json(&output::success(results.into()));
        return Ok(());
    }

    for result in &results {
        println!(
            "{}\t{}\t{}",
            result["domain"].as_str().unwrap_or_default(),
            result["username"].as_str().unwrap_or_default(),
            result["code"].as_str().unwrap_or_default()
        );
    }
    Ok(())
}
