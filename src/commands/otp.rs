use crate::commands::otp_result;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::output::{self, Style};
use crate::totp;
use crate::vault;

/// `apw otp` lists every code; `apw otp <query>` prints just that code.
pub fn run(paths: &Paths, config: &mut Config, query: Option<&str>, style: Style) -> Result<()> {
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

    if query.is_some() && results.is_empty() {
        return Err(Error::NoResults(format!(
            "no one-time code matches {}",
            query.unwrap_or_default()
        )));
    }

    if style.json {
        output::print_json(&output::success(results.into()));
        return Ok(());
    }

    if query.is_some() {
        for result in &results {
            println!("{}", result["code"].as_str().unwrap_or_default());
        }
        return Ok(());
    }

    let rows = results
        .iter()
        .map(|result| {
            vec![
                result["name"].as_str().unwrap_or_default().to_string(),
                result["username"].as_str().unwrap_or_default().to_string(),
                result["code"].as_str().unwrap_or_default().to_string(),
            ]
        })
        .collect::<Vec<_>>();
    output::print_table_opts(
        &["NAME", "USERNAME", "CODE"],
        &rows,
        style.no_header,
        style.wide,
    );
    Ok(())
}
