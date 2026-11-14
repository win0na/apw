use std::path::Path;

use crate::error::Result;
use crate::model::{Source, Vault};

pub fn read(path: &Path) -> Result<Vault> {
    let text = std::fs::read_to_string(path)?;
    let mut vault: Vault = serde_json::from_str(&text)?;
    vault.source = Source::Fixture;
    if vault.generated_at.is_none() {
        vault.generated_at = Some(chrono::Utc::now());
    }
    for (index, entry) in vault.entries.iter_mut().enumerate() {
        if entry.id.is_empty() {
            entry.id = format!("fixture-{index}");
        }
    }
    Ok(vault)
}
