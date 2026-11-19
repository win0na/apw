use serde_json::{json, Value};

use crate::model::Entry;

pub mod join;
pub mod login;
pub mod otp;
pub mod probe;
pub mod pw;
pub mod status;
pub mod sync;
pub mod units;
pub mod write;

pub fn login_result(entry: &Entry, include_password: bool) -> Value {
    let mut result = json!({
        "id": entry.id,
        "username": entry.username.clone().unwrap_or_default(),
        "domain": entry.domain(),
        "name": entry.name(),
        "url": entry.url.clone().unwrap_or_default(),
        "sites": entry.sites,
    });
    let object = result.as_object_mut().expect("object");

    if let Some(title) = &entry.title {
        object.insert("title".into(), json!(title));
    }
    if let Some(password) = &entry.password {
        if include_password {
            object.insert("password".into(), json!(password));
        }
    }
    if let Some(notes) = &entry.notes {
        object.insert("notes".into(), json!(notes));
    }
    if let Some(group) = &entry.group {
        object.insert("group".into(), json!(group));
    }
    result
}

pub fn otp_result(entry: &Entry, code: &str) -> Value {
    let source = entry
        .totp
        .as_ref()
        .and_then(|totp| totp.issuer.clone())
        .or_else(|| entry.title.clone())
        .unwrap_or_else(|| "apw".into());
    json!({
        "id": entry.id,
        "username": entry.username.clone().unwrap_or_default(),
        "domain": entry.domain(),
        "name": entry.name(),
        "url": entry.url.clone().unwrap_or_default(),
        "source": source,
        "code": code,
    })
}
