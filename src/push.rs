//! Push queued local writes to CloudKit.
//!
//! The engine works one pending op at a time, never prompts, and never aborts
//! a sync for one op. A step that conflicts is blocked with a reason the user
//! resolves with `apw resolve`; a transient error keeps the op queued and
//! counts an attempt.

use std::collections::BTreeMap;

use base64::Engine;
use plist::Value;

use crate::ckks;
use crate::cloudkit::{FieldValue, Gateway, OutgoingRecord, Record, SAVE_CREATE, SAVE_UPDATE};
use crate::error::Error;
use crate::model::{self, Entry, EntryKind, OpKind, PendingOp};

/// One sync's CloudKit context for pushing.
pub struct PushEnv<'a> {
    pub gateway: &'a Gateway,
    pub class_keys: &'a BTreeMap<String, Vec<u8>>,
    pub synckeys: &'a BTreeMap<String, String>,
}

/// Counts from one [`push_pending`] run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PushReport {
    pub written: usize,
    pub skipped: usize,
    pub blocked: usize,
    pub failed: usize,
}

/// After this many transient failures an op is blocked until it is resolved.
const MAX_ATTEMPTS: u32 = 5;

/// The synckey class login items and password-manager metadata live under.
/// `inet` is the plist's `class` key, not the synckey class.
const ITEM_CLASS: &str = "classA";
/// Wi-Fi items are generic passwords in the `WiFi` zone under `classC`.
const WIFI_CLASS: &str = "classC";

/// The synckey class a record of `kind` is sealed under.
fn item_class(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Wifi => WIFI_CLASS,
        _ => ITEM_CLASS,
    }
}

enum StepOutcome {
    /// The server already holds the desired state, or a delete target is gone.
    Matched,
    /// The server accepted the write, with its new etag when it sent one.
    Wrote { etag: Option<String> },
    /// A remote state this op refuses to overwrite.
    Blocked(String),
}

enum OpEnd {
    Done { wrote: bool },
    Blocked(String),
}

/// One item or sidecar step for [`apply`].
struct StepSpec<'a> {
    kind: OpKind,
    zone: &'a str,
    owner: Option<&'a str>,
    name: &'a str,
    record_type: &'a str,
    base: Option<&'a str>,
    new: Option<&'a str>,
    write: Option<&'a str>,
    force: bool,
    label: &'a str,
    op_id: &'a str,
    /// Sidecars compare and seal the `v_Data` metadata dictionary, not the
    /// outer item plist.
    metadata: bool,
    /// The synckey class this record is sealed under.
    class: &'a str,
}

impl StepSpec<'_> {
    fn matches(&self, server: &Value, wanted_b64: &str) -> bool {
        if self.metadata {
            metadata_matches(server, wanted_b64)
        } else {
            matches(server, wanted_b64)
        }
    }
}

/// Push every queued op, removing the ones that finished and keeping the ones
/// that blocked or failed.
///
/// `entries` is a `Vec` reference so the engine can grow it later; it only
/// rewrites entries in place today.
#[allow(clippy::ptr_arg)]
pub async fn push_pending(
    entries: &mut Vec<Entry>,
    pending: &mut Vec<PendingOp>,
    env: &PushEnv<'_>,
) -> PushReport {
    let mut report = PushReport::default();
    let mut kept = Vec::with_capacity(pending.len());
    for mut op in std::mem::take(pending) {
        if let Some(reason) = op.blocked.clone() {
            eprintln!("push: {}: {reason}", op.label);
            report.blocked += 1;
            kept.push(op);
            continue;
        }
        match push_one(entries, &mut op, env).await {
            Ok(OpEnd::Done { wrote: true }) => report.written += 1,
            Ok(OpEnd::Done { wrote: false }) => report.skipped += 1,
            Ok(OpEnd::Blocked(reason)) => {
                eprintln!("push: {}: {reason}", op.label);
                op.blocked = Some(reason);
                report.blocked += 1;
                kept.push(op);
            }
            Err(error) => {
                op.attempts += 1;
                let message = error.to_string();
                eprintln!("push: {}: {message}", op.label);
                if op.attempts >= MAX_ATTEMPTS {
                    op.blocked = Some(format!("repeated failures: {message}"));
                }
                report.failed += 1;
                kept.push(op);
            }
        }
    }
    *pending = kept;
    eprintln!(
        "push: wrote {}, skipped {}, blocked {}, failed {}",
        report.written, report.skipped, report.blocked, report.failed
    );
    report
}

async fn push_one(
    entries: &mut [Entry],
    op: &mut PendingOp,
    env: &PushEnv<'_>,
) -> Result<OpEnd, Error> {
    let mut wrote = false;
    match op.kind {
        OpKind::Create | OpKind::Edit => {
            if op.item_dirty {
                match apply_item(op, env).await? {
                    StepOutcome::Matched => {}
                    StepOutcome::Wrote { etag } => {
                        op.item_etag = etag;
                        wrote = true;
                        update_entry(entries, op);
                    }
                    StepOutcome::Blocked(reason) => return Ok(OpEnd::Blocked(reason)),
                }
            }
            if op.sidecar_dirty {
                match apply_sidecar(op, env).await? {
                    StepOutcome::Matched => {}
                    StepOutcome::Wrote { etag } => {
                        op.sidecar_etag = etag;
                        wrote = true;
                        update_entry(entries, op);
                    }
                    StepOutcome::Blocked(reason) => return Ok(OpEnd::Blocked(reason)),
                }
            }
        }
        OpKind::Delete => {
            // Remove the metadata before the item it describes.
            if op.sidecar_dirty {
                match apply_sidecar(op, env).await? {
                    StepOutcome::Matched => {}
                    StepOutcome::Wrote { .. } => {
                        wrote = true;
                        update_entry(entries, op);
                    }
                    StepOutcome::Blocked(reason) => return Ok(OpEnd::Blocked(reason)),
                }
            }
            if op.item_dirty {
                match apply_item(op, env).await? {
                    StepOutcome::Matched => {}
                    StepOutcome::Wrote { .. } => {
                        wrote = true;
                        update_entry(entries, op);
                    }
                    StepOutcome::Blocked(reason) => return Ok(OpEnd::Blocked(reason)),
                }
            }
        }
    }
    Ok(OpEnd::Done { wrote })
}

async fn apply_item(op: &PendingOp, env: &PushEnv<'_>) -> Result<StepOutcome, Error> {
    let spec = StepSpec {
        kind: op.kind,
        zone: &op.zone,
        owner: op.owner.as_deref(),
        name: &op.item_name,
        record_type: record_type(&op.item_type),
        base: op.item_base.as_deref(),
        new: op.item_new.as_deref(),
        write: op.item_new.as_deref(),
        force: op.force,
        label: &op.label,
        op_id: &op.id,
        metadata: false,
        class: item_class(op.entry_kind),
    };
    apply(&spec, env).await
}

async fn apply_sidecar(op: &mut PendingOp, env: &PushEnv<'_>) -> Result<StepOutcome, Error> {
    if op.sidecar_name.is_none() {
        match op.kind {
            // A delete of a sidecar that was never addressed has nothing to do.
            OpKind::Delete => return Ok(StepOutcome::Matched),
            OpKind::Create | OpKind::Edit => op.sidecar_name = Some(model::record_name()),
        }
    }
    let spec = StepSpec {
        kind: op.kind,
        zone: &op.zone,
        owner: op.owner.as_deref(),
        name: op.sidecar_name.as_deref().unwrap_or_default(),
        record_type: record_type(op.sidecar_type.as_deref().unwrap_or_default()),
        base: op.sidecar_base.as_deref(),
        new: op.sidecar_new.as_deref(),
        write: op.sidecar_write.as_deref(),
        force: op.force,
        label: &op.label,
        op_id: &op.id,
        metadata: true,
        class: ITEM_CLASS,
    };
    apply(&spec, env).await
}

async fn apply(step: &StepSpec<'_>, env: &PushEnv<'_>) -> Result<StepOutcome, Error> {
    let server = retrieve(env, step.zone, step.owner, step.name).await?;
    match step.kind {
        OpKind::Create => create(step, env, server.as_ref()).await,
        OpKind::Edit => edit(step, env, server.as_ref()).await,
        OpKind::Delete => delete(step, env, server.as_ref()).await,
    }
}

async fn create(
    step: &StepSpec<'_>,
    env: &PushEnv<'_>,
    server: Option<&Record>,
) -> Result<StepOutcome, Error> {
    if let Some(server) = server {
        let exists = format!("{} already exists on the server", step.label);
        let Some(value) = ckks::decrypt_one(server, env.class_keys).map(|(_, value)| value) else {
            return Ok(StepOutcome::Blocked(format!(
                "{exists} (its contents could not be decrypted)"
            )));
        };
        if step.new.is_some_and(|wanted| step.matches(&value, wanted)) {
            return Ok(StepOutcome::Matched);
        }
        return Ok(StepOutcome::Blocked(exists));
    }
    let Some(blob) = step.write else {
        return Ok(StepOutcome::Blocked(format!(
            "{} has no payload to write",
            step.label
        )));
    };
    let Some(parent) = parent_for(env, step.zone, None, step.class) else {
        return Ok(StepOutcome::Blocked(format!(
            "no synckey for {}:{}",
            step.zone, step.class
        )));
    };
    let Some(class_key) = env.class_keys.get(&parent) else {
        return Ok(StepOutcome::Blocked(format!(
            "class key {parent} is not available"
        )));
    };
    let bplist = decode(blob)?;
    let fields = seal_fields(step.name, class_key, &parent, 0, &bplist)?;
    let etag = save(step, env, fields, None, SAVE_CREATE).await?;
    Ok(StepOutcome::Wrote { etag })
}

async fn edit(
    step: &StepSpec<'_>,
    env: &PushEnv<'_>,
    server: Option<&Record>,
) -> Result<StepOutcome, Error> {
    let Some(server) = server else {
        return Ok(StepOutcome::Blocked(format!(
            "{} was deleted on another device",
            step.label
        )));
    };
    let Some(value) = ckks::decrypt_one(server, env.class_keys).map(|(_, value)| value) else {
        return Ok(StepOutcome::Blocked(changed(step)));
    };
    if step.new.is_some_and(|wanted| step.matches(&value, wanted)) {
        return Ok(StepOutcome::Matched);
    }
    if !step.force && !step.base.is_some_and(|base| step.matches(&value, base)) {
        return Ok(StepOutcome::Blocked(changed(step)));
    }
    let Some(parent) = parent_for(env, step.zone, Some(server), step.class) else {
        return Ok(StepOutcome::Blocked(format!(
            "no synckey for {}:{}",
            step.zone, step.class
        )));
    };
    let Some(class_key) = env.class_keys.get(&parent) else {
        return Ok(StepOutcome::Blocked(format!(
            "class key {parent} is not available"
        )));
    };
    let Some(blob) = step.write else {
        return Ok(StepOutcome::Blocked(format!(
            "{} has no payload to write",
            step.label
        )));
    };
    let bplist = decode(blob)?;
    let gen = server.int("gen").unwrap_or(0);
    let fields = seal_fields(step.name, class_key, &parent, gen, &bplist)?;
    let etag = save(step, env, fields, server.etag.clone(), SAVE_UPDATE).await?;
    Ok(StepOutcome::Wrote { etag })
}

async fn delete(
    step: &StepSpec<'_>,
    env: &PushEnv<'_>,
    server: Option<&Record>,
) -> Result<StepOutcome, Error> {
    let Some(server) = server else {
        return Ok(StepOutcome::Matched);
    };
    let Some(value) = ckks::decrypt_one(server, env.class_keys).map(|(_, value)| value) else {
        return Ok(StepOutcome::Blocked(changed(step)));
    };
    if !step.force && !step.base.is_some_and(|base| step.matches(&value, base)) {
        return Ok(StepOutcome::Blocked(changed(step)));
    }
    env.gateway
        .delete_record(step.zone, step.owner, step.name)
        .await?;
    Ok(StepOutcome::Wrote { etag: None })
}

fn changed(step: &StepSpec<'_>) -> String {
    format!(
        "{} changed on another device; run apw resolve {} --local or --remote",
        step.label, step.op_id
    )
}

/// The class-key record name for a write: the server copy's parent reference
/// first, then the zone's synckey for this record class.
fn parent_for(
    env: &PushEnv<'_>,
    zone: &str,
    server: Option<&Record>,
    class: &str,
) -> Option<String> {
    server
        .and_then(|record| record.reference("parentkeyref"))
        .map(str::to_string)
        .or_else(|| env.synckeys.get(&format!("{zone}:{class}")).cloned())
}

fn record_type(value: &str) -> &str {
    if value.is_empty() {
        "item"
    } else {
        value
    }
}

fn seal_fields(
    name: &str,
    class_key: &[u8],
    parent: &str,
    gen: i64,
    bplist: &[u8],
) -> Result<Vec<(String, FieldValue)>, Error> {
    let mut fields = BTreeMap::from([
        ("gen".to_string(), FieldValue::Int(gen)),
        ("encver".to_string(), FieldValue::Int(2)),
        (
            "parentkeyref".to_string(),
            FieldValue::Reference(parent.to_string()),
        ),
        (
            "uploadver".to_string(),
            FieldValue::Text(concat!("apw ", env!("CARGO_PKG_VERSION")).to_string()),
        ),
    ]);
    let aad = ckks::aad_values(name, &fields);
    let sealed = ckks::seal_item(&ckks::random_item_key(), class_key, &aad, bplist)?;
    fields.insert("data".to_string(), FieldValue::Bytes(sealed.data));
    fields.insert(
        "wrappedkey".to_string(),
        FieldValue::Text(sealed.wrappedkey),
    );
    Ok(fields.into_iter().collect())
}

async fn save(
    step: &StepSpec<'_>,
    env: &PushEnv<'_>,
    fields: Vec<(String, FieldValue)>,
    etag: Option<String>,
    semantics: u32,
) -> Result<Option<String>, Error> {
    let record = OutgoingRecord {
        name: step.name.to_string(),
        record_type: step.record_type.to_string(),
        etag,
        semantics,
        fields,
        delete_fields: Vec::new(),
    };
    env.gateway
        .save_record(step.zone, step.owner, &record)
        .await
}

async fn retrieve(
    env: &PushEnv<'_>,
    zone: &str,
    owner: Option<&str>,
    name: &str,
) -> Result<Option<Record>, Error> {
    match env.gateway.retrieve_record(zone, owner, name, None).await {
        Ok((record, _)) => Ok(Some(record)),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn is_not_found(error: &Error) -> bool {
    let Error::CloudKit { code, description } = error else {
        return false;
    };
    matches!(code, 3 | 11)
        || description.as_deref().is_some_and(|text| {
            let text = text.to_lowercase();
            text.contains("not found")
                || text.contains("does not exist")
                || text.contains("unknown item")
        })
}

fn matches(server_plist: &Value, wanted_bplist_b64: &str) -> bool {
    decode_plist(wanted_bplist_b64).is_some_and(|wanted| &wanted == server_plist)
}

/// Sidecar comparison: the queued payload is the metadata dictionary carried
/// in `v_Data`, while the server record is the outer item plist.
fn metadata_matches(server_plist: &Value, wanted_bplist_b64: &str) -> bool {
    let Some(wanted) = decode_plist(wanted_bplist_b64) else {
        return false;
    };
    let Some(bytes) = ckks::metadata_bytes(server_plist) else {
        return false;
    };
    plist::from_bytes::<Value>(&bytes).is_ok_and(|server| server == wanted)
}

fn decode_plist(value: &str) -> Option<Value> {
    plist::from_bytes::<Value>(&decode(value).ok()?).ok()
}

fn decode(value: &str) -> Result<Vec<u8>, Error> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Message(format!("invalid base64 payload: {error}")))
}

/// Copy the pushed state onto the entry a later read would otherwise replace
/// with stale server data. User-visible fields are left alone.
fn update_entry(entries: &mut [Entry], op: &PendingOp) {
    let Some(entry) = entries.iter_mut().find(|entry| entry.id == op.item_name) else {
        return;
    };
    let Some(record) = entry.record.as_mut() else {
        return;
    };
    record.item_etag = op.item_etag.clone();
    record.plist = op.item_new.clone();
    record.metadata = op.sidecar_new.clone();
    record.sidecar_etag = op.sidecar_etag.clone();
    if op.sidecar_name.is_some() {
        record.sidecar_name = op.sidecar_name.clone();
    }
    if op.sidecar_write.is_some() {
        record.sidecar_plist = op.sidecar_write.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Dictionary;

    const CLASS_KEY: [u8; 64] = [7u8; 64];

    fn class_keys(parent: &str) -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([(parent.to_string(), CLASS_KEY.to_vec())])
    }

    fn sealed_record(name: &str, parent: &str, value: &Value) -> Record {
        let mut fields = BTreeMap::from([
            ("gen".to_string(), FieldValue::Int(0)),
            ("encver".to_string(), FieldValue::Int(2)),
            (
                "parentkeyref".to_string(),
                FieldValue::Reference(parent.to_string()),
            ),
            (
                "uploadver".to_string(),
                FieldValue::Text("test".to_string()),
            ),
            (
                "acct".to_string(),
                FieldValue::Text("me@example.com".to_string()),
            ),
        ]);
        let aad = ckks::aad_values(name, &fields);
        let bplist = ckks::plist_bytes(value).expect("bplist");
        let sealed =
            ckks::seal_item(&ckks::random_item_key(), &CLASS_KEY, &aad, &bplist).expect("seal");
        fields.insert("data".to_string(), FieldValue::Bytes(sealed.data));
        fields.insert(
            "wrappedkey".to_string(),
            FieldValue::Text(sealed.wrappedkey),
        );
        Record {
            name: name.to_string(),
            zone: None,
            owner: None,
            etag: None,
            record_type: "item".to_string(),
            fields,
            protection_info: None,
            pcs_key: None,
            share_info: None,
        }
    }

    #[test]
    fn seals_and_decrypts_the_same_plist() {
        let value = Value::Dictionary(Dictionary::new());
        let record = sealed_record("item-1", "class-key", &value);
        let (_, decrypted) =
            ckks::decrypt_one(&record, &class_keys("class-key")).expect("decrypts");
        assert_eq!(decrypted, value);
    }

    #[test]
    fn a_changed_byte_fails_to_decrypt() {
        let value = Value::String("secret".to_string());
        let mut record = sealed_record("item-1", "class-key", &value);
        if let Some(FieldValue::Bytes(data)) = record.fields.get_mut("data") {
            data[20] ^= 0x01;
        }
        assert!(ckks::decrypt_one(&record, &class_keys("class-key")).is_none());
    }

    #[test]
    fn not_found_codes_and_descriptions() {
        let with_code = |code| Error::CloudKit {
            code,
            description: None,
        };
        assert!(is_not_found(&with_code(3)));
        assert!(is_not_found(&with_code(11)));
        assert!(!is_not_found(&with_code(60)));
        assert!(is_not_found(&Error::CloudKit {
            code: 1,
            description: Some("Record not found".into()),
        }));
        assert!(!is_not_found(&Error::Message("network is down".into())));
    }

    #[test]
    fn compare_accepts_equal_plists_and_rejects_a_change() {
        let mut dict = Dictionary::new();
        dict.insert("title".into(), Value::String("Example".into()));
        let value = Value::Dictionary(dict);
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(ckks::plist_bytes(&value).expect("bplist"));
        assert!(matches(&value, &encoded));

        let mut changed = value.as_dictionary().expect("dict").clone();
        changed.insert("title".into(), Value::String("Other".into()));
        assert!(!matches(&Value::Dictionary(changed), &encoded));
    }

    #[test]
    fn sidecar_write_keeps_the_outer_keys() {
        let mut outer = Dictionary::new();
        outer.insert(
            "cdat".into(),
            Value::Date(plist::Date::from(std::time::SystemTime::UNIX_EPOCH)),
        );
        outer.insert(
            "labl".into(),
            Value::String("Password Manager Metadata: example.com (me)".into()),
        );
        outer.insert("srvr".into(), Value::String("example.com".into()));
        outer.insert("acct".into(), Value::String("me".into()));
        outer.insert(
            "agrp".into(),
            Value::String("com.apple.password-manager".into()),
        );
        let base = base64::engine::general_purpose::STANDARD
            .encode(ckks::plist_bytes(&Value::Dictionary(outer.clone())).expect("bplist"));

        let mut metadata = Dictionary::new();
        metadata.insert("title".into(), Value::Data(b"Hello".to_vec()));

        let bytes =
            crate::commands::write::sidecar_plist(Some(&base), &Dictionary::new(), &metadata)
                .expect("sidecar");
        let value: Value = plist::from_bytes(&bytes).expect("plist");
        let dict = value.as_dictionary().expect("dict");
        assert_eq!(dict.get("cdat"), outer.get("cdat"));
        assert_eq!(dict.get("labl"), outer.get("labl"));
        assert_eq!(dict.get("srvr"), outer.get("srvr"));
        assert_eq!(dict.get("acct"), outer.get("acct"));
        assert!(dict.get("mdat").is_some(), "mdat is refreshed");

        let round_trip = ckks::metadata_bytes(&value).expect("metadata bytes");
        let parsed: Value = plist::from_bytes(&round_trip).expect("plist");
        assert_eq!(parsed.as_dictionary(), Some(&metadata));
    }
}
