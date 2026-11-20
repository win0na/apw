//! Local-first write commands.
//!
//! Every command here changes only the encrypted snapshot and records a
//! [`PendingOp`] for a later push. None of them touch the network.

use std::io::Write;

use base64::Engine;
use chrono::Utc;
use plist::{Dictionary, Value};
use rand::Rng;
use serde_json::json;

use crate::ckks::{
    append_password_change, new_login_plist, new_metadata_dict, new_metadata_plist,
    new_note_item_plist, new_wifi_plist, plist_bytes, set_metadata_text, set_metadata_totp,
};
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::model::{Entry, EntryKind, OpKind, PendingOp, RecordMeta, Vault};
use crate::output::{self, Style};
use crate::totp::{self, TotpSpec};
use crate::vault;

const GENERATED_CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";

/// Apple's suffix on the access group of an item in Recently Deleted.
const RECENTLY_DELETED: &str = "-recently-deleted";

/// A pending queue beyond these caps is refused, so a long offline run cannot
/// grow the vault without bound.
pub(crate) const MAX_PENDING_OPS: usize = 200;
pub(crate) const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;

#[allow(clippy::too_many_arguments)]
pub fn add_login(
    paths: &Paths,
    config: &mut Config,
    url: &str,
    username: Option<&str>,
    title: Option<&str>,
    notes: Option<&str>,
    totp: Option<&str>,
    password_stdin: bool,
    generate: bool,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    if password_stdin && generate {
        return Err(Error::Invalid(
            "pass only one of --password-stdin or --generate".into(),
        ));
    }
    let totp_spec = totp.map(totp::parse_spec).transpose()?;
    let (url, host) = normalize_url(url)?;
    let password = match (password_stdin, generate) {
        (true, _) => read_stdin_line()?,
        (_, true) => {
            let password = generate_password();
            eprintln!("generated password: {password}");
            password
        }
        _ => prompt_to_make_password()?,
    };
    let username = username.unwrap_or("");

    let login = new_login_plist(&host, username, password.as_bytes());
    let login_bytes = plist_bytes(&login)?;

    let mut metadata = new_metadata_dict();
    // Apple writes an empty `s_as` array into every metadata record it creates.
    metadata.insert("s_as".into(), Value::Array(Vec::new()));
    if let Some(title) = title {
        set_metadata_text(&mut metadata, "title", title);
    }
    if let Some(notes) = notes {
        set_metadata_text(&mut metadata, "notes", notes);
    }
    if let Some(spec) = &totp_spec {
        set_metadata_totp(&mut metadata, spec, Utc::now());
    }
    // The outer sidecar item CloudKit receives carries the metadata dictionary
    // in `v_Data`; `metadata_bytes` is the dictionary alone.
    let sidecar_write = encode(&plist_bytes(&new_metadata_plist(
        &host, username, &metadata,
    ))?);
    let metadata_bytes = plist_bytes(&Value::Dictionary(metadata))?;

    let id = uuid();
    let sidecar = uuid();
    let login_b64 = encode(&login_bytes);
    let metadata_b64 = encode(&metadata_bytes);
    let label = entry_label(&Entry {
        title: title.map(str::to_string),
        sites: vec![host.clone()],
        username: Some(username.to_string()),
        ..Entry::default()
    });

    let entry = Entry {
        id: id.clone(),
        kind: EntryKind::Login,
        agrp: Some("com.apple.cfnetwork".into()),
        title: title.map(str::to_string),
        url: Some(url.clone()),
        sites: vec![host.clone()],
        username: Some(username.to_string()),
        password: Some(password.clone()),
        notes: notes.map(str::to_string),
        totp: totp_spec.as_ref().map(TotpSpec::to_totp),
        record: Some(RecordMeta {
            zone: "Passwords".into(),
            item_type: "item".into(),
            plist: Some(login_b64.clone()),
            sidecar_name: Some(sidecar.clone()),
            sidecar_type: Some("item".into()),
            metadata: Some(metadata_b64.clone()),
            ..RecordMeta::default()
        }),
        ..Entry::default()
    };

    let op = PendingOp {
        id: uuid(),
        kind: OpKind::Create,
        entry_kind: EntryKind::Login,
        zone: "Passwords".into(),
        owner: None,
        item_name: id.clone(),
        item_type: "item".into(),
        item_base: None,
        item_new: Some(login_b64),
        item_etag: None,
        item_dirty: true,
        sidecar_name: Some(sidecar),
        sidecar_type: Some("item".into()),
        sidecar_base: None,
        sidecar_new: Some(metadata_b64),
        sidecar_write: Some(sidecar_write),
        sidecar_etag: None,
        sidecar_dirty: true,
        blocked: None,
        attempts: 0,
        next_attempt: None,
        force: false,
        label: label.clone(),
    };

    let mut working = vault::load(paths, config)?;
    ensure_queue_room(&working)?;
    let name = entry.display_name();
    if dry_run {
        if style.json {
            let mut data = json!({
                "dry_run": true,
                "id": id,
                "name": name,
                "label": label,
                "pending_id": op.id,
            });
            if generate {
                data["password"] = json!(password);
            }
            output::print_json(&output::success(data));
        } else {
            println!("would add {id} {name}");
            println!("would queue create {}", op.id);
        }
        return Ok(());
    }

    working.entries.push(entry);
    working.pending.push(op.clone());
    vault::save(paths, config, &working)?;

    if style.json {
        let mut data = json!({
            "id": id,
            "name": name,
            "label": label,
            "pending_id": op.id,
        });
        if generate {
            data["password"] = json!(password);
        }
        output::print_json(&output::success(data));
    } else {
        println!("added {id} {name}");
        println!("pending {}", op.id);
    }
    Ok(())
}

/// Add a Wi-Fi network. One item record in the `WiFi` zone, no sidecar.
pub fn add_wifi(
    paths: &Paths,
    config: &mut Config,
    ssid: &str,
    password_stdin: bool,
    generate: bool,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    if password_stdin && generate {
        return Err(Error::Invalid(
            "pass only one of --password-stdin or --generate".into(),
        ));
    }
    let ssid = ssid.trim();
    if ssid.is_empty() {
        return Err(Error::Invalid("a network name is required".into()));
    }
    let password = match (password_stdin, generate) {
        (true, _) => read_stdin_line()?,
        (_, true) => {
            let password = generate_password();
            eprintln!("generated password: {password}");
            password
        }
        _ => prompt_to_make_password()?,
    };

    let item_b64 = encode(&plist_bytes(&new_wifi_plist(ssid, password.as_bytes()))?);
    let id = uuid();
    let entry = Entry {
        id: id.clone(),
        kind: EntryKind::Wifi,
        agrp: Some("apple".into()),
        title: Some(ssid.to_string()),
        sites: vec![ssid.to_string()],
        username: Some(ssid.to_string()),
        password: Some(password.clone()),
        record: Some(RecordMeta {
            zone: "WiFi".into(),
            item_type: "item".into(),
            plist: Some(item_b64.clone()),
            ..RecordMeta::default()
        }),
        ..Entry::default()
    };
    let label = entry_label(&entry);

    let op = PendingOp {
        id: uuid(),
        kind: OpKind::Create,
        entry_kind: EntryKind::Wifi,
        zone: "WiFi".into(),
        owner: None,
        item_name: id.clone(),
        item_type: "item".into(),
        item_base: None,
        item_new: Some(item_b64),
        item_etag: None,
        item_dirty: true,
        sidecar_name: None,
        sidecar_type: None,
        sidecar_base: None,
        sidecar_new: None,
        sidecar_write: None,
        sidecar_etag: None,
        sidecar_dirty: false,
        blocked: None,
        attempts: 0,
        next_attempt: None,
        force: false,
        label: label.clone(),
    };

    let mut working = vault::load(paths, config)?;
    ensure_queue_room(&working)?;
    let name = entry.display_name();
    if dry_run {
        if style.json {
            let mut data = json!({
                "dry_run": true,
                "id": id,
                "name": name,
                "label": label,
                "pending_id": op.id,
            });
            if generate {
                data["password"] = json!(password);
            }
            output::print_json(&output::success(data));
        } else {
            println!("would add wifi {id} {name}");
            println!("would queue create {}", op.id);
        }
        return Ok(());
    }

    working.entries.push(entry);
    working.pending.push(op.clone());
    vault::save(paths, config, &working)?;

    if style.json {
        let mut data = json!({
            "id": id,
            "name": name,
            "label": label,
            "pending_id": op.id,
        });
        if generate {
            data["password"] = json!(password);
        }
        output::print_json(&output::success(data));
    } else {
        println!("added {id} {name}");
        println!("pending {}", op.id);
    }
    Ok(())
}

/// Add a note: a login-shaped stub item plus its metadata sidecar.
pub fn add_note(
    paths: &Paths,
    config: &mut Config,
    title: &str,
    body: Option<&str>,
    body_stdin: bool,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    if body.is_some() && body_stdin {
        return Err(Error::Invalid(
            "pass only one of --body or --body-stdin".into(),
        ));
    }
    let title = title.trim();
    if title.is_empty() {
        return Err(Error::Invalid("a note title is required".into()));
    }
    let body = if body_stdin {
        read_stdin_all()?
    } else {
        body.unwrap_or("").to_string()
    };

    let site = uuid();
    let item_b64 = encode(&plist_bytes(&new_note_item_plist(&site))?);

    let metadata = new_note_metadata(title, &body);
    let metadata_b64 = encode(&plist_bytes(&Value::Dictionary(metadata.clone()))?);
    let sidecar_id = uuid();
    let sidecar_plist = new_metadata_plist(&site, "", &metadata);
    let sidecar_b64 = encode(&plist_bytes(&sidecar_plist)?);

    let entry = Entry {
        id: site.clone(),
        kind: EntryKind::Note,
        agrp: Some("com.apple.cfnetwork".into()),
        title: Some(title.to_string()),
        notes: Some(body.clone()),
        sites: vec![title.to_string()],
        record: Some(RecordMeta {
            zone: "Passwords".into(),
            item_type: "item".into(),
            plist: Some(item_b64.clone()),
            sidecar_name: Some(sidecar_id.clone()),
            sidecar_type: Some("item".into()),
            metadata: Some(metadata_b64.clone()),
            sidecar_plist: Some(sidecar_b64.clone()),
            ..RecordMeta::default()
        }),
        ..Entry::default()
    };
    let label = entry_label(&entry);

    let op = PendingOp {
        id: uuid(),
        kind: OpKind::Create,
        entry_kind: EntryKind::Note,
        zone: "Passwords".into(),
        owner: None,
        item_name: site.clone(),
        item_type: "item".into(),
        item_base: None,
        item_new: Some(item_b64),
        item_etag: None,
        item_dirty: true,
        sidecar_name: Some(sidecar_id),
        sidecar_type: Some("item".into()),
        sidecar_base: None,
        sidecar_new: Some(metadata_b64),
        sidecar_write: Some(sidecar_b64),
        sidecar_etag: None,
        sidecar_dirty: true,
        blocked: None,
        attempts: 0,
        next_attempt: None,
        force: false,
        label: label.clone(),
    };

    let mut working = vault::load(paths, config)?;
    ensure_queue_room(&working)?;
    let name = entry.display_name();
    if dry_run {
        if style.json {
            output::print_json(&output::success(json!({
                "dry_run": true,
                "id": site,
                "name": name,
                "label": label,
                "pending_id": op.id,
            })));
        } else {
            println!("would add note {site} {name}");
            println!("would queue create {}", op.id);
        }
        return Ok(());
    }

    working.entries.push(entry);
    working.pending.push(op.clone());
    vault::save(paths, config, &working)?;

    if style.json {
        output::print_json(&output::success(json!({
            "id": site,
            "name": name,
            "label": label,
            "pending_id": op.id,
        })));
    } else {
        println!("added {site} {name}");
        println!("pending {}", op.id);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn edit(
    paths: &Paths,
    config: &mut Config,
    query: Option<&str>,
    id: Option<&str>,
    title_flag: Option<&str>,
    notes_flag: Option<&str>,
    clear_notes: bool,
    password_stdin: bool,
    generate: bool,
    totp_flag: Option<&str>,
    clear_totp: bool,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    if password_stdin && generate {
        return Err(Error::Invalid(
            "pass only one of --password-stdin or --generate".into(),
        ));
    }
    if notes_flag.is_some() && clear_notes {
        return Err(Error::Invalid(
            "pass only one of --notes or --clear-notes".into(),
        ));
    }
    if totp_flag.is_some() && clear_totp {
        return Err(Error::Invalid(
            "pass only one of --totp or --clear-totp".into(),
        ));
    }

    let vault = vault::load(paths, config)?;
    let index = find_entry(&vault, query, id)?;
    let entry = vault.entries[index].clone();
    if entry.group.is_some() {
        return Err(Error::Invalid(format!(
            "{} is a shared entry; shared entries cannot be edited here",
            entry.display_name()
        )));
    }
    let record = entry.record.clone().ok_or_else(|| {
        Error::Invalid(format!(
            "{} has no CloudKit record; run `apw sync` first",
            entry.display_name()
        ))
    })?;
    let item_base = record.plist.clone().ok_or_else(|| {
        Error::Invalid(format!(
            "{} has no item payload; run `apw sync` first",
            entry.display_name()
        ))
    })?;

    let mut item = decode_dict(&item_base, "item")?;
    let mut metadata = match record.metadata.as_deref() {
        Some(value) => decode_dict(value, "metadata")?,
        None => {
            let mut dict = new_metadata_dict();
            dict.insert("s_as".into(), Value::Array(Vec::new()));
            dict
        }
    };

    let wifi = entry.kind == EntryKind::Wifi;
    let note = entry.kind == EntryKind::Note;
    if wifi
        && (title_flag.is_some()
            || notes_flag.is_some()
            || clear_notes
            || totp_flag.is_some()
            || clear_totp)
    {
        return Err(Error::Invalid(format!(
            "{} is a Wi-Fi network; only its password can change (the SSID is the join key)",
            entry.display_name()
        )));
    }
    if note && (password_stdin || generate || totp_flag.is_some() || clear_totp) {
        return Err(Error::Invalid(format!(
            "{} is a note; it has a title and body, not a password or one-time code",
            entry.display_name()
        )));
    }

    let totp_spec = totp_flag.map(totp::parse_spec).transpose()?;

    let mut new_title = entry.title.clone();
    let mut new_notes = entry.notes.clone();
    let mut new_password = entry.password.clone();
    let mut new_totp = entry.totp.clone();
    let mut title_changed = false;
    let mut notes_changed = false;
    let mut password_changed = false;
    let mut totp_changed = false;

    if !wifi {
        if let Some(value) = title_flag {
            title_changed = true;
            if value.is_empty() {
                metadata.remove("title");
                new_title = None;
            } else {
                set_metadata_text(&mut metadata, "title", value);
                new_title = Some(value.to_string());
            }
        }
        if clear_notes {
            notes_changed = true;
            metadata.remove("notes");
            new_notes = None;
        } else if let Some(value) = notes_flag {
            notes_changed = true;
            set_metadata_text(&mut metadata, "notes", value);
            new_notes = Some(value.to_string());
        }
    }
    if !note {
        if password_stdin {
            let value = read_stdin_line()?;
            if wifi {
                item.insert("v_Data".into(), Value::Data(value.as_bytes().to_vec()));
            } else {
                apply_password(&mut item, &mut metadata, &value);
            }
            new_password = Some(value);
            password_changed = true;
        } else if generate {
            let value = generate_password();
            eprintln!("generated password: {value}");
            if wifi {
                item.insert("v_Data".into(), Value::Data(value.as_bytes().to_vec()));
            } else {
                apply_password(&mut item, &mut metadata, &value);
            }
            new_password = Some(value);
            password_changed = true;
        }
    }
    if let Some(spec) = &totp_spec {
        set_metadata_totp(&mut metadata, spec, Utc::now());
        new_totp = Some(spec.to_totp());
        totp_changed = true;
    }
    if clear_totp {
        metadata.remove("totp");
        new_totp = None;
        totp_changed = true;
    }

    let interactive = title_flag.is_none()
        && notes_flag.is_none()
        && !clear_notes
        && !password_stdin
        && !generate
        && totp_flag.is_none()
        && !clear_totp
        && !dry_run;
    if interactive {
        if !wifi {
            if let Some(value) = prompt_text("Title", entry.title.as_deref())? {
                title_changed = true;
                set_metadata_text(&mut metadata, "title", &value);
                new_title = Some(value);
            }
            if let Some(value) = prompt_text("Notes", entry.notes.as_deref())? {
                notes_changed = true;
                set_metadata_text(&mut metadata, "notes", &value);
                new_notes = Some(value);
            }
        }
        if !note {
            let entered =
                rpassword::prompt_password("Password (Enter keeps the current password): ")?;
            if !entered.is_empty() {
                let again = rpassword::prompt_password("Password again: ")?;
                if entered != again {
                    return Err(Error::Invalid("passwords do not match".into()));
                }
                if wifi {
                    item.insert("v_Data".into(), Value::Data(entered.as_bytes().to_vec()));
                } else {
                    apply_password(&mut item, &mut metadata, &entered);
                }
                new_password = Some(entered);
                password_changed = true;
            }
        }
    }

    if !title_changed && !notes_changed && !password_changed && !totp_changed {
        if style.json {
            output::print_json(&output::success(json!({
                "id": entry.id,
                "name": entry.name(),
                "changed": false,
            })));
        } else {
            println!("no changes for {}", entry.display_name());
        }
        return Ok(());
    }

    let sidecar_changed = title_changed || notes_changed || totp_changed;
    let sidecar_write = if sidecar_changed {
        Some(encode(&sidecar_plist(
            record.sidecar_plist.as_deref(),
            &item,
            &metadata,
        )?))
    } else {
        None
    };
    let item_new = encode(&plist_bytes(&Value::Dictionary(item))?);
    // A Wi-Fi record has no sidecar; leave the stored metadata untouched.
    let metadata_new = if wifi {
        None
    } else {
        Some(encode(&plist_bytes(&Value::Dictionary(metadata))?))
    };
    let label = entry_label(&Entry {
        title: new_title.clone(),
        notes: new_notes.clone(),
        password: new_password.clone(),
        ..entry.clone()
    });

    let op = PendingOp {
        id: uuid(),
        kind: OpKind::Edit,
        entry_kind: entry.kind,
        zone: record.zone.clone(),
        owner: None,
        item_name: entry.id.clone(),
        item_type: record.item_type.clone(),
        item_base: record.plist.clone(),
        item_new: Some(item_new),
        item_etag: record.item_etag.clone(),
        item_dirty: password_changed,
        sidecar_name: record.sidecar_name.clone(),
        sidecar_type: record.sidecar_type.clone(),
        sidecar_base: record.metadata.clone(),
        sidecar_new: metadata_new,
        sidecar_write,
        sidecar_etag: record.sidecar_etag.clone(),
        sidecar_dirty: sidecar_changed,
        blocked: None,
        attempts: 0,
        next_attempt: None,
        force: false,
        label,
    };

    let mut working = vault.clone();
    ensure_queue_room(&working)?;
    let merged = merge_edit(&mut working.pending, op);
    let name = {
        let entry = &mut working.entries[index];
        entry.title = new_title;
        entry.notes = new_notes;
        entry.password = new_password;
        entry.totp = new_totp;
        if note {
            entry.sites = entry.title.iter().cloned().collect();
        }
        entry.display_name()
    };

    if dry_run {
        if style.json {
            output::print_json(&output::success(json!({
                "dry_run": true,
                "id": entry.id,
                "name": name,
                "label": merged.label,
                "pending_id": merged.id,
            })));
        } else {
            println!("would edit {} {name}", entry.id);
            println!("would queue edit {}", merged.id);
        }
        return Ok(());
    }

    vault::save(paths, config, &working)?;

    if style.json {
        output::print_json(&output::success(json!({
            "id": entry.id,
            "name": name,
            "label": merged.label,
            "pending_id": merged.id,
        })));
    } else {
        println!("edited {} {name}", entry.id);
        println!("pending {}", merged.id);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn rm(
    paths: &Paths,
    config: &mut Config,
    query: Option<&str>,
    id: Option<&str>,
    yes: bool,
    dry_run: bool,
    style: Style,
) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let index = find_entry(&vault, query, id)?;
    let entry = vault.entries[index].clone();
    if entry.group.is_some() {
        return Err(Error::Invalid(format!(
            "{} is a shared entry; shared entries cannot be deleted here",
            entry.display_name()
        )));
    }
    let record = entry.record.clone().ok_or_else(|| {
        Error::Invalid(format!(
            "{} has no CloudKit record; run `apw sync` first",
            entry.display_name()
        ))
    })?;
    if !yes {
        return Err(Error::Invalid("refusing to delete without --yes".into()));
    }
    ensure_queue_room(&vault)?;

    // Apple does not remove the record. It moves the same item, under the same
    // class key, to Recently Deleted by appending `-recently-deleted` to
    // `agrp` and stamping `mdat`. Every other key, including the secret, stays.
    let deleted_at = Utc::now();
    let (item_new, sidecar_new) = trash_payloads(&record, deleted_at)?;

    let label = entry_label(&entry);
    let op = PendingOp {
        id: uuid(),
        kind: OpKind::Delete,
        entry_kind: entry.kind,
        zone: record.zone.clone(),
        owner: None,
        item_name: entry.id.clone(),
        item_type: record.item_type.clone(),
        item_base: record.plist.clone(),
        item_new: item_new.clone(),
        item_etag: record.item_etag.clone(),
        item_dirty: true,
        sidecar_name: record.sidecar_name.clone(),
        sidecar_type: record.sidecar_type.clone(),
        sidecar_base: record.metadata.clone(),
        sidecar_new: sidecar_new.clone(),
        sidecar_write: sidecar_new,
        sidecar_etag: record.sidecar_etag.clone(),
        sidecar_dirty: record.sidecar_name.is_some(),
        blocked: None,
        attempts: 0,
        next_attempt: None,
        force: false,
        label,
    };
    let name = entry.display_name();

    if dry_run {
        if style.json {
            output::print_json(&output::success(json!({
                "dry_run": true,
                "id": entry.id,
                "name": name,
                "label": op.label,
                "pending_id": op.id,
            })));
        } else {
            println!("would delete {} {name}", entry.id);
            println!("would queue delete {}", op.id);
        }
        return Ok(());
    }

    let mut working = vault.clone();
    working
        .pending
        .retain(|pending| pending.item_name != op.item_name);
    working.pending.push(op.clone());
    working.entries.retain(|candidate| candidate.id != entry.id);
    vault::save(paths, config, &working)?;

    if style.json {
        output::print_json(&output::success(json!({
            "id": entry.id,
            "name": name,
            "label": op.label,
            "pending_id": op.id,
            "recently_deleted": true,
            "recoverable_days": 30,
        })));
    } else {
        println!("deleted {} {name}", entry.id);
        println!("pending {}", op.id);
        println!("the entry is in Recently Deleted and can be restored on any device for 30 days");
    }
    Ok(())
}

pub fn pending(paths: &Paths, config: &mut Config, style: Style) -> Result<()> {
    let vault = vault::load(paths, config)?;
    let rows = vault
        .pending
        .iter()
        .map(|op| {
            json!({
                "id": op.id,
                "kind": kind_name(op.kind),
                "item_name": op.item_name,
                "label": op.label,
                "state": match &op.blocked {
                    Some(reason) => format!("blocked: {reason}"),
                    None => "pending".to_string(),
                },
                "attempts": op.attempts,
                "next_attempt": op.next_attempt,
            })
        })
        .collect::<Vec<_>>();

    if style.json {
        output::print_json(&output::success(serde_json::Value::Array(rows)));
        return Ok(());
    }

    let table = vault
        .pending
        .iter()
        .map(|op| {
            vec![
                op.id.clone(),
                kind_name(op.kind).to_string(),
                op.label.clone(),
                match &op.blocked {
                    Some(reason) => format!("blocked: {reason}"),
                    None => "pending".to_string(),
                },
                op.attempts.to_string(),
                op.next_attempt.clone().unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect::<Vec<_>>();
    output::print_table_opts(
        &["ID", "KIND", "LABEL", "STATE", "ATTEMPTS", "RETRY"],
        &table,
        style.no_header,
        style.wide,
    );
    Ok(())
}

pub fn resolve(
    paths: &Paths,
    config: &mut Config,
    id: &str,
    local: bool,
    remote: bool,
    style: Style,
) -> Result<()> {
    if local == remote {
        return Err(Error::Invalid(
            "pass exactly one of --local or --remote".into(),
        ));
    }
    let mut vault = vault::load(paths, config)?;
    let index = vault
        .pending
        .iter()
        .position(|op| op.id.eq_ignore_ascii_case(id))
        .ok_or_else(|| Error::NoResults(format!("no pending op with id {id}")))?;

    if local {
        let op = &mut vault.pending[index];
        op.blocked = None;
        op.force = true;
        op.attempts = 0;
        op.next_attempt = None;
    } else {
        vault.pending.remove(index);
    }
    vault::save(paths, config, &vault)?;

    let action = if local { "local" } else { "remote" };
    if style.json {
        output::print_json(&output::success(json!({
            "id": id,
            "action": action,
        })));
    } else if local {
        println!("kept {id}; it will be pushed on the next sync");
    } else {
        println!("discarded {id}");
    }
    Ok(())
}

/// The metadata dictionary a new note starts from: a title, a body, an empty
/// `s_as`, and no password history.
fn new_note_metadata(title: &str, body: &str) -> Dictionary {
    let mut metadata = new_metadata_dict();
    metadata.insert("s_as".into(), Value::Array(Vec::new()));
    set_metadata_text(&mut metadata, "title", title);
    set_metadata_text(&mut metadata, "notes", body);
    metadata
}

/// A fresh dashed uppercase UUID, matching the record names CloudKit uses.
fn uuid() -> String {
    crate::model::record_name()
}

/// Build the outer password-manager sidecar item plist for a metadata change.
///
/// The base is the decrypted sidecar plist, when the vault has one, so every
/// key Apple wrote (`labl`, `srvr`, `acct`, `cdat`, `type`, unknown keys)
/// survives. Only `v_Data` and `mdat` change. Without a base, a fresh sidecar
/// is built from the login plist's site and username.
pub(crate) fn sidecar_plist(
    base: Option<&str>,
    login: &Dictionary,
    metadata: &Dictionary,
) -> Result<Vec<u8>> {
    let mut sidecar = match base {
        Some(value) => decode_dict(value, "sidecar")?,
        None => {
            let site = dictionary_text(login, "srvr").unwrap_or_default();
            let username = dictionary_text(login, "acct").unwrap_or_default();
            new_metadata_plist(&site, &username, metadata)
                .as_dictionary()
                .cloned()
                .ok_or_else(|| Error::Message("metadata plist is not a dictionary".into()))?
        }
    };
    sidecar.insert(
        "v_Data".into(),
        Value::Data(plist_bytes(&Value::Dictionary(metadata.clone()))?),
    );
    sidecar.insert(
        "mdat".into(),
        Value::Date(plist::Date::from(std::time::SystemTime::now())),
    );
    plist_bytes(&Value::Dictionary(sidecar))
}

/// The base64 plist Apple keeps for an item in Recently Deleted: the base
/// dictionary with `-recently-deleted` appended to `agrp` (idempotently) and
/// `mdat` set to the deletion time. Every other key is preserved byte for byte
/// after the plist round trip.
pub(crate) fn trashed_plist(base: &str, label: &str, at: chrono::DateTime<Utc>) -> Result<String> {
    let mut dict = decode_dict(base, label)?;
    trash_dict(&mut dict, at);
    Ok(encode(&plist_bytes(&Value::Dictionary(dict))?))
}

/// The item and sidecar payloads for moving `record` to Recently Deleted.
/// The sidecar is `Some` only when the record has one; a Wi-Fi record has none.
pub(crate) fn trash_payloads(
    record: &RecordMeta,
    at: chrono::DateTime<Utc>,
) -> Result<(Option<String>, Option<String>)> {
    let item_new = record
        .plist
        .as_deref()
        .map(|base| trashed_plist(base, "item", at))
        .transpose()?;
    let sidecar_new = if record.sidecar_name.is_some() {
        let metadata = match record.metadata.as_deref() {
            Some(value) => decode_dict(value, "metadata")?,
            None => {
                let mut dict = new_metadata_dict();
                dict.insert("s_as".into(), Value::Array(Vec::new()));
                dict
            }
        };
        let item = match record.plist.as_deref() {
            Some(value) => decode_dict(value, "item")?,
            None => Dictionary::new(),
        };
        let outer = match record.sidecar_plist.as_deref() {
            Some(value) => value.to_string(),
            None => encode(&sidecar_plist(None, &item, &metadata)?),
        };
        Some(trashed_plist(&outer, "sidecar", at)?)
    } else {
        None
    };
    Ok((item_new, sidecar_new))
}

fn trash_dict(dict: &mut Dictionary, at: chrono::DateTime<Utc>) {
    let agrp = dictionary_text(dict, "agrp").unwrap_or_default();
    let agrp = if agrp.ends_with(RECENTLY_DELETED) {
        agrp
    } else {
        format!("{agrp}{RECENTLY_DELETED}")
    };
    dict.insert("agrp".into(), Value::String(agrp));
    dict.insert(
        "mdat".into(),
        Value::Date(plist::Date::from(std::time::SystemTime::from(at))),
    );
}

fn dictionary_text(dict: &Dictionary, key: &str) -> Option<String> {
    match dict.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Data(bytes) => String::from_utf8(bytes.clone()).ok(),
        _ => None,
    }
}

fn generate_password() -> String {
    let mut rng = rand::thread_rng();
    (0..20)
        .map(|_| GENERATED_CHARSET[rng.gen_range(0..GENERATED_CHARSET.len())] as char)
        .collect()
}

/// Accept a bare host or an http(s) URL and return the canonical URL and host.
fn normalize_url(input: &str) -> Result<(String, String)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Invalid("a site URL is required".into()));
    }
    let rest = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                return Err(Error::Invalid(format!(
                    "unsupported URL scheme {scheme}; use http or https"
                )));
            }
            rest
        }
        None => trimmed,
    };
    // Drop any userinfo before the host.
    let rest = rest.rsplit_once('@').map(|(_, host)| host).unwrap_or(rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((inner, _)) => format!("[{inner}]"),
            None => return Err(Error::Invalid("cannot read a host from the URL".into())),
        }
    } else {
        authority.split(':').next().unwrap_or(authority).to_string()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(Error::Invalid("cannot read a host from the URL".into()));
    }
    Ok((format!("https://{host}"), host))
}

fn prompt_to_make_password() -> Result<String> {
    let first = rpassword::prompt_password("Password: ")?;
    if first.is_empty() {
        return Err(Error::Invalid(
            "password cannot be empty; use --password-stdin for an empty password".into(),
        ));
    }
    let again = rpassword::prompt_password("Password again: ")?;
    if first != again {
        return Err(Error::Invalid("passwords do not match".into()));
    }
    Ok(first)
}

/// Read one line, stripping only the trailing newline (and a paired `\r`).
fn read_stdin_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    strip_newline(&mut line);
    Ok(line)
}

/// Read all of stdin for a multi-line body, stripping the final newline.
fn read_stdin_all() -> Result<String> {
    use std::io::Read;
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    strip_newline(&mut text);
    Ok(text)
}

fn strip_newline(text: &mut String) {
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
}

fn prompt_text(label: &str, current: Option<&str>) -> Result<Option<String>> {
    match current {
        Some(value) => eprint!("{label} [{value}]: "),
        None => eprint!("{label}: "),
    }
    std::io::stderr().flush()?;
    let line = read_stdin_line()?;
    Ok((!line.is_empty()).then_some(line))
}

/// Replace the item secret and record the old value in the password history.
fn apply_password(item: &mut Dictionary, metadata: &mut Dictionary, password: &str) {
    let old = item.get("v_Data").and_then(|value| match value {
        Value::String(text) => Some(text.clone()),
        Value::Data(bytes) => std::str::from_utf8(bytes).ok().map(str::to_string),
        _ => None,
    });
    item.insert("v_Data".into(), Value::Data(password.as_bytes().to_vec()));
    if let Some(old) = old {
        append_password_change(metadata, password, &old, Utc::now());
    }
}

/// Add an op, folding it into a pending Create/Edit for the same record.
fn merge_edit(pending: &mut Vec<PendingOp>, op: PendingOp) -> PendingOp {
    if let Some(existing) = pending.iter_mut().find(|pending| {
        pending.item_name == op.item_name && matches!(pending.kind, OpKind::Create | OpKind::Edit)
    }) {
        // The original base and etags stay: they name the version CloudKit
        // still has, not what this edit produced.
        existing.item_new = op.item_new;
        // A sidecar write must wrap the metadata it replaces. When this edit
        // only changed the item, keep the queued sidecar payload untouched.
        if op.sidecar_dirty {
            existing.sidecar_new = op.sidecar_new;
            existing.sidecar_write = op.sidecar_write;
        }
        existing.item_dirty |= op.item_dirty;
        existing.sidecar_dirty |= op.sidecar_dirty;
        existing.entry_kind = op.entry_kind;
        existing.blocked = None;
        existing.attempts = 0;
        existing.next_attempt = None;
        existing.label = op.label;
        if existing.sidecar_name.is_none() {
            existing.sidecar_name = op.sidecar_name;
        }
        if existing.sidecar_type.is_none() {
            existing.sidecar_type = op.sidecar_type;
        }
        existing.clone()
    } else {
        pending.push(op.clone());
        op
    }
}

/// The base64 payload bytes the pending queue holds.
fn pending_payload_bytes(vault: &Vault) -> usize {
    vault
        .pending
        .iter()
        .map(|op| {
            [
                &op.item_base,
                &op.item_new,
                &op.sidecar_base,
                &op.sidecar_new,
            ]
            .into_iter()
            .filter_map(|payload| payload.as_ref())
            .map(String::len)
            .sum::<usize>()
        })
        .sum()
}

/// Refuse a new op when the queue is already at its cap. `apw sync` drains
/// what it can and `apw resolve` drops what it cannot.
pub(crate) fn ensure_queue_room(vault: &Vault) -> Result<()> {
    let bytes = pending_payload_bytes(vault);
    if vault.pending.len() >= MAX_PENDING_OPS || bytes >= MAX_PENDING_BYTES {
        let mib = bytes as f64 / (1024.0 * 1024.0);
        return Err(Error::Invalid(format!(
            "pending queue is full ({} ops, {mib:.1} MB); run apw sync or apw resolve",
            vault.pending.len()
        )));
    }
    Ok(())
}

fn find_entry(vault: &Vault, query: Option<&str>, id: Option<&str>) -> Result<usize> {
    match (query, id) {
        (None, None) => Err(Error::Invalid("pass a query or --id".into())),
        (query, Some(id)) => {
            let index = vault
                .entries
                .iter()
                .position(|entry| entry.id.eq_ignore_ascii_case(id))
                .ok_or_else(|| Error::NoResults(format!("no entry with id {id}")))?;
            if let Some(query) = query {
                if !vault.entries[index].matches(query) {
                    return Err(Error::NoResults(format!(
                        "no entry matches {query} with id {id}"
                    )));
                }
            }
            Ok(index)
        }
        (Some(query), None) => {
            let matches: Vec<usize> = vault
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    matches!(
                        entry.kind,
                        EntryKind::Login | EntryKind::Note | EntryKind::Wifi
                    ) && !entry.is_placeholder()
                        && entry.matches(query)
                })
                .map(|(index, _)| index)
                .collect();
            match matches.len() {
                0 => Err(Error::NoResults(format!("no entry matches {query}"))),
                1 => Ok(matches[0]),
                count => {
                    let ids = matches
                        .iter()
                        .map(|index| vault.entries[*index].id.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    Err(Error::Invalid(format!(
                        "{count} entries match; pass --id <id> ({ids})"
                    )))
                }
            }
        }
    }
}

/// The label shown for a queued op: the entry name, else its domain, plus the
/// username when there is one.
fn entry_label(entry: &Entry) -> String {
    if entry.kind == EntryKind::Wifi {
        return entry.display_name();
    }
    let mut label = entry.display_name();
    if label.is_empty() {
        label = entry.domain();
    }
    if let Some(username) = entry.username.as_deref().filter(|value| !value.is_empty()) {
        label = format!("{label} ({username})");
    }
    label
}

fn decode_dict(value: &str, label: &str) -> Result<Dictionary> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Message(format!("invalid base64 {label} payload: {error}")))?;
    let parsed: Value = plist::from_bytes(&bytes)?;
    parsed
        .as_dictionary()
        .cloned()
        .ok_or_else(|| Error::Message(format!("stored {label} payload is not a plist dictionary")))
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn kind_name(kind: OpKind) -> &'static str {
    match kind {
        OpKind::Create => "create",
        OpKind::Edit => "edit",
        OpKind::Delete => "delete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> chrono::DateTime<Utc> {
        chrono::DateTime::from_timestamp(seconds, 0).expect("timestamp")
    }

    fn decode(b64: &str) -> Dictionary {
        decode_dict(b64, "test").expect("plist dictionary")
    }

    fn without_trash_keys(dict: &Dictionary) -> Dictionary {
        let mut copy = dict.clone();
        copy.remove("agrp");
        copy.remove("mdat");
        copy
    }

    #[test]
    fn trashing_a_login_changes_only_agrp_and_mdat() {
        let base = plist_bytes(&new_login_plist("example.com", "alice", b"hunter2")).unwrap();
        let original = decode(&encode(&base));
        let deleted_at = at(1_800_000_000);

        let trashed = decode(&trashed_plist(&encode(&base), "item", deleted_at).unwrap());

        assert_eq!(
            trashed.get("agrp").and_then(Value::as_string),
            Some("com.apple.cfnetwork-recently-deleted")
        );
        assert_eq!(
            trashed.get("mdat").and_then(Value::as_date),
            Some(plist::Date::from(std::time::SystemTime::from(deleted_at)))
        );
        assert_eq!(
            trashed.get("v_Data").and_then(Value::as_data),
            Some(b"hunter2".as_slice())
        );
        for key in ["labl", "acct", "srvr", "cdat", "sha1"] {
            assert_eq!(trashed.get(key), original.get(key), "{key} is preserved");
        }
        assert_eq!(without_trash_keys(&trashed), without_trash_keys(&original));
    }

    #[test]
    fn trashing_a_wifi_item_only_touches_agrp_and_mdat() {
        let base = plist_bytes(&new_wifi_plist("HomeNet", b"wifi-pass")).unwrap();
        let deleted_at = at(1_800_000_000);

        let trashed = decode(&trashed_plist(&encode(&base), "item", deleted_at).unwrap());

        assert_eq!(
            trashed.get("agrp").and_then(Value::as_string),
            Some("apple-recently-deleted")
        );
        assert_eq!(
            trashed.get("v_Data").and_then(Value::as_data),
            Some(b"wifi-pass".as_slice())
        );
        assert_eq!(
            trashed.get("svce").and_then(Value::as_string),
            Some("AirPort")
        );
    }

    #[test]
    fn trashing_a_sidecar_uses_the_password_manager_suffix() {
        let metadata = new_note_metadata("Example", "note");
        let outer = new_metadata_plist("example.com", "alice", &metadata);

        let trashed = decode(
            &trashed_plist(&encode(&plist_bytes(&outer).unwrap()), "sidecar", at(1)).unwrap(),
        );

        assert_eq!(
            trashed.get("agrp").and_then(Value::as_string),
            Some("com.apple.password-manager-recently-deleted")
        );
    }

    #[test]
    fn trashing_twice_keeps_one_suffix_and_refreshes_mdat() {
        let base = plist_bytes(&new_login_plist("example.com", "alice", b"hunter2")).unwrap();
        let once = trashed_plist(&encode(&base), "item", at(1_000)).unwrap();
        let twice = trashed_plist(&once, "item", at(2_000)).unwrap();

        let trashed = decode(&twice);
        assert_eq!(
            trashed.get("agrp").and_then(Value::as_string),
            Some("com.apple.cfnetwork-recently-deleted")
        );
        assert_eq!(
            trashed.get("mdat").and_then(Value::as_date),
            Some(plist::Date::from(std::time::SystemTime::from(at(2_000))))
        );
    }

    fn sidecar_record_meta(plist: &str, outer: bool) -> RecordMeta {
        let metadata = new_note_metadata("Example", "note");
        RecordMeta {
            zone: "Passwords".into(),
            item_type: "item".into(),
            plist: Some(plist.into()),
            sidecar_name: Some(uuid()),
            sidecar_type: Some("item".into()),
            metadata: Some(encode(
                &plist_bytes(&Value::Dictionary(metadata.clone())).unwrap(),
            )),
            sidecar_plist: outer.then(|| {
                encode(
                    &plist_bytes(&new_metadata_plist("example.com", "alice", &metadata)).unwrap(),
                )
            }),
            ..RecordMeta::default()
        }
    }

    #[test]
    fn trashing_a_login_with_a_sidecar_returns_both_payloads() {
        let login =
            encode(&plist_bytes(&new_login_plist("example.com", "alice", b"hunter2")).unwrap());

        for outer in [true, false] {
            let record = sidecar_record_meta(&login, outer);
            let (item, sidecar) = trash_payloads(&record, at(1_800_000_000)).expect("trash");

            let item = decode(&item.expect("item payload"));
            assert_eq!(
                item.get("agrp").and_then(Value::as_string),
                Some("com.apple.cfnetwork-recently-deleted")
            );
            let sidecar = decode(&sidecar.expect("sidecar payload"));
            assert_eq!(
                sidecar.get("agrp").and_then(Value::as_string),
                Some("com.apple.password-manager-recently-deleted")
            );
        }
    }

    #[test]
    fn trashing_a_wifi_record_returns_only_the_item() {
        let wifi = encode(&plist_bytes(&new_wifi_plist("HomeNet", b"wifi-pass")).unwrap());
        let record = RecordMeta {
            zone: "WiFi".into(),
            item_type: "item".into(),
            plist: Some(wifi),
            ..RecordMeta::default()
        };

        let (item, sidecar) = trash_payloads(&record, at(1)).expect("trash");

        let item = decode(&item.expect("item payload"));
        assert_eq!(
            item.get("agrp").and_then(Value::as_string),
            Some("apple-recently-deleted")
        );
        assert!(sidecar.is_none());
    }

    fn queued_op(payload: Option<String>) -> PendingOp {
        PendingOp {
            id: uuid(),
            kind: OpKind::Edit,
            entry_kind: EntryKind::Login,
            zone: "Passwords".into(),
            owner: None,
            item_name: uuid(),
            item_type: "item".into(),
            item_base: None,
            item_new: payload,
            item_etag: None,
            item_dirty: true,
            sidecar_name: None,
            sidecar_type: None,
            sidecar_base: None,
            sidecar_new: None,
            sidecar_write: None,
            sidecar_etag: None,
            sidecar_dirty: false,
            blocked: None,
            attempts: 0,
            next_attempt: None,
            force: false,
            label: String::new(),
        }
    }

    #[test]
    fn the_queue_cap_counts_ops() {
        let mut vault = Vault {
            pending: (0..MAX_PENDING_OPS).map(|_| queued_op(None)).collect(),
            ..Vault::default()
        };

        let error = ensure_queue_room(&vault).expect_err("a full queue is refused");

        let text = error.to_string();
        assert!(text.contains("pending queue is full (200 ops"), "{text}");
        assert!(text.contains("apw sync"), "{text}");
        assert!(text.contains("apw resolve"), "{text}");

        vault.pending.pop();
        ensure_queue_room(&vault).expect("one slot free");
    }

    #[test]
    fn the_queue_cap_counts_payload_bytes() {
        let mut vault = Vault {
            pending: vec![queued_op(Some("A".repeat(MAX_PENDING_BYTES)))],
            ..Vault::default()
        };
        let error = ensure_queue_room(&vault).expect_err("an oversized queue is refused");
        assert!(error.to_string().contains("MB"), "{error}");

        vault.pending = vec![queued_op(Some("A".repeat(MAX_PENDING_BYTES - 1)))];
        ensure_queue_room(&vault).expect("one byte under the cap");
    }

    #[test]
    fn note_metadata_stores_title_and_body_as_data() {
        let metadata = new_note_metadata("Trip ideas", "Pack light");
        assert_eq!(
            metadata.get("title").and_then(Value::as_data),
            Some(b"Trip ideas".as_slice())
        );
        assert_eq!(
            metadata.get("notes").and_then(Value::as_data),
            Some(b"Pack light".as_slice())
        );
        assert_eq!(
            metadata.get("s_as").and_then(Value::as_array).map(Vec::len),
            Some(0)
        );
        assert!(metadata.get("s_hi").is_none());
    }
}
