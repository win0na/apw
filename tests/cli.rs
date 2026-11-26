use assert_cmd::Command;
use base64::Engine;
use predicates::prelude::*;
use tempfile::TempDir;

fn apw(dir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("apw").expect("binary");
    command
        .env("APW_CONFIG_DIR", dir.path().join("config"))
        .env("APW_DATA_DIR", dir.path().join("data"))
        .env("APW_STATE_DIR", dir.path().join("state"))
        .env("APW_PASSPHRASE", "test passphrase")
        .env_remove("APW_FIXTURE")
        .env_remove("APW_ANISETTE_URL");
    command
}

fn sync(dir: &TempDir) {
    apw(dir)
        .args(["sync", "--fixture", "tests/fixtures/vault.json"])
        .assert()
        .success();
}

#[test]
fn sync_writes_an_encrypted_snapshot() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let snapshot = std::fs::read(dir.path().join("data/snapshot.bin")).unwrap();
    assert!(snapshot.starts_with(b"APWSNAP\x00"));
    assert!(!snapshot
        .windows(7)
        .any(|window| window == b"hunter2".as_slice()));
    assert!(!snapshot
        .windows(7)
        .any(|window| window == b"example".as_slice()));
}

#[test]
fn join_requires_a_session() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .args(["join"])
        .env("APW_ESCROW_PASSCODE", "1234")
        .assert()
        .failure()
        .stderr(predicate::str::contains("login"));
}

#[test]
fn live_sync_requires_a_session() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .args(["sync", "--force"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("login"));
}

#[test]
fn pw_get_returns_the_password() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["get", "example.com", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], 0);
    assert_eq!(value["data"][0]["username"], "alice");
    assert_eq!(value["data"][0]["password"], "hunter2");
    assert_eq!(value["data"][0]["name"], "Example");
    assert_eq!(value["data"][0]["domain"], "example.com");
}

#[test]
fn pw_get_filters_by_username() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    apw(&dir)
        .args(["get", "example.com", "--username", "bob", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("\"status\":3"));
}

#[test]
fn pw_list_hides_notes_and_passwords() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let results = value["data"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|entry| entry["password"].is_null()));
    assert!(results.iter().all(|entry| entry["title"] != "Guest Wi-Fi"));
}

#[test]
fn otp_get_returns_a_six_digit_code() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["otp", "example.com", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let code = value["data"][0]["code"].as_str().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(value["data"][0]["source"], "Example");
}

#[test]
fn wrong_passphrase_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    apw(&dir)
        .env("APW_PASSPHRASE", "wrong passphrase")
        .args(["get", "example.com", "--json"])
        .assert()
        .code(6)
        .stderr(predicate::str::contains("cannot decrypt the snapshot"))
        .stderr(predicate::str::contains("\"code\":\"locked\""));
}

#[test]
fn missing_snapshot_points_at_login() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .args(["list", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("run `apw login` first"));
}

#[test]
fn status_reports_the_snapshot() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["entries"], 3);
    assert_eq!(value["data"]["logins"], 2);
    assert_eq!(value["data"]["wifi"], 1);
    assert_eq!(value["data"]["groups"], 1);
    assert_eq!(value["data"]["source"], "fixture");
}

#[test]
fn group_show_lists_the_items_in_a_group() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["group", "show", "Family", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["name"], "Family");
    assert_eq!(value["data"]["zone"], "group-family");
    let items = value["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], "login-github");
    assert_eq!(items[0]["kind"], "login");
}

#[test]
fn group_show_unknown_group_fails() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    apw(&dir)
        .args(["group", "show", "nowhere"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no group"));
}

#[test]
fn pw_wifi_lists_networks_and_get_returns_the_password() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir).args(["wifi", "--json"]).output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"][0]["domain"], "HomeNet");

    let output = apw(&dir)
        .args(["get", "HomeNet", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"][0]["password"], "wifi-secret");
}

#[test]
fn login_explains_an_unreachable_anisette_server() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .env("APW_PASSWORD", "test password")
        .env("APW_ANISETTE_URL", "::bad")
        .args(["login", "--account", "a@b.c"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot use the anisette server"))
        .stderr(predicate::str::contains("APW_ANISETTE_URL"));
}

#[test]
fn get_returns_every_match() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["get", "e", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"].as_array().unwrap().len(), 2);
}

#[test]
fn get_password_only_prints_one_password_per_line() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["get", "e", "--password-only"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert_eq!(text, "hunter2\nwifi-secret\n");
}

#[test]
fn missing_session_uses_the_auth_exit_code() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .args(["join"])
        .env("APW_ESCROW_PASSCODE", "1234")
        .assert()
        .code(4);
}

#[test]
fn otp_query_prints_a_code_through_a_pipe() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir).args(["otp", "example.com"]).output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let code = text.trim();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn wifi_json_does_not_include_the_password() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir).args(["wifi", "--json"]).output().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["data"][0]["password"].is_null());
}

#[test]
fn usage_errors_keep_the_json_envelope() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .args(["--json", "get"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("\"code\":\"usage\""));
}

fn json_of(dir: &TempDir, args: &[&str]) -> serde_json::Value {
    let output = apw(dir).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "apw {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// A fixture whose login carries a decrypted item payload, so `edit` and `rm`
/// have a CloudKit base to work from.
fn record_fixture(dir: &TempDir) -> std::path::PathBuf {
    let mut item = plist::Dictionary::new();
    item.insert(
        "v_Data".into(),
        plist::Value::Data(b"old-password".to_vec()),
    );
    item.insert("srvr".into(), plist::Value::String("example.com".into()));
    item.insert("acct".into(), plist::Value::String("alice".into()));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(item)).unwrap();
    let plist = base64::engine::general_purpose::STANDARD.encode(bytes);

    let fixture = serde_json::json!({
        "version": 1,
        "account": "user@example.com",
        "entries": [
            {
                "id": "login-record",
                "kind": "login",
                "title": "Example",
                "url": "https://example.com",
                "sites": ["example.com"],
                "username": "alice",
                "password": "old-password",
                "record": {
                    "zone": "Passwords",
                    "item_type": "item",
                    "item_etag": "etag-1",
                    "plist": plist,
                    "sidecar_etag": "etag-2"
                }
            }
        ],
        "groups": []
    });
    let path = dir.path().join("record-fixture.json");
    std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    path
}

#[test]
fn add_login_queues_a_create() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args([
            "add",
            "login",
            "example.org",
            "--username",
            "carol",
            "--title",
            "Example Org",
            "--password-stdin",
            "--json",
        ])
        .write_stdin("s3cret\n")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], 0);
    assert!(!value["data"]["id"].as_str().unwrap().is_empty());
    assert!(!value["data"]["pending_id"].as_str().unwrap().is_empty());
    assert_eq!(value["data"]["label"], "Example Org (carol)");

    let list = json_of(&dir, &["list", "--json"]);
    let added = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["domain"] == "example.org")
        .expect("added entry is listed");
    assert_eq!(added["name"], "Example Org");
    assert_eq!(added["url"], "https://example.org");
    assert_eq!(added["username"], "carol");

    let pending = json_of(&dir, &["pending", "--json"]);
    let ops = pending["data"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["kind"], "create");
    assert_eq!(ops[0]["id"], value["data"]["pending_id"]);
    assert_eq!(ops[0]["state"], "pending");
}

#[test]
fn add_login_generate_stores_a_twenty_character_password() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["add", "login", "gen.example", "--generate", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("generated password:"));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let password = value["data"]["password"].as_str().unwrap();
    assert_eq!(password.chars().count(), 20);

    let get = json_of(&dir, &["get", "gen.example", "--json"]);
    assert_eq!(get["data"][0]["password"], password);
}

#[test]
fn edit_queues_one_edit_and_merges_the_next() {
    let dir = TempDir::new().unwrap();
    let fixture = record_fixture(&dir);
    apw(&dir)
        .args(["sync", "--fixture", fixture.to_str().unwrap()])
        .assert()
        .success();

    apw(&dir)
        .args(["edit", "--id", "login-record", "--title", "New", "--json"])
        .assert()
        .success();

    let list = json_of(&dir, &["list", "--json"]);
    assert_eq!(list["data"][0]["name"], "New");
    let pending = json_of(&dir, &["pending", "--json"]);
    assert_eq!(pending["data"].as_array().unwrap().len(), 1);
    assert_eq!(pending["data"][0]["kind"], "edit");

    apw(&dir)
        .args(["edit", "--id", "login-record", "--notes", "x", "--json"])
        .assert()
        .success();

    let pending = json_of(&dir, &["pending", "--json"]);
    let ops = pending["data"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["kind"], "edit");
    assert_eq!(ops[0]["item_name"], "login-record");
}

#[test]
fn edit_with_two_matches_asks_for_an_id() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    apw(&dir)
        .args(["edit", "com", "--title", "Nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass --id"));
}

#[test]
fn rm_requires_yes_and_queues_a_delete() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args([
            "add",
            "login",
            "rm.example",
            "--title",
            "Removable",
            "--password-stdin",
            "--json",
        ])
        .write_stdin("s3cret\n")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = value["data"]["id"].as_str().unwrap().to_string();

    apw(&dir)
        .args(["rm", "--id", &id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--yes"));

    apw(&dir)
        .args(["rm", "--id", &id, "--yes", "--json"])
        .assert()
        .success();

    let list = json_of(&dir, &["list", "--json"]);
    assert!(list["data"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["id"] != id));

    let pending = json_of(&dir, &["pending", "--json"]);
    let ops = pending["data"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["kind"], "delete");
    assert_eq!(ops[0]["item_name"], id);
    assert_eq!(ops[0]["label"], "Removable");
}

#[test]
fn add_login_dry_run_leaves_the_vault_untouched() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let before_list = json_of(&dir, &["list", "--json"]);
    let before_pending = json_of(&dir, &["pending", "--json"]);

    apw(&dir)
        .args([
            "add",
            "login",
            "dry.example",
            "--title",
            "Dry",
            "--password-stdin",
            "--dry-run",
        ])
        .write_stdin("s3cret\n")
        .assert()
        .success();

    let after_list = json_of(&dir, &["list", "--json"]);
    let after_pending = json_of(&dir, &["pending", "--json"]);
    assert_eq!(before_list, after_list);
    assert_eq!(before_pending, after_pending);
}

#[test]
fn resolve_keeps_or_drops_a_pending_op() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args([
            "add",
            "login",
            "resolve.example",
            "--password-stdin",
            "--json",
        ])
        .write_stdin("s3cret\n")
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = value["data"]["pending_id"].as_str().unwrap().to_string();

    apw(&dir)
        .args(["resolve", &id, "--local", "--json"])
        .assert()
        .success();
    let pending = json_of(&dir, &["pending", "--json"]);
    assert_eq!(pending["data"].as_array().unwrap().len(), 1);

    apw(&dir)
        .args(["resolve", &id, "--remote", "--json"])
        .assert()
        .success();
    let pending = json_of(&dir, &["pending", "--json"]);
    assert!(pending["data"].as_array().unwrap().is_empty());
}

/// A login plist as Apple keeps it in Recently Deleted: `agrp` carries the
/// suffix and every other key is unchanged.
fn trashed_login(id: &str, title: &str, site: &str, username: &str) -> serde_json::Value {
    let mut item = plist::Dictionary::new();
    item.insert(
        "agrp".into(),
        plist::Value::String("com.apple.cfnetwork-recently-deleted".into()),
    );
    item.insert("srvr".into(), plist::Value::String(site.into()));
    item.insert("acct".into(), plist::Value::String(username.into()));
    item.insert("labl".into(), plist::Value::String(title.into()));
    item.insert(
        "v_Data".into(),
        plist::Value::Data(b"old-password".to_vec()),
    );
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(item)).unwrap();
    let plist = base64::engine::general_purpose::STANDARD.encode(bytes);
    let record = serde_json::json!({
        "zone": "Passwords",
        "item_type": "item",
        "item_etag": "etag-trash",
        "plist": plist,
    });
    serde_json::json!({
        "entry": {
            "id": id,
            "kind": "login",
            "agrp": "com.apple.cfnetwork-recently-deleted",
            "title": title,
            "url": format!("https://{site}"),
            "sites": [site],
            "username": username,
            "password": "old-password",
            "record": record,
        },
        "record": record,
        "deleted_at": "2026-01-02T03:04:05Z",
    })
}

/// A fixture with two trashed logins; both match the query "example".
fn trash_fixture(dir: &TempDir) -> std::path::PathBuf {
    let fixture = serde_json::json!({
        "version": 1,
        "account": "user@example.com",
        "entries": [],
        "trash": [
            trashed_login("trash-a", "Alpha", "example.com", "alice"),
            trashed_login("trash-b", "Beta", "example.org", "bob"),
        ],
        "groups": []
    });
    let path = dir.path().join("trash-fixture.json");
    std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    path
}

fn sync_trash_fixture(dir: &TempDir) {
    let fixture = trash_fixture(dir);
    apw(dir)
        .args(["sync", "--fixture", fixture.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn trash_lists_recently_deleted_and_restore_queues_an_edit() {
    let dir = TempDir::new().unwrap();
    sync_trash_fixture(&dir);

    let trash = json_of(&dir, &["trash", "--json"]);
    let rows = trash["data"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .any(|row| row["id"] == "trash-a" && row["deleted_at"] == "2026-01-02T03:04:05+00:00"));

    // Trashed items are not listed as live entries.
    let list = json_of(&dir, &["list", "--json"]);
    assert!(list["data"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["id"] != "trash-a"));

    let restored = json_of(&dir, &["restore", "--id", "trash-a", "--json"]);
    assert_eq!(restored["data"]["id"], "trash-a");
    assert_eq!(restored["data"]["name"], "Alpha");
    assert_eq!(restored["data"]["username"], "alice");
    assert_eq!(restored["data"]["restored"], true);

    let list = json_of(&dir, &["list", "--json"]);
    assert!(list["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["id"] == "trash-a"));

    let trash = json_of(&dir, &["trash", "--json"]);
    assert!(trash["data"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["id"] != "trash-a"));

    let pending = json_of(&dir, &["pending", "--json"]);
    let ops = pending["data"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["kind"], "edit");
    assert_eq!(ops[0]["item_name"], "trash-a");
    assert_eq!(ops[0]["label"], "Alpha (alice)");
}

#[test]
fn restore_with_two_matches_asks_for_an_id() {
    let dir = TempDir::new().unwrap();
    sync_trash_fixture(&dir);

    apw(&dir)
        .args(["restore", "example"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass --id"));
}

#[test]
fn restore_dry_run_changes_nothing() {
    let dir = TempDir::new().unwrap();
    sync_trash_fixture(&dir);
    let before_trash = json_of(&dir, &["trash", "--json"]);
    let before_pending = json_of(&dir, &["pending", "--json"]);

    apw(&dir)
        .args(["restore", "--id", "trash-a", "--dry-run", "--json"])
        .assert()
        .success();

    assert_eq!(before_trash, json_of(&dir, &["trash", "--json"]));
    assert_eq!(before_pending, json_of(&dir, &["pending", "--json"]));
    let list = json_of(&dir, &["list", "--json"]);
    assert!(list["data"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["id"] != "trash-a"));
}

#[test]
fn restore_before_sync_cancels_a_pending_delete() {
    let dir = TempDir::new().unwrap();
    let fixture = record_fixture(&dir);
    apw(&dir)
        .args(["sync", "--fixture", fixture.to_str().unwrap()])
        .assert()
        .success();
    apw(&dir)
        .args(["rm", "--id", "login-record", "--yes"])
        .assert()
        .success();
    assert_eq!(
        json_of(&dir, &["pending", "--json"])["data"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let restored = json_of(&dir, &["restore", "--id", "login-record", "--json"]);
    assert_eq!(restored["data"]["restored"], true);

    let pending = json_of(&dir, &["pending", "--json"]);
    assert!(pending["data"].as_array().unwrap().is_empty());
    let list = json_of(&dir, &["list", "--json"]);
    assert!(list["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["id"] == "login-record"));
}

fn write_cxf(path: &std::path::Path, credential_id: &str, user_handle: &str, username: &str) {
    use p256::pkcs8::EncodePrivateKey;

    let key = p256::SecretKey::random(&mut rand::thread_rng());
    let der = key.to_pkcs8_der().unwrap();
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let file = serde_json::json!({
        "version": {"major": 1, "minor": 0},
        "exporterRpId": "webauthn.io",
        "exporterDisplayName": "webauthn.io",
        "timestamp": 1_700_000_000,
        "accounts": [{
            "id": encode(b"account"),
            "username": "alice",
            "email": "alice@example.com",
            "collections": [],
            "items": [{
                "id": encode(b"item"),
                "creationAt": 1_700_000_000,
                "title": "webauthn.io",
                "credentials": [{
                    "type": "passkey",
                    "credentialId": credential_id,
                    "rpId": "webauthn.io",
                    "username": username,
                    "userDisplayName": "Alice",
                    "userHandle": user_handle,
                    "key": encode(der.as_bytes()),
                }]
            }]
        }]
    });
    std::fs::write(path, file.to_string()).unwrap();
}

#[test]
fn passkey_import_queues_one_create() {
    let dir = TempDir::new().unwrap();
    sync(&dir);
    let file = dir.path().join("passkeys.json");
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"credential");
    let user_handle = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"user");
    write_cxf(&file, &credential_id, &user_handle, "alice");

    let value = json_of(
        &dir,
        &["passkey", "import", file.to_str().unwrap(), "--json"],
    );

    let imported = value["data"]["imported"].as_array().unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0]["name"], "webauthn.io");
    assert_eq!(imported[0]["rp_id"], "webauthn.io");
    assert_eq!(imported[0]["username"], "alice");
    assert!(imported[0]["pending_id"].as_str().is_some());
    assert_eq!(value["data"]["skipped"].as_array().unwrap().len(), 0);

    let pending = json_of(&dir, &["pending", "--json"]);
    let ops = pending["data"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["kind"], "create");
    assert_eq!(ops[0]["item_name"], imported[0]["id"]);
    assert_eq!(ops[0]["id"], imported[0]["pending_id"]);
}

#[test]
fn passkey_import_dry_run_writes_nothing() {
    let dir = TempDir::new().unwrap();
    sync(&dir);
    let file = dir.path().join("passkeys.json");
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"credential");
    let user_handle = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"user");
    write_cxf(&file, &credential_id, &user_handle, "alice");

    let value = json_of(
        &dir,
        &[
            "passkey",
            "import",
            file.to_str().unwrap(),
            "--dry-run",
            "--json",
        ],
    );

    assert_eq!(value["data"]["dry_run"], true);
    let imported = value["data"]["imported"].as_array().unwrap();
    assert_eq!(imported.len(), 1);
    assert!(imported[0]["pending_id"].is_null());
    assert_eq!(value["data"]["skipped"].as_array().unwrap().len(), 0);
    let pending = json_of(&dir, &["pending", "--json"]);
    assert_eq!(pending["data"].as_array().unwrap().len(), 0);
}

#[test]
fn passkey_import_skips_duplicates_in_the_snapshot() {
    let dir = TempDir::new().unwrap();
    sync(&dir);
    let first = dir.path().join("first.json");
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"credential");
    let user_handle = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"user");
    write_cxf(&first, &credential_id, &user_handle, "alice");
    apw(&dir)
        .args(["passkey", "import", first.to_str().unwrap(), "--json"])
        .assert()
        .success();

    let same = json_of(
        &dir,
        &["passkey", "import", first.to_str().unwrap(), "--json"],
    );
    assert_eq!(same["data"]["imported"].as_array().unwrap().len(), 0);
    assert_eq!(same["data"]["skipped"][0]["reason"], "already imported");

    let other = dir.path().join("other.json");
    let other_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"other");
    write_cxf(&other, &other_id, &user_handle, "alice");
    let account = json_of(
        &dir,
        &["passkey", "import", other.to_str().unwrap(), "--json"],
    );
    assert_eq!(account["data"]["imported"].as_array().unwrap().len(), 0);
    assert_eq!(
        account["data"]["skipped"][0]["reason"],
        "another passkey for this account already exists"
    );

    let pending = json_of(&dir, &["pending", "--json"]);
    assert_eq!(pending["data"].as_array().unwrap().len(), 1);
}

#[test]
fn passkey_import_rejects_a_wrong_major_version() {
    let dir = TempDir::new().unwrap();
    sync(&dir);
    let file = dir.path().join("bad.json");
    std::fs::write(&file, r#"{"version": {"major": 2, "minor": 0}}"#).unwrap();

    apw(&dir)
        .args(["passkey", "import", file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "CXF major version 2 is not supported",
        ));
}

/// A fixture whose only passkey sits in Recently Deleted.
fn trashed_passkey_fixture(
    dir: &TempDir,
    credential_id: &[u8],
    user_handle: &[u8],
) -> std::path::PathBuf {
    assert!(user_handle.len() < 24);
    let mut atag = vec![0xA1, 0x62, b'i', b'd', 0x40 | user_handle.len() as u8];
    atag.extend_from_slice(user_handle);

    let mut item = plist::Dictionary::new();
    item.insert("labl".into(), plist::Value::String("webauthn.io".into()));
    item.insert("alis".into(), plist::Value::Data(credential_id.to_vec()));
    item.insert("atag".into(), plist::Value::Data(atag));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(item)).unwrap();
    let plist = base64::engine::general_purpose::STANDARD.encode(bytes);

    let fixture = serde_json::json!({
        "version": 1,
        "account": "user@example.com",
        "entries": [],
        "trash": [{
            "entry": {
                "id": "trashed-passkey",
                "kind": "passkey",
                "title": "webauthn.io",
                "sites": ["webauthn.io"],
                "passkey": {"relying_party": "webauthn.io"},
                "record": {
                    "zone": "Passwords",
                    "item_type": "item",
                    "plist": plist
                }
            },
            "record": {
                "zone": "Passwords",
                "item_type": "item",
                "plist": plist
            }
        }],
        "groups": []
    });
    let path = dir.path().join("trash-fixture.json");
    std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    path
}

#[test]
fn passkey_import_skips_credentials_in_recently_deleted() {
    let dir = TempDir::new().unwrap();
    let credential_id = b"trashed-credential";
    let user_handle = b"user";
    let fixture = trashed_passkey_fixture(&dir, credential_id, user_handle);
    apw(&dir)
        .args(["sync", "--fixture", fixture.to_str().unwrap()])
        .assert()
        .success();

    let same = dir.path().join("same.json");
    write_cxf(
        &same,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_handle),
        "alice",
    );
    let value = json_of(
        &dir,
        &["passkey", "import", same.to_str().unwrap(), "--json"],
    );
    assert_eq!(value["data"]["imported"].as_array().unwrap().len(), 0);
    assert_eq!(
        value["data"]["skipped"][0]["reason"],
        "already in Recently Deleted"
    );

    let account = dir.path().join("account.json");
    write_cxf(
        &account,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"new-credential"),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_handle),
        "alice",
    );
    let value = json_of(
        &dir,
        &["passkey", "import", account.to_str().unwrap(), "--json"],
    );
    assert_eq!(value["data"]["imported"].as_array().unwrap().len(), 0);
    assert_eq!(
        value["data"]["skipped"][0]["reason"],
        "already in Recently Deleted"
    );

    let pending = json_of(&dir, &["pending", "--json"]);
    assert_eq!(pending["data"].as_array().unwrap().len(), 0);
}

/// A fixture with one live passkey whose plist carries valid export material.
fn passkey_export_fixture(dir: &TempDir) -> (std::path::PathBuf, Vec<u8>) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let key = p256::SecretKey::random(&mut rand::thread_rng());
    let point = key.public_key().to_encoded_point(false);
    let mut v_data = point.as_bytes().to_vec();
    v_data.extend_from_slice(&key.to_bytes());

    let credential_id = b"exported-credential".to_vec();
    let user_handle = b"user".to_vec();
    let mut atag = vec![0xA3];
    atag.extend_from_slice(&[0x62, b'i', b'd', 0x40 | user_handle.len() as u8]);
    atag.extend_from_slice(&user_handle);
    atag.extend_from_slice(&[0x64, b'n', b'a', b'm', b'e', 0x65]);
    atag.extend_from_slice(b"alice");
    atag.extend_from_slice(&[0x6b]);
    atag.extend_from_slice(b"displayName");
    atag.extend_from_slice(&[0x65]);
    atag.extend_from_slice(b"Alice");

    let mut item = plist::Dictionary::new();
    item.insert("labl".into(), plist::Value::String("webauthn.io".into()));
    item.insert("alis".into(), plist::Value::Data(credential_id.clone()));
    item.insert("atag".into(), plist::Value::Data(atag));
    item.insert("v_Data".into(), plist::Value::Data(v_data));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(item)).unwrap();
    let plist = base64::engine::general_purpose::STANDARD.encode(bytes);

    let fixture = serde_json::json!({
        "version": 1,
        "account": "winnie@example.com",
        "entries": [{
            "id": "passkey-1",
            "kind": "passkey",
            "title": "webauthn.io",
            "sites": ["webauthn.io"],
            "passkey": {"relying_party": "webauthn.io", "username": "alice"},
            "record": {
                "zone": "Passwords",
                "item_type": "item",
                "plist": plist
            }
        }],
        "groups": []
    });
    let path = dir.path().join("export-fixture.json");
    std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    (path, credential_id)
}

#[test]
fn passkey_export_writes_a_cxf_file_and_refuses_overwrite() {
    let dir = TempDir::new().unwrap();
    let (fixture, credential_id) = passkey_export_fixture(&dir);
    apw(&dir)
        .args(["sync", "--fixture", fixture.to_str().unwrap()])
        .assert()
        .success();

    let output = dir.path().join("passkeys.json");
    let value = json_of(
        &dir,
        &["passkey", "export", output.to_str().unwrap(), "--json"],
    );
    assert_eq!(value["data"]["exported"], 1);
    assert_eq!(value["data"]["skipped"].as_array().unwrap().len(), 0);
    assert!(output.exists());

    let text = std::fs::read_to_string(&output).unwrap();
    let parsed = apw::cxf::parse(&text).unwrap();
    assert_eq!(parsed.passkeys.len(), 1);
    assert_eq!(parsed.passkeys[0].credential_id, credential_id);
    assert_eq!(parsed.passkeys[0].rp_id, "webauthn.io");
    assert_eq!(parsed.passkeys[0].username, "alice");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&output).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    apw(&dir)
        .args(["passkey", "export", output.to_str().unwrap()])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--force"));

    apw(&dir)
        .args(["passkey", "export", output.to_str().unwrap(), "--force"])
        .assert()
        .success();
}
