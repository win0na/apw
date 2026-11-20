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
fn login_explains_how_to_start_anisette() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .env("APW_PASSWORD", "test password")
        .env("APW_ANISETTE_URL", "::bad")
        .args(["login", "--account", "a@b.c"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("podman run"))
        .stderr(predicate::str::contains("anisette-server-rs"));
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
