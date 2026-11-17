use assert_cmd::Command;
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
        .args(["join", "--passcode", "1234"])
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
        .args(["pw", "get", "example.com", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], 0);
    assert_eq!(value["results"][0]["username"], "alice");
    assert_eq!(value["results"][0]["password"], "hunter2");
    assert_eq!(value["results"][0]["domain"], "example.com");
}

#[test]
fn pw_get_filters_by_username() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    apw(&dir)
        .args(["pw", "get", "example.com", "--username", "bob", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("\"status\":3"));
}

#[test]
fn pw_list_hides_notes_and_passwords() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["pw", "list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let results = value["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|entry| entry["password"].is_null()));
    assert!(results.iter().all(|entry| entry["title"] != "Guest Wi-Fi"));
}

#[test]
fn otp_get_returns_a_six_digit_code() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir)
        .args(["otp", "get", "example.com", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let code = value["results"][0]["code"].as_str().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(value["results"][0]["source"], "Example");
}

#[test]
fn wrong_passphrase_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    apw(&dir)
        .env("APW_PASSPHRASE", "wrong passphrase")
        .args(["pw", "get", "example.com", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot decrypt the snapshot"));
}

#[test]
fn missing_snapshot_points_at_sync() {
    let dir = TempDir::new().unwrap();
    apw(&dir)
        .args(["pw", "list", "--json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("run `apw sync` first"));
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
    assert_eq!(value["results"][0]["entries"], 3);
    assert_eq!(value["results"][0]["logins"], 2);
    assert_eq!(value["results"][0]["wifi"], 1);
    assert_eq!(value["results"][0]["groups"], 1);
    assert_eq!(value["results"][0]["source"], "fixture");
}

#[test]
fn pw_wifi_lists_networks_and_get_returns_the_password() {
    let dir = TempDir::new().unwrap();
    sync(&dir);

    let output = apw(&dir).args(["pw", "wifi", "--json"]).output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["results"].as_array().unwrap().len(), 1);
    assert_eq!(value["results"][0]["domain"], "HomeNet");

    let output = apw(&dir)
        .args(["pw", "get", "HomeNet", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["results"][0]["password"], "wifi-secret");
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
