//! Live checks against Apple's GrandSlam gateway.
//!
//! Ignored by default because they provision a real device identity and touch
//! the network. Run with:
//!
//! ```sh
//! APW_LIVE_ADI=1 cargo test --test adi_live -- --ignored --nocapture
//! ```

use std::path::PathBuf;

use apw::auth::anisette::{Anisette, Identity};
use apw::config::{Config, Paths};
use base64::Engine as _;
use plist::{Dictionary, Value};
use rand::RngCore;

fn paths(root: &std::path::Path) -> Paths {
    Paths {
        config_dir: root.join("config"),
        config_file: root.join("config/config.toml"),
        data_dir: root.join("data"),
        snapshot_file: root.join("data/snapshot.bin"),
        state_dir: root.join("state"),
        state_file: root.join("state/state.json"),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn init_body(identity: &Identity) -> Value {
    let mut cpd = Dictionary::new();
    for (name, value) in &identity.headers {
        cpd.insert(name.clone(), Value::String(value.clone()));
    }
    cpd.insert("bootstrap".into(), Value::Boolean(true));
    cpd.insert("icscrec".into(), Value::Boolean(true));
    cpd.insert("pbe".into(), Value::Boolean(false));
    cpd.insert("prkgen".into(), Value::Boolean(true));
    cpd.insert("svct".into(), Value::String("iCloud".into()));

    let mut public = vec![0_u8; 256];
    rand::thread_rng().fill_bytes(&mut public);
    let account = format!(
        "apw-check-{}@example.invalid",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
    );

    let mut request = Dictionary::new();
    request.insert("cpd".into(), Value::Dictionary(cpd));
    request.insert("A2k".into(), Value::Data(public));
    request.insert(
        "ps".into(),
        Value::Array(vec![
            Value::String("s2k".into()),
            Value::String("s2k_fo".into()),
        ]),
    );
    request.insert("u".into(), Value::String(account));
    request.insert("o".into(), Value::String("init".into()));

    let mut header = Dictionary::new();
    header.insert("Version".into(), Value::String("1.0.1".into()));
    let mut root = Dictionary::new();
    root.insert("Header".into(), Value::Dictionary(header));
    root.insert("Request".into(), Value::Dictionary(request));
    Value::Dictionary(root)
}

#[derive(Debug)]
struct GrandSlamReply {
    status: u16,
    code: Option<i64>,
    hardware_status: Option<i64>,
    challenge: bool,
}

impl GrandSlamReply {
    /// `hsc` is the device-identity status: 200 means GSA accepted the ADI
    /// proof, 401 means it rejected the proof. `ec` then reports the account
    /// stage, which fails for the placeholder address and is not checked here.
    fn identity_accepted(&self) -> bool {
        self.status == 200 && self.hardware_status == Some(200)
    }
}

async fn init(identity: &Identity) -> GrandSlamReply {
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, &init_body(identity)).unwrap();
    let response = reqwest::Client::new()
        .post("https://gsa.apple.com/grandslam/GsService2")
        .header("Content-Type", "text/x-xml-plist")
        .header("Accept", "*/*")
        .header("User-Agent", &identity.user_agent)
        .header("X-MMe-Client-Info", &identity.client_info)
        .header("Connection", "close")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    let root = plist::Value::from_reader_xml(&bytes[..])
        .ok()
        .and_then(|value| value.as_dictionary().cloned())
        .and_then(|root| root.get("Response").and_then(Value::as_dictionary).cloned());
    let status_body = root
        .as_ref()
        .and_then(|body| body.get("Status"))
        .and_then(Value::as_dictionary);
    GrandSlamReply {
        status,
        code: status_body
            .and_then(|status| status.get("ec"))
            .and_then(Value::as_signed_integer),
        hardware_status: status_body
            .and_then(|status| status.get("hsc"))
            .and_then(Value::as_signed_integer),
        challenge: root
            .as_ref()
            .is_some_and(|body| body.contains_key("s") && body.contains_key("B")),
    }
}

#[test]
#[ignore = "provisions a device identity and calls Apple"]
fn native_identities_are_accepted_by_gsa() {
    if std::env::var_os("APW_LIVE_ADI").is_none() {
        return;
    }
    if std::env::var_os("APW_ANISETTE_URL").is_some() {
        panic!("unset APW_ANISETTE_URL: this test exercises the native source");
    }
    let root = tempfile::tempdir().unwrap();
    let paths = paths(root.path());
    let config = Config::default();
    let runtime = runtime();

    for backend in [Some("macos"), None] {
        let identity = runtime
            .block_on(Anisette::from_config(&config, &paths).identity_for(backend))
            .unwrap();
        for required in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU"] {
            assert!(identity.header(required).is_some(), "{required}");
        }

        let accepted = runtime.block_on(init(&identity));
        println!(
            "{:?}: HTTP {} ec {:?} hsc {:?} challenge {}",
            backend.unwrap_or("windows"),
            accepted.status,
            accepted.code,
            accepted.hardware_status,
            accepted.challenge
        );
        assert!(
            accepted.identity_accepted(),
            "{backend:?}: Apple rejected the native device identity: {accepted:?}"
        );

        // A zeroed proof must be rejected at the device stage, which is what
        // makes the check above meaningful.
        let mut broken = identity.clone();
        let zeros = base64::engine::general_purpose::STANDARD.encode([0_u8; 28]);
        broken.headers.insert("X-Apple-I-MD".into(), zeros);
        let rejected = runtime.block_on(init(&broken));
        println!(
            "{:?} with a zeroed proof: HTTP {} ec {:?} hsc {:?}",
            backend.unwrap_or("windows"),
            rejected.status,
            rejected.code,
            rejected.hardware_status
        );
        assert!(
            !rejected.identity_accepted(),
            "{backend:?}: a zeroed proof was accepted: {rejected:?}"
        );
    }

    let state: Vec<PathBuf> = ["macos", "windows"]
        .iter()
        .map(|name| paths.state_dir.join("adi").join(format!("{name}.json")))
        .collect();
    for path in state {
        assert!(path.exists(), "{}", path.display());
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600, "{}", path.display());
    }
}
