pub mod adi;
pub mod auth;
pub mod ckks;
pub mod cli;
pub mod cloudkit;
pub mod commands;
pub mod config;
pub mod cxf;
pub mod error;
pub mod group_write;
pub mod groups;
pub mod kcsharing;
pub mod model;
pub mod octagon;
pub mod output;
pub mod pcs;
pub mod push;
pub mod store;
pub mod totp;
#[cfg(feature = "tui")]
pub mod tui;
pub mod vault;
pub mod wire;

/// Install the rustls provider reqwest expects once per process. apw builds
/// reqwest without a bundled TLS provider so the binary links ring instead of
/// AWS-LC, which means every client construction needs this first.
pub(crate) fn install_tls_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn run() -> i32 {
    install_tls_provider();
    cli::run()
}
