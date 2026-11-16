pub mod auth;
pub mod ckks;
pub mod cli;
pub mod cloudkit;
pub mod commands;
pub mod config;
pub mod error;
pub mod groups;
pub mod kcsharing;
pub mod model;
pub mod octagon;
pub mod output;
pub mod pcs;
pub mod store;
pub mod totp;
pub mod vault;
pub mod wire;

pub fn run() -> i32 {
    cli::run()
}
