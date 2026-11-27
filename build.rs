//! Linker settings for the installed layout.
//!
//! The package installs the executable at `bin/apw` and OpenTUI at
//! `lib/apw/libopentui.so`, so `$ORIGIN/../lib/apw` finds it without a loader
//! configuration. Cargo puts binaries in the profile directory and tests in its
//! `deps` subdirectory; `opentui-sys` copies the library into both, so
//! `$ORIGIN` also covers `cargo run` and `cargo test` in the build tree.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var_os("CARGO_FEATURE_TUI").is_none() {
        return;
    }

    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("-linux") {
        return;
    }

    println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib/apw");
}
