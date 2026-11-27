//! Linker settings for the installed layout.
//!
//! The package installs the executable at `bin/apw` and OpenTUI at
//! `lib/apw/libopentui.so`, so `$ORIGIN/../lib/apw` finds it without a loader
//! configuration. Cargo puts binaries in the profile directory and tests in its
//! `deps` subdirectory; `opentui-sys` copies the library into both, so
//! `$ORIGIN` also covers `cargo run` and `cargo test` in the build tree.

use std::env;
use std::path::PathBuf;

fn platform(target: &str) -> Option<&'static str> {
    Some(match target {
        "x86_64-unknown-linux-gnu" => "x86_64-linux",
        "aarch64-unknown-linux-gnu" => "aarch64-linux",
        "x86_64-unknown-linux-musl" => "x86_64-linux-musl",
        "aarch64-unknown-linux-musl" => "aarch64-linux-musl",
        _ => return None,
    })
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OPENTUI_LIB_DIR");
    if env::var_os("CARGO_FEATURE_TUI").is_none() {
        return;
    }

    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("-linux") {
        return;
    }

    println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib/apw");

    // Some Cargo versions run test binaries from the build script's OUT_DIR,
    // where the relative entries above cannot reach the library. The absolute
    // build-tree path keeps debug and test builds working; release packages
    // resolve through `$ORIGIN` and stay free of build paths.
    let profile = env::var("PROFILE").unwrap_or_default();
    if profile != "release" {
        let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        let library = env::var_os("OPENTUI_LIB_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                platform(&target)
                    .map(|platform| manifest.join("opentui/packages/native/lib").join(platform))
            });
        if let Some(library) = library {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", library.display());
        }
    }
}
