//! Thin shim over OpenTUI's `opentui-sys`: build the pinned native library, then
//! run upstream's own build script for header checks and static link directives.
//!
//! A crate's own `build.rs` runs after its dependencies' build scripts, so the
//! native build cannot live in apw's root. Patching `opentui-sys` is the only way
//! to keep `cargo build` as the single entry point.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod upstream {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../opentui/packages/rust/crates/opentui-sys/build.rs"
    ));

    pub fn run() {
        main();
    }
}

fn platform(target: &str) -> &'static str {
    match target {
        "x86_64-unknown-linux-gnu" => "x86_64-linux",
        "aarch64-unknown-linux-gnu" => "aarch64-linux",
        "x86_64-unknown-linux-musl" => "x86_64-linux-musl",
        "aarch64-unknown-linux-musl" => "aarch64-linux-musl",
        "x86_64-apple-darwin" => "x86_64-macos",
        "aarch64-apple-darwin" => "aarch64-macos",
        "x86_64-pc-windows-msvc" | "x86_64-pc-windows-gnu" => "x86_64-windows",
        "aarch64-pc-windows-msvc" | "aarch64-pc-windows-gnullvm" => "aarch64-windows",
        other => panic!("apw: OpenTUI has no native artifact for target {other}"),
    }
}

fn run(command: &mut Command, what: &str) {
    let status = command.status().unwrap_or_else(|error| {
        panic!(
            "apw: cannot run {what}: {error}. Install Zig 0.17.x and put `zig` on PATH \
             (https://ziglang.org/download/0.17.1/)."
        )
    });
    assert!(status.success(), "apw: {what} failed with {status}");
}

fn main() {
    println!("cargo:rerun-if-env-changed=OPENTUI_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PATH");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().expect("repository root").to_path_buf();
    let checkout = root.join("opentui");
    let native = checkout.join("packages/native");
    let target = env::var("TARGET").expect("TARGET");
    let libdir = native.join("lib").join(platform(&target));

    // An explicit OPENTUI_LIB_DIR wins, for distro packaging and prebuilt archives.
    if env::var_os("OPENTUI_LIB_DIR").is_none() {
        let stamp_path = root.join(".opentui-native.stamp");
        let commit = Command::new("git")
            .arg("-C")
            .arg(&checkout)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let stamp = format!("{commit}\n{target}\nvideo=false\noptimize=ReleaseSmall\n");
        let fresh = fs::read_to_string(&stamp_path)
            .map(|old| old == stamp)
            .unwrap_or(false)
            && libdir.join("opentui.h").is_file()
            && libdir.join("libopentui.a").is_file();

        if !fresh {
            assert!(
                native.join("build.zig").is_file(),
                "apw: the OpenTUI submodule is missing. Run \
                 `git submodule update --init --recursive`."
            );
            let version = Command::new("zig")
                .arg("version")
                .output()
                .unwrap_or_else(|error| {
                    panic!(
                        "apw: Zig 0.17.x is required to build the TUI native library: {error}. \
                         Install it from https://ziglang.org/download/0.17.1/."
                    )
                });
            assert!(version.status.success(), "apw: `zig version` failed");
            let version = String::from_utf8_lossy(&version.stdout);
            assert!(
                version.trim().starts_with("0.17."),
                "apw: OpenTUI needs Zig 0.17.x, found {}",
                version.trim()
            );
            run(
                Command::new("sh")
                    .arg("scripts/prepare-zig-deps.sh")
                    .current_dir(&native),
                "OpenTUI dependency preparation",
            );
            run(
                Command::new("zig")
                    .args(["build", "-Dvideo=false", "-Doptimize=ReleaseSmall"])
                    .current_dir(&native),
                "OpenTUI native build",
            );
            fs::write(&stamp_path, stamp).expect("write the OpenTUI native stamp");
        }
        env::set_var("OPENTUI_LIB_DIR", &libdir);
    }

    println!(
        "cargo:rerun-if-changed={}",
        native.join("build.zig").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        native.join("build.zig.zon").display()
    );
    upstream::run();
}
