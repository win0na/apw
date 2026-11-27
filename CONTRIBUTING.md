# Contributing

`apw` is a Rust binary. The Deno implementation under `legacy/` is reference material and is not built.

## Build

Rust 1.88 or later. The Secret Service backend links `libdbus-1`; the TLS stack uses ring. OpenTUI's native library is built with Zig 0.17.1.

```sh
sudo apt-get install -y libdbus-1-dev pkg-config   # Debian, Ubuntu
sudo pacman -S --needed dbus pkgconf               # Arch
cargo build
cargo run -- --help
```

## Test

```sh
cargo test
```

The suite has two parts:

- Unit tests in `src/`: TOTP vectors from RFC 6238, AES key wrap, snapshot seal and open, SRP round trips, sidecar matching, the GSA `spd` decrypt, and the ADI OTP vectors in `tests/fixtures/adi/`.
- Integration tests in `tests/cli.rs`: a fixture sync, `list`, `get`, `wifi`, `otp`, `status`, wrong passphrase, missing snapshot, and an unreachable anisette
server. `tests/adi_provisioning.rs` replays the captured provisioning transcript;
`tests/adi_live.rs` is ignored and needs `APW_LIVE_ADI=1` plus network access.

Tests isolate the XDG directories with `APW_CONFIG_DIR`, `APW_DATA_DIR`, and `APW_STATE_DIR`, and set `APW_PASSPHRASE` so no Secret Service is needed. They never touch the network.

## Checks

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --no-default-features
```

All four must pass before a pull request. The last one keeps the crate building without the Secret Service backend.

## Fixtures

A fixture uses the same JSON model as the vault:

```json
{
  "account": "user@example.com",
  "entries": [
    {
      "id": "login-example",
      "kind": "login",
      "title": "Example",
      "url": "https://example.com",
      "sites": ["example.com"],
      "username": "alice",
      "password": "hunter2",
      "totp": { "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" }
    }
  ]
}
```

`apw sync --fixture <path>` reads it; `APW_FIXTURE` does the same when the flag is absent. A TOTP seed needs only `secret`; the algorithm, digits, and period default to SHA1, 6, and 30.

Fixtures are test data. Never put a real password, token, or account in one.

## Live gate

The auth, Octagon, and CKKS passes cannot run in CI: they need a real Apple ID, and escrow attempts are destructive. Run this once on your own account and report the result in the pull request:

```sh
apw login --account you@example.com
apw status
apw sync
apw list
apw get example.com
apw otp example.com
```

`apw login` makes one escrow attempt per run. Do not loop it.

## Repo map

| Path | Contents |
| --- | --- |
| `src/cli.rs` | clap definitions and dispatch |
| `src/commands/` | `login`, `join`, `sync`, `status`, `pw`, `otp`, `units`, `probe` |
| `src/adi/` | Native device identity, ported from the MIT apple-auth implementation |
| `src/auth/` | Identity sources, SRP, GSA, two-factor, token exchange |
| `src/wire.rs` | Protobuf framing and the CloudKit gateway client |
| `src/octagon/` | Peer keys, escrow, trust join, TLK shares |
| `src/ckks/` | Zones, records, AES-SIV, item plists |
| `src/config.rs` | XDG paths, `config.toml`, `state.json`, snapshot lock |
| `src/model.rs` | Vault, entry, TOTP, group, sidecar merge |
| `src/store/` | Snapshot encryption and key sources |
| `src/vault/` | Snapshot load and save, fixture reader |
| `src/totp.rs` | RFC 6238 |
| `tests/` | CLI integration tests and fixtures |
| `assets/icon/` | Icon recipes, SVG layers, renders, Icon Composer package |
| `packaging/` | systemd units and package manifests |
| `legacy/` | Deno macOS implementation, reference only |
| `docs/` | User and design docs |

## Standards

- Read-only stays read-only. Do not add `save` or item edits.
- A new dependency needs a reason in the pull request.
- Every protocol constant gets a test vector.
- Never log a password, token, passcode, or key.
- Docs change in the same pull request as the code.

## Release

1. Bump `version` in `Cargo.toml`, run `cargo check` to refresh `Cargo.lock`,
   add the `## [X.Y.Z]` section to `CHANGELOG.md`, and update the versioned
   names in `docs/install.md` and `packaging/README.md`.
2. Commit and push, then tag `vX.Y.Z` and push the tag. `release.yml` builds the
   tarball, the Debian package, their checksums, and `install.sh`, then
   publishes a pre-release from the CHANGELOG section.
3. Bump `pkgver` in `packaging/aur/PKGBUILD` and `.SRCINFO`, then push both to
   `ssh://aur@aur.archlinux.org/apw-cli.git`. The source checksums stay `SKIP`
   because the recipe builds from the git tag.

## License

GPL-3.0-only. Contributions are under the same license.
