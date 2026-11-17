# Contributing

`apw` is a Rust binary. The Deno implementation under `legacy/` is reference material and is not built.

## Build

Rust 1.85 or later.

```sh
cargo build
cargo run -- --help
```

## Test

```sh
cargo test
```

The suite has two parts:

- Unit tests in `src/`: TOTP vectors from RFC 6238, snapshot seal and open, SRP round trips, and the GSA `spd` decrypt.
- Integration tests in `tests/cli.rs`: a fixture sync, `pw`, `otp`, `status`, wrong passphrase, missing snapshot, and the anisette check.

Tests isolate the XDG directories with `APW_CONFIG_DIR`, `APW_DATA_DIR`, and `APW_STATE_DIR`, and set `APW_PASSPHRASE` so no keyring is needed. They never touch the network.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

All three must pass before a pull request.

## Icon

The icon is one Liquid Glass key on a white plate, built from four Liquid Composer recipes. The PNGs and the `.icon` package are generated files, so edit a recipe or the SVGs in `assets/icon/src/` and render again:

```sh
cd assets/icon
for r in icon.json icon-dark.json icon-clear.json; do
  npx -y liquid-composer apply "$r" --out renders
done
npx -y liquid-composer apply icon-bundle.json --out .
```

Rendering needs Node 22.12 or later and Google Chrome. The binary needs neither. [Icon](docs/icon.md) covers the mark, the appearances, the Icon Composer package, and what the engine cannot match; `assets/icon/NOTES.md` has the measured geometry and the registration checks.

## Fixtures

A fixture is the same JSON model as the vault:

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

The auth, Octagon, and CKKS passes cannot be tested in CI: they need a real Apple ID, and escrow attempts are destructive. Run this once on your own account and report the result in the pull request:

```sh
apw login --account you@example.com
apw status
apw sync
apw pw list
apw pw get example.com
apw otp get example.com
```

`apw login` makes one escrow attempt per run. Do not loop it.

## Repo map

| Path | Contents |
| --- | --- |
| `src/cli.rs` | clap definitions and dispatch |
| `src/commands/` | `login`, `sync`, `status`, `pw`, `otp`, `units` |
| `src/auth/` | SRP, anisette, GSA, two-factor, token exchange |
| `src/wire/` | Protobuf framing and the CloudKit gateway client (pass 3) |
| `src/octagon/` | Peer keys, escrow, trust join, TLK shares (pass 3) |
| `src/ckks/` | Zones, records, AES-SIV, item plists (pass 3) |
| `src/config.rs` | XDG paths, `config.toml`, `state.json` |
| `src/model.rs` | Vault, entry, TOTP, group |
| `src/store/` | Snapshot encryption and key sources |
| `src/vault/` | Snapshot load and save, fixture reader |
| `src/totp.rs` | RFC 6238 |
| `tests/` | CLI integration tests and fixtures |
| `assets/icon/` | Icon recipes, SVG layers, renders, Icon Composer package |
| `packaging/` | systemd units and package manifests |
| `legacy/` | Deno macOS implementation, reference only |
| `docs/` | User and design docs |

## Standards

- Read-only stays read-only in v1. Do not add `pw save` or item edits.
- A new dependency needs a reason in the pull request.
- Every protocol constant gets a test vector.
- Never log a password, token, passcode, or key.
- Docs change in the same pull request as the code.

## License

GPL-3.0-only. Contributions are under the same license.
