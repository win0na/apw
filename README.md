# apw

apw reads Apple Passwords on Linux. One Rust binary, one encrypted snapshot, no daemon.

Apple ships Passwords for macOS, Windows, and iOS, with no Linux client and no public API for iCloud Keychain. apw signs in with an Apple ID, joins the device trust circle, decrypts the keychain records, and stores them in a local encrypted snapshot. Query commands read that snapshot and never touch the network. Nothing is written back to Apple.

## Status

| Area | State |
| --- | --- |
| CLI, encrypted snapshot, `pw`, `otp`, `status`, `install-units` | Works against fixtures |
| `login` and live `sync` | Designed, not in this build |
| Shared groups, passkeys, notes | Designed, not in this build |

The Deno implementation for macOS stays under `legacy/` for reference. It is not built or supported.

## Requirements

- Linux on x86_64 or aarch64, glibc.
- An Apple ID with two-factor authentication.
- An anisette server for sign-in. See [Install](docs/install.md#anisette).
- A Secret Service provider (GNOME Keyring, KWallet) or `APW_PASSPHRASE`.

Rust 1.82 or later is needed only to build from source.

## How it works

`apw login` authenticates through GSA SRP, answers the two-factor prompt, joins Octagon, and recovers the keychain keys through escrow. `apw sync` refreshes the tokens and decrypts the CKKS records into the snapshot. `apw pw` and `apw otp` read the snapshot.

The snapshot is AES-256-GCM under a 256-bit key in Secret Service. Without a session bus, the key is derived with Argon2id from a passphrase.

## Install

```sh
cargo install --git https://github.com/bendews/apw
```

[Install](docs/install.md) covers the anisette server, the first sign-in, the systemd timer, and the build from a checkout.

## Use

```sh
apw login --anisette-url http://127.0.0.1:6969
apw sync
apw pw list example.com
apw pw get example.com
apw otp get example.com
apw status
```

`apw pw get` prints the password.

```sh
apw pw get example.com --json
```

```json
{"results":[{"id":"login-example","username":"alice","domain":"example.com","sites":["example.com"],"title":"Example","password":"hunter2"}],"status":0}
```

`--json` works on every command and prints the envelope described in [Reference](docs/reference.md#json).

## Read-only

This build has no `pw save` and no item edit. `apw pw save` fails as an unknown command.

Apple's iCloud terms prohibit automated access. apw stays polite: paced syncs, no automatic retries, one escrow attempt per user action. The contract risk is yours.

## Docs

- [Install](docs/install.md): anisette, sign-in, timer, source build.
- [Operate](docs/operate.md): sync, status, re-authentication, shared groups.
- [Reference](docs/reference.md): commands, paths, config, JSON, limits.
- [Secrets](docs/secrets.md): snapshot key, passphrase, escrow, threat model.
- [Troubleshooting](docs/troubleshooting.md): symptoms and fixes.
- [Design](docs/design.md): protocols, architecture, passes.
- [Contributing](CONTRIBUTING.md): build, tests, fixtures, live gate.

## License

GPL-3.0-only. See `LICENSE`.
