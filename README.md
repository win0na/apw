<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/icon/renders/icon-512-dark.png">
    <img alt="apw" src="./assets/icon/renders/icon-512.png" width="70" valign="middle">
  </picture>
  &nbsp;apw
</h1>

`apw` reads Apple Passwords on Linux. It is a single Rust binary that keeps an encrypted local snapshot and answers queries offline.

Apple ships Passwords for macOS, Windows, and iOS, with no Linux client and no public API for iCloud Keychain. `apw` signs in with an Apple ID, joins the device trust circle, decrypts the keychain records through escrow, and stores them in a snapshot. It never writes to Apple.

Sign in, join, and sync run against a live account.

## Get started

### Requirements

- Linux on x86_64 or aarch64, glibc.
- An Apple ID with two-factor authentication.
- An [anisette server](docs/install.md#set-up-anisette) for sign-in.
- A Secret Service provider (GNOME Keyring, KWallet) or `APW_PASSPHRASE`.

Rust 1.85 or later is needed only to build from source.

### Install

```sh
cargo install --git https://github.com/win0na/apw
```

The binary lands in `~/.cargo/bin/apw`. [Install](docs/install.md) covers the anisette server and the build from a checkout.

### Sign in

```sh
apw login --account you@example.com
```

`apw login` asks for the Apple ID, a new apw passcode, the Apple ID password, and a two-factor code, then joins the trust and writes the first snapshot. The apw passcode encrypts the snapshot and is reused for escrow, so enter your device passcode. The anisette server defaults to `http://127.0.0.1:6969`; pass `--anisette-url` only when yours runs elsewhere.

Escrow allows about ten attempts before the record is destroyed, so read [Troubleshooting](docs/troubleshooting.md) before retrying a failed sign-in.

### Sync and query

```sh
apw sync
apw pw list example.com
apw pw get example.com
apw pw wifi
apw otp get example.com
```

`apw sync` decrypts the iCloud records into the snapshot. `apw pw` and `apw otp` read the snapshot and never touch the network.

`--json` works on every command:

```json
{"results":[{"id":"login-example","username":"alice","domain":"example.com","sites":["example.com"],"title":"Example","password":"hunter2"}],"status":0}
```

### Refresh on a timer

```sh
apw install-units
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. Sync refuses to run more often than every five minutes unless you pass `--force`.

### Upgrade or uninstall

```sh
cargo install --git https://github.com/win0na/apw --force
cargo uninstall apw
```

`cargo uninstall apw` leaves the snapshot and config in place. Remove them with:

```sh
rm -rf ~/.config/apw ~/.local/share/apw ~/.local/state/apw
```

## Next steps

- [Install](docs/install.md): anisette, sign-in, timer, source build.
- [Operate](docs/operate.md): sync, status, re-authentication, shared groups.
- [Reference](docs/reference.md): commands, paths, config, JSON, limits.
- [Secrets](docs/secrets.md): snapshot key, passphrase, escrow, threat model.
- [Troubleshooting](docs/troubleshooting.md): symptoms and fixes.
- [Design](docs/design.md): protocols, architecture, passes.
- [Contributing](CONTRIBUTING.md): build, tests, fixtures, live gate.

## Read-only

This build has no `pw save` and no item edit. `apw pw save` fails as an unknown command.

Apple's iCloud terms prohibit automated access. `apw` stays polite: paced syncs, no automatic retries, one escrow attempt per user action. The contract risk is yours.

## Project status

| Area | State |
| --- | --- |
| CLI, encrypted snapshot, `pw`, `otp`, `status`, `install-units` | Works; 44 unit and 11 integration tests |
| `login`: GSA SRP, anisette, 2FA, token exchange | Works against the live account |
| `join`: Octagon trust, escrow recovery | Works; peer joined, restore point stored |
| `sync` from iCloud | Works; 383 items, 370 logins, 33 passkeys, 47 codes |
| Shared groups | Read path implemented; the test account has no shared items |
| Passkeys, notes, cards | Read and listed |
| Packaging: tarball, .deb, AUR, Nix | Recipes in `packaging/`; not yet published |

The Deno implementation for macOS stays under `legacy/` for reference. It is not built or supported.

## Contributing

Contributions are welcome. [Contributing](CONTRIBUTING.md) covers the build, the test suite, fixtures, and the live gate.

## License

GPL-3.0-only. See `LICENSE`.
