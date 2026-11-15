<h1>
  <img alt="apw" src="./assets/icon.png" width="70" valign="middle">
  &nbsp;apw
</h1>

`apw` reads Apple Passwords on Linux. It is a single Rust binary that keeps an encrypted local snapshot and answers queries offline.

Apple ships Passwords for macOS, Windows, and iOS, with no Linux client and no public API for iCloud Keychain. `apw` signs in with an Apple ID, joins the device trust circle, decrypts the keychain records through escrow, and stores them in a snapshot. It never writes to Apple.

Sign in works today. Sync from iCloud is designed and not in this build.

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
apw login --anisette-url http://127.0.0.1:6969
```

`apw login` prompts for the Apple ID password and a two-factor code, then stores the session in the encrypted snapshot. Escrow allows about ten attempts before the record is destroyed, so read [Troubleshooting](docs/troubleshooting.md) before retrying a failed sign-in.

### Sync and query

```sh
apw sync
apw pw list example.com
apw pw get example.com
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
| CLI, encrypted snapshot, `pw`, `otp`, `status`, `install-units` | Works against fixtures |
| `login`: GSA SRP, anisette, 2FA, token exchange | Implemented, live run pending |
| `sync` from iCloud | Designed, not in this build |
| Shared groups, passkeys, notes | Designed, not in this build |

The Deno implementation for macOS stays under `legacy/` for reference. It is not built or supported.

## Contributing

Contributions are welcome. [Contributing](CONTRIBUTING.md) covers the build, the test suite, fixtures, and the live gate.

## License

GPL-3.0-only. See `LICENSE`.
