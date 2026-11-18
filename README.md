<h1>
<picture>
<source media="(prefers-color-scheme: dark)" srcset="./assets/icon/renders/icon-512-dark.png">
<img alt="apw" src="./assets/icon/renders/icon-512.png" width="70" valign="middle">
</picture>
&nbsp;apw
</h1>

`apw` reads Apple Passwords on Linux. It is one Rust binary with an encrypted local snapshot, and the query commands work offline.

Apple has no Linux client and no public API for iCloud Keychain. `apw` signs in with an Apple ID, joins the device trust circle, decrypts keychain records through escrow, and stores them locally. Keychain and CloudKit records stay read-only. The one remote write is the trust peer that `login` or `join` adds.

## Requirements

- Linux on x86_64 or aarch64 with glibc.
- An Apple ID with two-factor authentication.
- An anisette server. See [Install](docs/install.md#set-up-anisette).
- A Secret Service provider (GNOME Keyring, KWallet) or `APW_PASSPHRASE`.

Rust 1.88 or later, `cmake`, `perl`, and `libdbus-1` are needed only to build. On Debian and Ubuntu install `libdbus-1-dev`; on Arch install `dbus`.

## Install

```sh
cargo install --git https://github.com/win0na/apw
```

The binary lands in `~/.cargo/bin/apw`. [Install](docs/install.md) covers the anisette server, packages, and a build from a checkout.

## First run

```sh
apw login --account you@example.com
```

`apw login` asks for the Apple ID password, a two-factor code, and the escrow passcode. It joins the trust and writes the first snapshot, so one command leaves you with a usable vault.

The snapshot key goes to Secret Service on first write. Without it, `apw` asks for a new apw passphrase. The escrow passcode is the device passcode or iCloud Security Code; it is used once, never stored, and never reused as the snapshot passphrase.

Escrow allows about ten attempts before Apple destroys the recovery record. Read [Troubleshooting](docs/troubleshooting.md) before retrying a failed sign-in.

## Query

```sh
apw sync
apw list example.com
apw get example.com
apw wifi
apw otp example.com
```

`apw sync` decrypts iCloud records into the snapshot. `list`, `get`, `wifi`, and `otp` never touch the network.

`--json` works on every command. A pipe or redirect gets JSON too; `--wide` and `--no-header` keep the table form.

```json
{"status":0,"data":[{"id":"login-example","name":"Example","username":"alice","domain":"example.com","sites":["example.com"],"password":"hunter2"}]}
```

## Timer

```sh
apw install-units
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. Sync refuses to run more often than every five minutes unless you pass `--force`.

## Upgrade or uninstall

```sh
cargo install --git https://github.com/win0na/apw --force
```

To remove `apw`, stop the timer before the binary:

```sh
systemctl --user disable --now apw-sync.timer
rm -f ~/.config/systemd/user/apw-sync.service ~/.config/systemd/user/apw-sync.timer
systemctl --user daemon-reload
cargo uninstall apw
rm -rf ~/.config/apw ~/.local/share/apw ~/.local/state/apw
secret-tool clear service apw account snapshot-key
```

`secret-tool` is part of `libsecret`. Skip the last line if you never used Secret Service.

## Status

| Area | State |
| --- | --- |
| CLI, snapshot, `list`, `get`, `wifi`, `otp`, `status`, `install-units` | Works; 57 unit and 18 integration tests |
| `login`, `join`, `sync` against iCloud | Works; 383 items, 370 logins, 33 passkeys, 47 codes |
| Shared groups | Read path implemented; the test account has no shared items |
| Passkeys, notes, cards | Read; passkeys are counted in `status` but not listed |
| Packaging | Tarball, `.deb`, AUR `apw-cli`, Nix flake |

There is no `save` or edit command. Apple's iCloud terms prohibit automated access; `apw` stays polite with paced syncs, no automatic retries, and one escrow attempt per user action. The contract risk is yours.

The Deno implementation for macOS stays under `legacy/` as reference. It is not built.

## Docs

[Install](docs/install.md) · [Operate](docs/operate.md) · [Reference](docs/reference.md) · [Secrets](docs/secrets.md) · [Troubleshooting](docs/troubleshooting.md) · [Design](docs/design.md) · [Icon](docs/icon.md) · [Contributing](CONTRIBUTING.md)

## License

GPL-3.0-only. See `LICENSE`.
