<h1>
<picture>
<source media="(prefers-color-scheme: dark)" srcset="./assets/icon/renders/icon-512-dark.png">
<img alt="apw" src="./assets/icon/renders/icon-512.png" width="70" valign="middle">
</picture>
&nbsp;apw
</h1>

`apw` reads and writes Apple Passwords on Linux. It is one Rust binary with an encrypted local snapshot: queries work offline, and edits wait for the next sync.

Apple has no Linux client and no public API for iCloud Keychain. `apw` signs in with an Apple ID, joins the device trust circle, decrypts keychain records through escrow, and stores them locally. Queries never touch the network. Writes change the snapshot first and go back through CloudKit on `sync`.

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
{"status":0,"data":[{"id":"login-example","name":"Example","username":"alice","domain":"example.com","url":"https://example.com","sites":["example.com"],"password":"hunter2"}]}
```

## Write

```sh
apw add login https://example.com --username alice --password-stdin
apw edit example.com --title "Example"
apw rm example.com --yes
apw pending
```

`add`, `edit`, and `rm` change the snapshot and queue the change. `apw sync` pushes queued changes after it reads, so an edit made offline goes out on the next sync. `apw pending` lists the queue.

A password comes from `--password-stdin`, from `--generate`, or from a prompt that asks twice. There is no `--password` flag, so a password does not land in shell history. `--dry-run` prints the queued change without writing it.

If another device changed the same entry, the push blocks instead of overwriting it and prints the pending id. `apw resolve <id> --local` pushes the local version; `--remote` drops it and takes the server copy.

Writes cover personal logins. Wi-Fi networks, notes, cards, shared items, and passkey creation stay read-only for now. `rm` is permanent: Recently Deleted is not implemented, so Apple Passwords has no copy to restore either. Changing a site or username is not supported in place; delete the entry and add it again.

## Timer

```sh
apw install-units
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. It also pushes queued edits. Sync refuses to run more often than every five minutes unless you pass `--force`, or a queued change is waiting.

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
| Packaging | Tarball, `.deb`, AUR recipe, Nix flake |

There is no `save` or edit command. Apple's iCloud terms prohibit automated access; `apw` stays polite with paced syncs, no automatic retries, and one escrow attempt per user action. The contract risk is yours.

The Deno implementation for macOS stays under `legacy/` as reference. It is not built.

## Docs

[Install](docs/install.md) · [Operate](docs/operate.md) · [Reference](docs/reference.md) · [Secrets](docs/secrets.md) · [Troubleshooting](docs/troubleshooting.md) · [Design](docs/design.md) · [Icon](docs/icon.md) · [Contributing](CONTRIBUTING.md)

## License

GPL-3.0-only. See `LICENSE`.
