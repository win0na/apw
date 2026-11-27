# Install

Installs `apw` and opens the interface.

## Install script

```sh
curl -fsSL https://raw.githubusercontent.com/win0na/apw/main/scripts/install.sh | sh
```

The script verifies the release checksum and installs `~/.local/bin/apw`; add
that directory to `PATH`. `--prefix DIR` installs elsewhere and
`--version vX.Y.Z` pins a release.

## Cargo

```sh
cargo install --git https://github.com/win0na/apw --locked
```

Cargo needs Rust 1.88 or newer, Zig 0.17.1, `libdbus-1`, and `pkg-config`. On
Debian and Ubuntu install `libdbus-1-dev`; on Arch install `dbus` and `pkgconf`.
Use this path on aarch64; the prebuilt packages are x86_64.

## Packages

| Package | Command |
| --- | --- |
| Debian | `sudo apt install ./apw_0.5.1_amd64.deb`, after downloading it from the [release](https://github.com/win0na/apw/releases) |
| Nix | `nix profile install github:win0na/apw` |

The AUR recipe in `packaging/aur/` is updated by hand, and the published
`apw-cli` package still carries 0.3.0; use another path until it catches up.

## Sign in

```sh
apw login
apw sync
```

The first sign-in asks for the Apple ID password, a two-factor code, and your
escrow passcode, then joins the Octagon trust circle and syncs. Later sign-ins
usually ask only for the password; `--refresh` re-reads the service URLs without
signing in.

The escrow passcode is your device passcode, or the iCloud Security Code when
you set one. It is used once, never stored, and is not the snapshot passphrase.
A join spends one of about ten attempts. For a non-interactive run, set
`APW_ESCROW_PASSCODE`.

The snapshot key goes to Secret Service on the first write. When Secret Service
is unavailable, `apw` asks for an apw passphrase and derives the key with
Argon2id; set `APW_PASSPHRASE` to choose that mode from the start.

Apple expects a device identity on every account request. `apw` provisions one
in process and stores it under `$XDG_STATE_HOME/apw/adi/`; delete that directory
to provision a new identity. A release before 0.5.0 required a separate
anisette service: delete `anisette_url` from `~/.config/apw/config.toml` and
sign in again. [Secrets](secrets.md) covers the identity and escrow details.

## Start the sync timer

```sh
apw install-units
systemctl --user daemon-reload
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. It reads `~/.config/apw/sync.env` when that
file exists, so a headless passphrase can live in a mode 0600 file:

```sh
install -m 600 /dev/null ~/.config/apw/sync.env
printf 'APW_PASSPHRASE=%s\n' 'your apw passphrase' > ~/.config/apw/sync.env
```

Use the apw passphrase, never the device passcode. In Secret Service mode the
timer needs an unlocked collection instead. `apw` no longer reads the kernel
keyring cache, so set `APW_PASSPHRASE` whenever the timer runs without an
unlocked session.

`Persistent=true` catches up after suspend or a missed run. Enable lingering
when the user session is not always active:

```sh
loginctl enable-linger "$USER"
```

## Check the install

```sh
apw
apw status
```

Bare `apw` opens the interface. `apw status` prints the account, source, entry
counts, last sync, and snapshot path. Next, read [Operate](operate.md) for
day-to-day use, or [Troubleshooting](troubleshooting.md) when a step fails.
