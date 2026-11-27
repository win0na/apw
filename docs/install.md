# Install

This page installs `apw`, signs in, and starts the hourly sync timer. Upgrading
from an earlier release also needs the anisette note under [Sign in](#sign-in).

## Requirements

- Linux on x86_64 or aarch64 with glibc.
- An Apple ID with two-factor authentication and iCloud Passwords enabled.
- Network access to Apple on the first sign-in.
- Secret Service on the session bus, or `APW_PASSPHRASE`.
- To build: Rust 1.88 or newer, Zig 0.17.1, and `libdbus-1`. On Debian and
  Ubuntu install `libdbus-1-dev` and `pkg-config`; on Arch install `dbus` and
  `pkgconf`.

The executable needs glibc, `libdbus-1` for Secret Service, and the
`libopentui.so` installed beside it. It does not need Zig or Rust at runtime.

## Install

### Install script

```sh
curl -fsSL https://github.com/win0na/apw/releases/latest/download/install.sh | sh
```

The script verifies the release checksum and installs `apw` to
`~/.local/bin/apw` and the library to `~/.local/lib/apw/libopentui.so`. Add
`~/.local/bin` to `PATH`. Use `--prefix DIR` or `APW_PREFIX` for another prefix,
and `--version vX.Y.Z` to pin a release.

Prebuilt releases are x86_64 only. On aarch64, build from source.

### Cargo

```sh
git clone --recurse-submodules https://github.com/win0na/apw
cd apw
cargo install --path . --locked
install -s -D -m 0755 opentui/packages/native/lib/x86_64-linux/libopentui.so \
  "${CARGO_HOME:-$HOME/.cargo}/lib/apw/libopentui.so"
```

Use `aarch64-linux` in place of `x86_64-linux` on ARM. `cargo install` builds
only the executable, so the second command installs the library it loads at
`../lib/apw`. Zig 0.17.1 must be on `PATH`; the build uses it once.

To build without installing, run `cargo build --release --locked` and install
`target/release/apw` and `opentui/packages/native/lib/<platform>/libopentui.so`
into the same `bin` and `lib/apw` layout.

### Packages

| Package | Command | Installs |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.5.0-<target>.tar.gz` |
| Debian | `packaging/debian/build.sh` | `dist/apw_0.5.0_<arch>.deb` |
| AUR | `cd packaging/aur && makepkg -si` | the `apw-cli` package |
| Nix | `nix build` | `result/bin/apw`, `result/lib/apw/libopentui.so` |

Every layout keeps `libopentui.so` in `lib/apw` beside the executable. The
tarball and Debian scripts build the release binary first; set
`APW_SKIP_BUILD=1` to reuse `target/release/apw`.

## Sign in

```sh
apw login --account you@example.com
apw sync
```

The first sign-in asks for the Apple ID password, a two-factor code, and your
escrow passcode, then joins the Octagon trust circle and syncs. Later sign-ins
usually ask only for the password; use `--refresh` to re-read the service URLs
without signing in, `--join` to join again, and `--no-join` to skip the join.

The escrow passcode is your device passcode, or the iCloud Security Code when
you set one. It is used once, never stored, and is not the snapshot passphrase.
A join spends one of about ten attempts; a wrong passcode stops the command. For
a non-interactive run, set `APW_ESCROW_PASSCODE`.

The snapshot key goes to Secret Service on the first write. When Secret Service
is unavailable, `apw` asks for an apw passphrase and derives the key with
Argon2id; set `APW_PASSPHRASE` to choose that mode from the start.

### Device identity

Apple expects a device identity on every account request. `apw` provisions one
in process from the Rust port of [apple-auth](https://github.com/apple-auth/apple-auth)
and stores the macOS profile at `$XDG_STATE_HOME/apw/adi/macos.json`, mode 0600
in a mode 0700 directory. Delete the file to provision a new identity. When
macOS provisioning fails, `apw` stores `windows.json` instead; the Windows
identity still reads the vault but escrow needs the macOS one.

A release before 0.5.0 required a separate anisette service. Delete the
`anisette_url` line from `~/.config/apw/config.toml` and sign in again: tokens
bind to the identity that minted them, and an old session keeps its Windows
escrow token until the next `apw login`. To keep using an external server, set
`APW_ANISETTE_URL`, pass `--anisette-url`, or set `anisette_url`; the server must
return a macOS identity with `?backend=macos`. See [Secrets](secrets.md) for the
identity and escrow details.

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
timer needs an unlocked collection instead of this file. `apw` no longer reads
the kernel keyring cache, so set `APW_PASSPHRASE` whenever the timer runs
without an unlocked session.

`Persistent=true` catches up after suspend or a missed run. Enable lingering
when the user session is not always active:

```sh
loginctl enable-linger "$USER"
```

## Check the install

```sh
apw status
apw list
apw otp example.com
```

`apw status` prints the account, source, entry counts, last sync, and snapshot
path. Bare `apw` opens the interface on a terminal. Next, read
[Operate](operate.md) for sync and re-authentication, or
[Troubleshooting](troubleshooting.md) when a step fails.
