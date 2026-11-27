# Install

This page installs `apw`, signs in, and starts the hourly sync timer.

## Requirements

- Linux on x86_64 or aarch64 with glibc.
- An Apple ID with two-factor authentication.
- Network access to Apple on the first sign-in, for the device identity.
- Secret Service on the session bus, or `APW_PASSPHRASE`.
- To build: Rust 1.88 or newer, Zig 0.17.1, `cmake`, `perl`, and `libdbus-1`.
  On Debian and Ubuntu install `libdbus-1-dev` and `pkg-config`. On Arch install
  `dbus`, `cmake`, `perl`, and `pkgconf`.

The built binary needs glibc and D-Bus for Secret Service. It links the OpenTUI
native library in, so it does not need Zig at runtime.

## Device identity

Apple expects a device identity on every account request. `apw` builds it in
process. The ADI implementation in `src/adi/` is a Rust port of
[apple-auth](https://github.com/apple-auth/apple-auth) (MIT) and does not load,
emulate, or download an Apple binary.

The first sign-in provisions a macOS profile and a Windows profile against
`gsa.apple.com`. If Apple asks for two-factor codes, the first is for the macOS
identity and the second is for the Windows identity; both are one-time. The
Windows identity authorizes escrow recovery, and later sign-ins ask for
neither. `apw` writes the profiles to `$XDG_STATE_HOME/apw/adi/macos.json` and
`windows.json` with mode 0600 in a mode 0700 directory, then reuses them on
later runs. Delete those files
to make `apw` provision a new identity.

Run the first sign-in with `apw login` rather than the interface. The second code
is prompted on the terminal, which the interface cannot do.

If you used the separate anisette service before this release, run `apw login`
again. Apple binds the session and escrow tokens to the machine identity that
minted them, and an old session keeps tokens from the service identity.

To use an external anisette server instead, set `APW_ANISETTE_URL`, pass
`--anisette-url`, or set `anisette_url` in the config. The server must return a
Windows identity by default and a macOS identity with `?backend=macos`. When a
URL is configured, `apw` does not provision locally.

## Install the binary

With Cargo:

```sh
cargo install --git https://github.com/win0na/apw --locked
```

The install fetches the OpenTUI submodule and builds its native library once.
Zig 0.17.1 must be on `PATH`.

From a checkout:

```sh
git clone --recurse-submodules https://github.com/win0na/apw
cd apw
cargo build --release --locked
install -m 0755 target/release/apw ~/.local/bin/apw
```

`apw --version` prints `0.4.0`.

Prebuilt formats build from the same checkout:

| Format | Command | Output |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.4.0-<target>.tar.gz` |
| Debian | `packaging/debian/build.sh` | `dist/apw_0.4.0_<arch>.deb` |
| Nix | `nix build` | `result/bin/apw` |

The tarball and Debian scripts build the release binary first. Set
`APW_SKIP_BUILD=1` to reuse an existing one. The AUR recipe in `packaging/aur/`
installs `/usr/bin/apw`.

## Sign in

Run `apw login` for the first sign-in; open `apw` and choose `login` for later ones:

```sh
apw login --account you@example.com
```

The first sign-in asks for the Apple ID password, a two-factor code, and the
escrow passcode. It then joins the Octagon trust circle and syncs. The CLI
leaves you with a readable snapshot in one command.

The snapshot key goes to Secret Service on the first write. When Secret Service
is unavailable, `apw` asks for a new apw passphrase and derives the key with
Argon2id. Set `APW_PASSPHRASE` to choose passphrase mode from the start.

The escrow passcode is your device passcode, or the iCloud Security Code when
you set one. It is used once, never stored, and never reused as the snapshot
passphrase. For a non-interactive run, set `APW_ESCROW_PASSCODE`.

Later sign-ins keep the existing peer and sync. Pass `--no-join` to skip the
join, `--join` to join again, or `--refresh` to re-read the service URLs without
signing in. `apw join` runs the join on its own.

Escrow allows about ten attempts before Apple destroys the recovery record. Each
join spends one attempt and never retries on its own. A wrong passcode stops the
command.

## Run the sync timer

```sh
apw install-units
systemctl --user daemon-reload
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. It reads `~/.config/apw/sync.env` when the file
exists, so a headless passphrase or anisette server URL can live in a mode 0600 file:

```sh
install -m 600 /dev/null ~/.config/apw/sync.env
printf 'APW_PASSPHRASE=%s\n' 'your apw passphrase' > ~/.config/apw/sync.env
```

Use the apw passphrase here, never the device passcode. In Secret Service mode
the timer needs an unlocked keyring instead of this file.

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

`apw status` prints the account, source, entry count, and snapshot path. Bare
`apw` opens the interface on a terminal. Next, read [Operate](operate.md) for
sync and re-authentication, or [Troubleshooting](troubleshooting.md) when a step
fails.
