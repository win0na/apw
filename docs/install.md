# Install

This page installs `apw`, signs in, and starts the hourly sync timer.

## Requirements

- Linux on x86_64 or aarch64 with glibc.
- An Apple ID with two-factor authentication.
- An anisette server. See [Set up anisette](#set-up-anisette).
- Secret Service on the session bus, or `APW_PASSPHRASE`.
- To build: Rust 1.88 or newer, Zig 0.17.1, `cmake`, `perl`, and `libdbus-1`.
  On Debian and Ubuntu install `libdbus-1-dev` and `pkg-config`. On Arch install
  `dbus`, `cmake`, `perl`, and `pkgconf`.

The built binary needs glibc and D-Bus for Secret Service. It links the OpenTUI
native library in, so it does not need Zig at runtime.

## Set up anisette

Anisette is the device identity Apple expects on account requests. Apple does
not document it and `apw` ships no Apple binary. Run a server and give `apw` its
URL.

The tested server is `anisette-server-rs` 0.2.1. It serves a Windows identity by
default and a macOS identity on request. `apw` uses both, so the server must
support `?backend=macos`.

```sh
podman run -d --name apw-anisette \
  --network host \
  -v apw-anisette:/data \
  ghcr.io/fdkevin0/anisette-server-rs:0.2.1 --backend windows
```

`apw` uses the podman server above at `http://127.0.0.1:6969` by default. Set
`APW_ANISETTE_URL` or pass
`--anisette-url` when the server runs elsewhere. `anisette-v3-server` also works
when it answers the same routes.

The server holds a device identity that Apple ties to your account. Self-host it
or use a host you trust.

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
is not published yet; it installs `/usr/bin/apw` when it is.

## Sign in

Run `apw` and choose `login`, or use the command line:

```sh
apw login --account you@example.com
```

The first sign-in asks for the Apple ID password, a two-factor code, and the
escrow passcode. It then joins the Octagon trust circle and syncs. One command
leaves you with a readable snapshot.

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
exists, so a headless passphrase or anisette URL can live in a mode 0600 file:

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
