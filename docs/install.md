# Install

This page takes a Linux machine from nothing to a signed-in snapshot and an hourly systemd timer.

## Requirements

- Linux on x86_64 or aarch64 with glibc.
- An Apple ID with two-factor authentication.
- An anisette server. See [Set up anisette](#set-up-anisette).
- A Secret Service provider (GNOME Keyring, KWallet) or `APW_PASSPHRASE`.
- To build: Rust 1.88 or later, `cmake`, `perl`, and `libdbus-1`. On Debian and Ubuntu install `libdbus-1-dev` and `pkg-config`; on Arch install `dbus`, `cmake`, `perl`, and `pkgconf`.

The binary needs glibc and a D-Bus session for Secret Service. It does not need Deno, Chrome, or Apple software.

## Set up anisette

Anisette is the device identity Apple expects on account requests. Apple does not document it, and `apw` ships no Apple binary. Run a server and give `apw` its URL.

The tested server is `anisette-server-rs` 0.2.1. It serves a Windows identity by default and a macOS identity on request. `apw` uses both, so the server must support `?backend=macos`.

```sh
podman run -d --name apw-anisette \
  --network host \
  -v apw-anisette:/data \
  ghcr.io/fdkevin0/anisette-server-rs:0.2.1 --backend windows
```

`apw` uses `http://127.0.0.1:6969` by default. Pass `--anisette-url` or set `APW_ANISETTE_URL` when the server runs elsewhere. `anisette-v3-server` in Docker also works if it answers the same routes.

The server holds a device identity that Apple ties to your account. Self-host it or use a host you trust.

## Install the binary

With Cargo:

```sh
cargo install --git https://github.com/win0na/apw
```

From a checkout:

```sh
cargo build --release
install -m755 target/release/apw ~/.local/bin/apw
```

`apw --version` prints `0.2.1`.

Prebuilt formats live in `packaging/`:

| Format | Command | Output |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.2.1-<target>.tar.gz` |
| Debian | `packaging/debian/build.sh` | `dist/apw_0.2.1_<arch>.deb` |
| Nix | `nix build` | `result/bin/apw` |

The tarball and Debian scripts build the release binary first; set `APW_SKIP_BUILD=1` to reuse an existing one. The AUR recipe in `packaging/aur/` is not published; when it is, it installs `/usr/bin/apw`.

## Sign in

```sh
apw login --account you@example.com
```

On the first run `apw login` asks for the Apple ID password, a two-factor code, and the escrow passcode. Then it joins the Octagon trust circle and syncs, so one command leaves you with a usable snapshot.

The snapshot key goes to Secret Service on first write. If Secret Service is unavailable, `apw` asks for a new apw passphrase and derives the key with Argon2id. Set `APW_PASSPHRASE` to choose passphrase mode from the start.

The escrow passcode is your device passcode, or the iCloud Security Code if you set one. It is used once, never stored, and never reused as the snapshot passphrase. In a non-interactive run, set `APW_ESCROW_PASSCODE`.

Later logins keep the existing peer and only sync. Pass `--no-join` to skip the join, `--join` to replace the peer, or `--refresh` to re-read the service URLs without signing in again. `apw join` runs the join on its own.

Escrow allows about ten attempts before Apple destroys the recovery record. Each join makes one attempt and never retries on its own. A wrong passcode stops the command.

`apw status` shows the account and entry count.

## Run the sync timer

```sh
apw install-units
systemctl --user daemon-reload
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. It reads `~/.config/apw/sync.env` when the file exists, so a headless passphrase or anisette URL can live in a mode 0600 file:

```sh
install -m600 /dev/null ~/.config/apw/sync.env
printf 'APW_PASSPHRASE=%s\n' 'your apw passphrase' > ~/.config/apw/sync.env
```

Use the apw passphrase here, never the device passcode. In Secret Service mode, the timer needs an unlocked keyring instead of this file.

`Persistent=true` catches up after suspend or a missed run. Enable lingering when the user session is not always active:

```sh
loginctl enable-linger "$USER"
```

## Check the install

```sh
apw status
apw list
apw otp example.com
```

`apw status` prints the account, source, entry count, and snapshot path. Next, read [Operate](operate.md) for sync and re-authentication, or [Troubleshooting](troubleshooting.md) when a step fails.
