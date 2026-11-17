# Install

This page takes a Linux machine to a signed-in snapshot and a systemd timer.

This build signs in, joins the trust, and syncs against a live account. See [Project status](../README.md#project-status).

## Requirements

- Linux on x86_64 or aarch64, glibc.
- An Apple ID with two-factor authentication.
- An anisette server. See [Set up anisette](#set-up-anisette).
- A Secret Service provider (GNOME Keyring, KWallet) or `APW_PASSPHRASE`.
- Rust 1.85 or later to build from source.

The binary needs glibc and a D-Bus session for Secret Service. It does not need Deno, Chrome, or Apple software.

## Set up anisette

Anisette is the device identity Apple expects on account requests. Apple does not document it, and `apw` ships no Apple binary. Run a server and give `apw` its URL.

The tested server is `anisette-server-rs` 0.2.1. It serves a Windows identity by default and a macOS one on request; `apw` uses both, so the server must support `?backend=macos`:

```sh
podman run -d --name apw-anisette \
  --network host \
  -v apw-anisette:/data \
  ghcr.io/fdkevin0/anisette-server-rs:0.2.1 --backend windows
```

The URL is `http://127.0.0.1:6969`. `anisette-v3-server` in Docker also works if it answers the same routes.

```sh
apw login --anisette-url http://127.0.0.1:6969 --account you@example.com
```

`APW_ANISETTE_URL` overrides the config file. The server holds a device identity that Apple ties to your account. Self-host it or use a host you trust.

## Install

With Cargo:

```sh
cargo install --git https://github.com/win0na/apw
```

From a checkout:

```sh
cargo build --release
install -m755 target/release/apw ~/.local/bin/apw
```

`apw --version` prints `2.0.0`.

AUR, Debian, Nix, and static tarball packages arrive with the packaging pass. Until then, build from source.

## Sign in

```sh
apw login --account you@example.com
apw join
```

`apw login` prompts for the Apple ID password, then for the two-factor code from a trusted device. It writes the session to the snapshot.

`apw join` joins the Octagon trust circle. It prompts for the device passcode or iCloud Security Code and recovers the keychain keys from the escrow record.

Escrow allows about ten attempts before Apple destroys the recovery record. `apw join` makes one attempt per run and never retries on its own. A wrong passcode stops the command.

On success the snapshot is written. `apw status` shows the account and entry count.

## Run the sync timer

```sh
apw install-units
systemctl --user daemon-reload
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. `Persistent=true` catches up after a suspend or a missed run. Enable lingering when the user session is not always active:

```sh
loginctl enable-linger "$USER"
```

## Check the install

```sh
apw status
apw pw list
apw otp get example.com
```

`apw status` prints the account, source, entry count, and snapshot path.
