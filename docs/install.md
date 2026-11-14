# Install

This page takes a Linux machine from nothing to a working snapshot and a systemd timer.

The commands describe the finished 2.0 build. This build reads fixtures: `login` and live `sync` are not implemented yet. See [Status](../README.md#status).

## Before you start

- Linux x86_64 or aarch64 with glibc.
- An Apple ID with two-factor authentication.
- A Secret Service provider, or a passphrase in `APW_PASSPHRASE`.
- Rust 1.82 or later when you build from source.

The binary needs glibc and a D-Bus session for Secret Service. It does not need Deno, Chrome, or any Apple software.

## Anisette

Anisette is the device identity Apple expects on account requests. Apple does not document it and apw ships no Apple binary. Run a server and give apw its URL:

- `anisette-v3-server` in Docker, on the same machine or a trusted host.
- A local CoreADI under Wine, as in `Sank6/Anisette-on-Wine`.

```sh
apw login --anisette-url http://127.0.0.1:6969 --account you@example.com
```

`APW_ANISETTE_URL` overrides the config file. Treat the server as sensitive: it holds a device identity that Apple ties to your account, so self-host it or use a host you trust.

## Install the binary

With Cargo:

```sh
cargo install --git https://github.com/bendews/apw
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
```

apw prompts for the Apple ID password, then for the two-factor code from a trusted device. It joins the trust circle and asks for the device passcode or iCloud Security Code to recover the keychain keys.

Escrow allows about ten attempts before Apple destroys the recovery record. `apw login` makes one attempt per run and never retries on its own. A wrong passcode is reported and the command stops.

On success the snapshot is written. `apw status` shows the account and entry count.

## Timer

```sh
apw install-units
systemctl --user daemon-reload
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. `Persistent=true` catches up after a suspend or a missed run. Enable lingering when the user session is not always active:

```sh
loginctl enable-linger "$USER"
```

## Verify

```sh
apw status
apw pw list
apw otp get example.com
```

`apw status` prints the account, source, entry count, and snapshot path.
