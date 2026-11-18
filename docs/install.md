# Install

This page takes a Linux machine to a signed-in snapshot and a systemd timer.

This build signs in, joins the trust, and syncs against a live account. See [Project status](../README.md#project-status).

## Requirements

- Linux on x86_64 or aarch64, glibc.
- An Apple ID with two-factor authentication.
- An anisette server. See [Set up anisette](#set-up-anisette).
- A Secret Service provider (GNOME Keyring, KWallet) or `APW_PASSPHRASE`.
- Rust 1.85 or later, plus `cmake` and `perl` (the aws-lc build) to build from source.

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

`apw` uses `http://127.0.0.1:6969` by default. Pass `--anisette-url` or set `APW_ANISETTE_URL` when the server runs elsewhere. `anisette-v3-server` in Docker also works if it answers the same routes.

```sh
apw login --account you@example.com
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

`apw --version` prints `0.1.5`.

Prebuilt formats live in `packaging/`:

| Format | Command | Output |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.1.5-<target>.tar.gz` |
| Debian | `packaging/debian/build.sh` | `dist/apw_0.1.5_<arch>.deb` |
| AUR | `yay -S apw-cli` | installed package |
| Nix | `nix build` | `result/bin/apw` |

The AUR package is `apw-cli`; it installs `/usr/bin/apw` and conflicts with the unrelated `apw` wrapper. The recipe builds from the `v0.1.5` tag. The tarball and Debian scripts build the release binary first; set `APW_SKIP_BUILD=1` to reuse an existing one.

## Sign in

```sh
apw login --account you@example.com
```

On the first run `apw login` asks for the Apple ID, a new apw passcode, the Apple ID password, and a two-factor code. It then joins the Octagon trust circle and syncs, so one command leaves you with a usable snapshot.

The apw passcode encrypts the local snapshot and is reused as the escrow passcode. Enter your device passcode, or the iCloud Security Code if you set one, so the join needs no second prompt. Pass `--passcode` to use a different code for escrow.

Later logins keep the existing peer and only sync. Pass `--no-join` to skip the join, or `--join` to replace the peer. `apw join` does the same join on its own.

Escrow allows about ten attempts before Apple destroys the recovery record. Each join makes one attempt and never retries on its own. A wrong passcode stops the command.

`apw status` shows the account and entry count.

## Run the sync timer

```sh
apw install-units
systemctl --user daemon-reload
systemctl --user enable --now apw-sync.timer
```

The timer runs `apw sync` hourly. It reads `~/.config/apw/sync.env` when that file exists, so a headless passphrase or anisette URL can live there with mode 0600:

```sh
install -m600 /dev/null ~/.config/apw/sync.env
printf 'APW_PASSPHRASE=%s\n' 'your passcode' > ~/.config/apw/sync.env
```

`Persistent=true` catches up after a suspend or a missed run. Enable lingering when the user session is not always active:

```sh
loginctl enable-linger "$USER"
```

## Check the install

```sh
apw status
apw list
apw otp example.com
```

`apw status` prints the account, source, entry count, and snapshot path.
