# apw

Apple Passwords on Linux, in the terminal.

![apw showing the login list with Example selected and its fields in the item pane](assets/apw-tui.png)

## Install

With the install script:

```sh
curl -fsSL https://raw.githubusercontent.com/win0na/apw/main/scripts/install.sh | sh
```

With Cargo:

```sh
cargo install --git https://github.com/win0na/apw --locked
```

With a package manager:

```sh
curl -fsSLO https://github.com/win0na/apw/releases/download/v0.5.1/apw_0.5.1_amd64.deb \
  && sudo apt install ./apw_0.5.1_amd64.deb   # Debian
nix profile install github:win0na/apw          # Nix
```

The script installs to `~/.local/bin`; add it to `PATH` if needed. Prebuilt
packages are x86_64; on aarch64 use Cargo. Every method needs `libdbus-1`.

## Sign in

```sh
apw login
apw sync
```

The first sign-in asks for the Apple ID password, a two-factor code, and your
escrow passcode. The passcode spends one of about ten attempts and is never
stored.

## Use the interface

Run `apw`. Type to filter, `/` opens the command palette, and `enter` opens the
selected item.

| Key | Action |
| --- | --- |
| `y` | Copy the password |
| `o` | Copy the current one-time code |
| `r` | Reveal the password for 20 seconds |
| `e` | Edit the item |
| `t` | Move the item to Recently Deleted |

The full key map is in [Operate](docs/operate.md).

## Command line

Every subcommand answers from the snapshot, for scripts and the systemd timer.

```sh
apw list github
apw get github --password-only
apw otp github
apw sync --force
```

See [Reference](docs/reference.md).

## Requirements

- Linux x86_64 or aarch64 with glibc, and `libdbus-1`.
- An Apple ID with iCloud Passwords, Secret Service or `APW_PASSPHRASE`, and
  network access on the first sign-in.

## Docs

[Install](docs/install.md) · [Operate](docs/operate.md) ·
[Reference](docs/reference.md) · [Secrets](docs/secrets.md) ·
[Troubleshooting](docs/troubleshooting.md) · [Design](docs/design.md) ·
[Changelog](CHANGELOG.md)

## License

GPL-3.0-only.
