# apw

Read Apple Passwords on Linux from an encrypted local snapshot.

`apw` signs in to your Apple ID, joins the keychain trust with your escrow
passcode, and keeps a snapshot of logins, notes, Wi-Fi networks, passkeys, and
groups on disk. Bare `apw` opens a terminal interface. Every subcommand keeps
the command-line contract, so scripts and the systemd timer continue to work.

## Features

- **Terminal interface:** browse, search, add, edit, delete, restore, and sync
  without leaving the terminal.
- **Full vault view:** logins, secure notes, Wi-Fi networks, passkeys, groups,
  Recently Deleted, and pending changes.
- **Offline reads:** `apw get`, `apw list`, and `apw otp` answer from the
  snapshot without a network call.
- **Local-first writes:** changes are encrypted into the snapshot and queued,
  then pushed by the next sync.
- **Machine output:** JSON on a pipe, stable exit codes, and `--password-only`
  for shell use.
- **Few moving parts:** one executable and the OpenTUI shared library, both in
  the same archive.

## Requirements

- Linux on x86_64 or aarch64.
- Network access to Apple on the first sign-in, for the device identity.
- Rust 1.88 or newer and Zig 0.17.1 to build from source.
- `libdbus-1-dev` and `pkg-config` to build with the Secret Service backend.
- An Apple ID with iCloud Passwords enabled.

The built executable does not need Rust, Zig, or the OpenTUI sources at
runtime; it needs the OpenTUI shared library that ships beside it.

## Install

Build from source, or use the packaging scripts in `packaging/`.

To build from source:

```sh
git clone --recurse-submodules https://github.com/win0na/apw
cd apw
cargo build --release --locked
./target/release/apw --version
```

`cargo install` builds only the executable; the OpenTUI library stays in the
checkout. Clone the repository, install from the checkout, and copy the
library:

```sh
git clone --recurse-submodules https://github.com/win0na/apw
cd apw
cargo install --path . --locked
install -s -D -m 0755 opentui/packages/native/lib/x86_64-linux/libopentui.so \
  "${CARGO_HOME:-$HOME/.cargo}/lib/apw/libopentui.so"
```

Zig must be on `PATH`; the build uses it once for the native library and reuses
the result.

The executable loads `libopentui.so` from `../lib/apw` relative to itself.
Without Cargo, install both files:

```sh
install -D -m 0755 target/release/apw ~/.local/bin/apw
install -s -D -m 0755 opentui/packages/native/lib/x86_64-linux/libopentui.so \
  ~/.local/lib/apw/libopentui.so
```

Use `aarch64-linux` in place of `x86_64-linux` on ARM.

Package-specific steps are in [Install](docs/install.md).

## Sign in

Run the first sign-in from the command line:

```sh
apw login
apw sync
```

The first sign-in may ask for a two-factor code and an escrow passcode. The
escrow passcode spends one of ten attempts. A successful join makes the
keychain readable; later sign-ins usually need only the password.

Bare `apw` requires a terminal. When stdin or stdout is not a terminal, apw uses
the command line instead.

## Use the interface

Run `apw` with no arguments.

- Type to filter the current list.
- Type `/` to open the command palette.
- Press `enter` to open the selected item.
- Press `tab` to move between panes.
- Press `esc` to go back.
- Press `ctrl+z` to suspend and `fg` to return.
- Press `ctrl+c` to quit.

The item pane shows the fields and the actions available for that kind of item.
Common keys:

| Key | Action |
| --- | --- |
| `y` | Copy the password |
| `o` | Copy the current one-time code |
| `r` | Reveal the password for 20 seconds |
| `e` | Edit the item |
| `t` | Move the item to Recently Deleted |
| `s` | Restore a trashed item |
| `g` | Add a login to a group, or leave its group |
| `u` | Undo the last move to Recently Deleted |
| `l` / `v` | Keep the local change or take the remote version of a pending op |

Slash commands mirror the CLI names: `/list`, `/notes`, `/wifi`, `/passkeys`,
`/groups`, `/trash`, `/pending`, `/add`, `/add wifi`, `/add note`, `/edit`,
`/rm`, `/restore`, `/sync`, `/sync --force`, `/resolve --local`,
`/resolve --remote`, `/passkey import`, `/passkey export`, `/otp`, `/group`,
`/login`,
`/login --refresh`, `/join`, `/status`, `/help`, and `/quit`.

The interface reads the snapshot on launch. If another process changes the
snapshot, the interface reloads it within a few seconds.

## Use the CLI

The CLI keeps the existing arguments, output, and exit codes.

```sh
apw list github
apw get github
apw get github --password-only
apw otp github
apw add login github.com --username you --generate
apw sync --force
```

JSON is the default when stdout is a pipe, unless `--wide`, `--no-header`,
`--password-only`, or a bare `apw otp QUERY` asks for text:

```sh
apw get github --json
```

Human-readable tables are used on a terminal. JSON errors use
`{"status":1,"error":{"code":"...","message":"..."}}`.

## Configuration

Configuration lives in `$XDG_CONFIG_HOME/apw/config.toml` and state in
`$XDG_STATE_HOME/apw/state.json`. The snapshot and its lock live in
`$XDG_DATA_HOME/apw/`.

Environment variables override the anisette server URL, account, directories,
and the snapshot passphrase. See [Reference](docs/reference.md).

The `[tui]` table remembers interface preferences:

```toml
[tui]
last_category = "logins"
split = true
show_wordmark = true
```

## Docs

- [Install](docs/install.md)
- [Operate](docs/operate.md)
- [Reference](docs/reference.md)
- [Secrets](docs/secrets.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Design](docs/design.md)

## License

GPL-3.0-only.
