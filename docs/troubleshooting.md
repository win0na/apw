# Troubleshooting

The failures you are most likely to see, with the message and the next action.

## `apw` exits without opening the interface

Bare `apw` opens the interface only when stdin and stdout are terminals and
`TERM` is not `dumb`. In a pipe, a script, or a terminal that reports `dumb`, it
prints help and exits. Run it in a terminal, or use a subcommand.

## `no snapshot at ...; run apw login first`

The snapshot file is missing. Run `apw`, then `/login` and `/sync`; a script
runs `apw login` and `apw sync`.

## `apw` asks for a passphrase and then cannot decrypt

The passphrase derives a different key from the one that wrote the snapshot. Use
the passphrase that created it. If `kdf_salt` changed or the Secret Service entry
was replaced, restore the original key or rebuild the snapshot from iCloud.

## `Secret Service is unavailable and stdin is not a terminal`

The Secret Service backend is missing and `apw` cannot prompt. Set
`APW_PASSPHRASE` for the command or in the timer's `sync.env`. On a desktop
session, unlock the collection and check that `DBUS_SESSION_BUS_ADDRESS` points
at it.

## A build fails looking for Zig or the OpenTUI library

The source build needs Zig 0.17.1 and the `opentui` submodule. Clone with
`--recurse-submodules`, or run:

```sh
git submodule update --init --recursive
zig version
```

The first build prepares the vendored Zig dependencies and compiles the native
library into `opentui/packages/native/lib/`; later builds reuse it, and a changed
submodule commit triggers a rebuild. If Zig is not on `PATH`:

```sh
PATH=/path/to/zig-0.17.1:$PATH cargo build --release --locked
```

`OPENTUI_LIB_DIR` overrides the native library directory and must contain
`opentui.h` and `libopentui.so` (or `libopentui.a` for a static build).

## A build fails looking for `dbus`

Install the development headers:

```sh
sudo apt-get install libdbus-1-dev pkg-config   # Debian, Ubuntu
sudo pacman -S dbus pkgconf                     # Arch
```

Build without the Secret Service backend when you only need passphrase mode:

```sh
cargo build --release --locked --no-default-features --features tui
```

## `apw login` stops before the two-factor prompt

Apple rejected the device identity, or a configured anisette server did not
answer. If `APW_ANISETTE_URL` or `anisette_url` is set, check that the server is
reachable. Otherwise delete `$XDG_STATE_HOME/apw/adi/` and sign in again; `apw`
provisions a new identity. Then run `/login --refresh` in the interface, or
`apw login --refresh`, to re-read the service URLs.

## `apw login` reports `GSA answered HTTP 503`

Apple's edge refuses the literal `<macOS;` platform token in `X-MMe-Client-Info`
with HTTP 503. `apw` rewrites it to `<Mac OS X;` before sending and retries with
the Windows identity when the macOS one is still refused, so seeing this error
means both were refused. Check a configured anisette server, or delete
`$XDG_STATE_HOME/apw/adi/` so the next sign-in provisions a new identity. A
fresh identity can be refused for a few minutes; retry after a short wait.

## `the session has no escrow URL`

The escrow proxy URL comes from the `keychainsync` entry of Apple's service map,
and Apple returns that entry only to a macOS client. A session created while
`apw` sent the literal `<macOS;` token signed in as a Windows client, so its map
lists dataclasses only and the escrow proxy is missing.

Sign in again with `/login` in the interface, or `apw login`, to obtain a macOS
session. If the URL is still missing, the macOS identity is being refused; check
for a 503 as above.

## The two-factor code is rejected

Use the current code from a trusted device. A code is valid for a short window;
request another when it expires. The interface keeps the wizard open and shows
the error above the field.

## The escrow passcode is rejected

Use the device passcode or the iCloud Security Code, not the Apple ID password.
A failed join spends one attempt and increments the failure count. Check the
passcode before trying again; repeated failures can exhaust the recovery record.

## `sync` refuses because of the floor

The previous sync finished less than 300 seconds ago. Wait, or use `--force` /
`/sync --force` when the previous run is done.

## `sync` says the session expired

The stored tokens are no longer accepted. Run `/login` in the interface, or
`apw login`. The peer is kept, so the join is not repeated unless you pass
`--join`.

## A shared group is empty

Shared items appear only after a sync reads them back. Run `/sync` in the
interface, or `apw sync`, then open **Groups** or run `apw group show <group>`. A group whose protection cannot be opened
still appears by name when `apw` journaled it.

## The timer does not fire

```sh
systemctl --user status apw-sync.timer
systemctl --user enable --now apw-sync.timer
journalctl --user -u apw-sync.service -n 50
```

If the user session is not always active, enable lingering with
`loginctl enable-linger "$USER"`. The service reads `sync.env`; a bad path or a
missing passphrase leaves an error in the journal.

## The interface does not update after a CLI write

The interface reloads the snapshot when its modification time changes, checked
every few seconds and after its own writes. A file copied in with an old mtime
can be missed. Run `/sync` or restart the interface.

## Copying a password does nothing

`apw` uses the system clipboard when it can and falls back to OSC 52. Your
terminal must allow clipboard writes; over SSH, enable clipboard integration in
the terminal. If both paths fail, select the text after pressing `r`.

## The interface is too narrow

Below 60 columns the dashboard drops the right column and hides the wordmark.
Below 40 columns the layout is not supported. Widen the terminal or use the CLI.
