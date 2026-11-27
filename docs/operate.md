# Operate

Day-to-day use of the interface, with the command line for scripts and the
timer.

## The interface

Run `apw` with no arguments. The dashboard shows the account, counts, warnings,
recent items, and the last sync. Category tabs open the vault.

- Type to filter the focused list.
- `/` opens the command palette; `enter` opens the selected item.
- `tab` moves between panes, `esc` goes back, and `ctrl+c` quits.
- `ctrl+z` suspends; return with `fg`.

| Key | Action |
| --- | --- |
| `y` | Copy the password |
| `o` | Copy the current one-time code |
| `r` | Reveal the password for 20 seconds |
| `e` | Edit the item |
| `t` | Move the item to Recently Deleted |
| `s` | Restore a trashed item |
| `g` | Add the login to a group, or leave its group |
| `u` | Undo the last move to Recently Deleted |
| `l` / `v` | Keep the local change or take the remote version of a pending operation |

Slash commands mirror the subcommands: `/list`, `/notes`, `/wifi`, `/passkeys`,
`/groups`, `/add`, `/edit`, `/rm`, `/restore`, `/trash`, `/pending`, `/sync`,
`/resolve`, `/passkey`, `/otp`, `/group`, `/login`, `/join`, `/status`,
`/help`, and `/quit`.

The interface reloads the snapshot when its modification time changes, checked
every few seconds and after its own writes. It holds the snapshot lock only for
a sync, so the timer and the command line can run while it is idle.

## Sync

`/sync` runs in the background and shows progress in the footer. A second sync
inside the five-minute floor is refused; `/sync --force` overrides the floor
when the previous run has finished. A queued write bypasses the floor, so the
queue can drain without `--force`.

The command-line equivalent is `apw sync`, with the same floor. Pending writes
are capped at 200 operations and 16 MiB of payload; at either limit new writes
are refused until a sync or `apw resolve` drains the queue.

A sync:

1. Opens the session stored in the snapshot, or fails with an expired-session
   error that asks you to sign in again.
2. Lists record zones and merges remote records into the local vault.
3. Pushes queued creates, edits, and deletes.
4. Writes the snapshot and state atomically.

A partial sync keeps the records it read and records the failure in state; the
next sync retries. Conflicts arrive as pending operations with a blocked reason.
Open **Pending** and keep the local change or take the remote version, or run
`apw resolve --local` or `--remote`.

## Read and write

The interface reads and writes the same snapshot as the CLI, so an item added
in one appears in the other. Writes change the snapshot and queue a CloudKit
operation; they do not touch the network.

```sh
apw status
apw list
apw get example.com
apw add login example.com --username you@example.com --generate
apw add note "Recovery codes" --body "Stored offline"
apw edit example.com --title Example --generate
apw rm example.com --yes
apw restore --id <id>
apw pending
apw trash
```

`apw rm` requires `--yes`; the item moves to Recently Deleted and stays
recoverable for 30 days. Shared entries cannot be edited or deleted here;
change them on a device that owns the group.

## Sign in again

When the session expires, a sync fails with an authentication error. `/login`
runs the wizard: Apple ID, password, a two-factor code when Apple asks, then an
optional join. The anisette field is optional and empty by default, which uses
the native device identity. `/join` asks for the escrow passcode and spends one
attempt.

```sh
apw login
apw sync
```

`apw login` keeps the existing peer; `--refresh` re-reads the service URLs
without a password.

## Shared groups

The interface lists snapshot groups, and selecting one shows its item count.
`g` adds a personal login to a group or removes a shared item from its group.
Both need a live session, run on the network, and are read back by the next sync.

```sh
apw group list
apw group show Family
apw group add Family example.com
apw group remove Family <record> --yes
```

## Inspect the timer

```sh
systemctl --user status apw-sync.timer
systemctl --user list-timers apw-sync.timer
journalctl --user -u apw-sync.service -n 50
```

The unit runs `apw sync` with the environment from `~/.config/apw/sync.env`. A
failed run leaves the last status and failure count in `state.json`; the next run
backs off instead of retrying in a tight loop.

## Sync a fixture

Tests and demos can read a JSON fixture instead of iCloud:

```sh
APW_FIXTURE=tests/fixtures/vault.json apw sync --force
```

Fixture sync writes the snapshot from the file and marks the state source as
`fixture`; the interface shows a warning for that data. Use `--fixture <path>`
when the path should appear on the command line instead of in the environment.
