# Operate

This page covers day-to-day sync, sign-in, writes, and timer checks.

## Sync the snapshot

Run `apw sync`, or choose `/sync` in the interface. The command refuses a second
sync inside the five-minute floor. Use `--force` or `/sync --force` to override
the floor after you know the previous run finished.

A sync reads the keychain into the snapshot and pushes queued local writes. A
queued write also bypasses the floor, so the queue can drain without `--force`.
Pending writes are limited to 200 operations and 16 MiB of payload. When either
limit is reached, new writes are refused until a sync or `apw resolve` drains the
queue.

The interface runs sync in the background and shows progress in the footer. It
keeps the snapshot lock only for the sync itself, so the timer and the command
line can run while the interface is idle.

## What sync does

1. Opens the session stored in the snapshot, or fails with an expired-session
   error that asks you to sign in again.
2. Lists record zones and merges remote records into the local vault.
3. Pushes queued creates, edits, and deletes.
4. Writes the new snapshot and state atomically.

A partial sync keeps the records it read and records the failure in state. The
next sync retries. Conflicts appear as pending operations with a blocked reason;
open **Pending** in the interface and keep the local change or take the remote
version.

## Check the snapshot

```sh
apw status
apw list
apw get example.com
apw pending
apw trash
```

`apw status` prints the account, source, entry counts, last sync, and snapshot
path. `--json` returns the same fields on a pipe.

In the interface, the dashboard shows the account, counts, warnings, recent
items, and the last sync. The footer shows the sync time.

## Write locally

```sh
apw add login example.com --username you@example.com --generate
apw add note "Recovery codes" --body "Stored offline"
apw edit example.com --title Example --generate
apw rm example.com --yes
apw restore --id <id>
```

Writes change the snapshot and queue a CloudKit operation. They do not touch the
network. The next sync pushes them.

`apw rm` requires `--yes`. The item moves to Recently Deleted and remains
recoverable for 30 days. The interface shows the same confirmation and offers
undo with `u`.

Shared entries cannot be edited or deleted with these commands. Change them on a
device that owns the group.

## Sign in again

```sh
apw login
apw sync
```

When the session expires, `apw sync` fails with an authentication error. A new
`apw login` refreshes the tokens and keeps the existing peer. Use `--refresh` to
re-read the service URLs without a password.

In the interface, `/login` opens the same steps: Apple ID, password, two-factor
code, then an optional join. The anisette server field is optional and empty by
default, which uses the native device identity. `/join` asks for the escrow
passcode and spends one attempt.

## Shared groups

The interface lists snapshot groups; selecting one shows its item count. `g` adds a personal login to
a group or removes a shared item from its group. Adding and removing group items
needs a live session and runs on the network, then the next sync reads the result
back into the snapshot.

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

The unit runs `apw sync` with the environment from
`~/.config/apw/sync.env`. A failed run leaves the last status and failure count
in `state.json`; the next run backs off instead of retrying in a tight loop.

## Sync a fixture

Tests and demos can read a JSON fixture instead of iCloud:

```sh
APW_FIXTURE=tests/fixtures/vault.json apw sync --force
```

Fixture sync writes the snapshot from the file and marks the state source as
`fixture`. The interface shows a warning for fixture data. Pass
`--fixture <path>` instead of the environment variable when you want the path in
the command line.
