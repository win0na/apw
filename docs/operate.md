# Operate

Queries read the snapshot. `apw sync` is the only command that talks to iCloud.

## Sync the snapshot

```sh
apw sync            # respects the interval
apw sync --force    # ignores it
```

Syncs are at least five minutes apart. The binary enforces the floor, so a laptop that was asleep catches up on the next timer tick instead of syncing in a burst. Errors back off exponentially to six hours, and a `Retry-After` header wins over the local schedule.

The timer runs hourly, well above the floor.

## What a sync does

1. Refresh `cloudKitToken` from `mmeAuthToken` through `setup.icloud.com`.
2. Fetch the TLK shares for the recovered sponsor and union them with the new peer's shares.
3. Read `tlkshare`, `synckey`, `item`, and `currentitem` records from the private zones.
4. Decrypt each item with AES-SIV and write the snapshot.

Fetching only the new peer's shares returns a clean, empty keychain. The union in step 2 is what makes the data appear.

## Check the snapshot

```sh
apw status
apw status --json
```

`apw status` prints the account, source, entry and group counts, the last sync time, and the snapshot path and size. It reads the state file, not the snapshot, so it never asks for the snapshot key.

`needs_sync` is true when there is no last sync or the last one is older than the interval.

## Re-authenticate

A 401 from CloudKit first re-fetches the service map once. That renews `cloudKitToken` while `mmeAuthToken` is still accepted. If the re-fetch also 401s, the session is dead: run `apw login` again. It keeps the existing peer and syncs, so no escrow attempt is spent. `mmeAuthToken` cannot be renewed from stored material, because only a password login mints a fresh PET. The escrow step makes one attempt per run.

The snapshot keeps working while the tokens are expired, so `pw` and `otp` continue to answer.

## Shared groups

Shared groups live in the `com.apple.security.shared.keychain` container, one zone per group. `apw sync` reads the zones directly and decrypts the items with PCS share keys. It does not accept invites; the shared database is per account, so a group that was already joined on any device is readable.

A group whose key or payload cannot be decoded is reported as locked, and the rest of the sync continues.

`apw pw list` shows a GROUP column and includes shared items by default. `--personal` restricts the list to personal items; `--group <uuid>` restricts it to one group.

## Inspect the timer

```sh
systemctl --user status apw-sync.timer
journalctl --user -u apw-sync -n 50
```

`apw install-units` writes `apw-sync.service` and `apw-sync.timer` to `~/.config/systemd/user/`. The service runs `apw sync` once; the timer fires hourly with `Persistent=true`.

If the timer never runs, enable lingering for the user:

```sh
loginctl enable-linger "$USER"
```

## Sync a fixture

The fixture path exercises the storage layer without Apple credentials:

```sh
apw sync --fixture tests/fixtures/vault.json
apw pw list
```

`APW_FIXTURE` does the same when `--fixture` is absent. Fixtures use the same JSON model as the snapshot.
