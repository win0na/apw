# Operate

Queries read the snapshot. `apw sync`, `apw login`, `apw join`, and the hidden `probe` commands talk to iCloud.

## Sync the snapshot

```sh
apw sync          # respects the interval
apw sync --force  # ignores it
```

Syncs are at least five minutes apart. The binary enforces the floor, so a laptop that wakes up after a missed timer tick does not sync twice. The timer runs hourly, well above the floor.

A failed sync does not back off on its own. Fix the cause and let the next timer tick try again.

## What sync does

1. Refreshes `cloudKitToken` from `mmeAuthToken` through `setup.icloud.com` when CloudKit returns 401.
2. Fetches the TLK shares for the stored sponsor and for the new peer, then unions them.
3. Reads `tlkshare`, `synckey`, `item`, and `currentitem` records from the private `Passwords`, `Manatee`, and `WiFi` zones.
4. Decrypts each item with AES-SIV and writes the snapshot.
5. Reads shared groups from the `com.apple.security.shared.keychain` container.

Fetching only the new peer's shares returns a clean, empty keychain. The union in step 2 makes the data appear.

Sync refuses to replace a good snapshot when it cannot decrypt every item. Set `APW_ALLOW_PARTIAL=1` to accept a partial sync, and read the warning it prints. A first sync has no previous snapshot, so it writes the items it decrypted and marks the run partial. Shared groups that cannot be read keep their previous entries.

## Check the snapshot

```sh
apw status
apw status --json
```

`apw status` prints the account, source, entry and group counts, last sync time, snapshot path, and size. It reads the state file, not the snapshot, and never asks for the snapshot key. `status` succeeds even before the first login.

`needs_sync` is true when there is no last sync or the last one is older than the interval. `last_status` is `ok`, `partial`, `joined`, or `join-failed`.

## Re-authenticate

A 401 from CloudKit first re-fetches the service map once. That renews `cloudKitToken` while `mmeAuthToken` is still accepted. If the re-fetch also returns 401, the session is dead: run `apw login` again.

`apw login` keeps the existing peer and syncs, so no escrow attempt is spent. `mmeAuthToken` cannot be renewed from stored material, because only a password login mints a fresh PET.

The snapshot keeps working while the tokens are expired, so `list`, `get`, `wifi`, and `otp` still answer.

## Shared groups

Shared groups live in the `com.apple.security.shared.keychain` container, one zone per group. `apw sync` reads the zones directly and decrypts items with PCS share keys. It does not accept invites; a group already joined on any device is readable.

A group whose key or payload cannot be decoded is reported as a warning, and the rest of the sync continues. If every group read fails, the previous shared entries stay in the snapshot.

`apw list` shows a GROUP column and includes shared items by default. `--personal` restricts the list to personal items; `--group <uuid>` restricts it to one group.

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
apw list
```

`APW_FIXTURE` does the same when `--fixture` is absent. Fixtures use the same JSON model as the snapshot. A fixture sync keeps the existing session and peer keys and writes `snapshot.bin.prev` before it replaces the entries.
