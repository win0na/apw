# Troubleshooting

Each heading is a symptom. The body names the cause and the fix.

## apw cannot find a snapshot

```
no snapshot at /home/you/.local/share/apw/snapshot.bin; run `apw login` first
```

There is no snapshot yet. Run `apw login` once. To exercise the CLI without an account, use `apw sync --fixture tests/fixtures/vault.json`.

`apw status` succeeds even before the first login; the other query commands exit 4.

## apw cannot reach Secret Service

```
no snapshot key; set APW_PASSPHRASE or unlock Secret Service
```

There is no D-Bus session, or no keyring provider is running. Start one (GNOME Keyring, KWallet), unlock it, or set `APW_PASSPHRASE`. A timer has no terminal, so it needs an unlocked keyring or the variable.

## apw cannot decrypt the snapshot

```
cannot decrypt the snapshot: wrong key or damaged file
```

The passphrase is wrong, the keyring entry changed, or the file is damaged. If an older release left the wrong key in Secret Service, `apw` prompts for the snapshot passphrase and opens the file. Clear the stale entry so the next unlock caches the right key.

To clear the entry by hand:

```sh
secret-tool clear service apw account snapshot-key
```

Then run the command again and enter the passphrase that created the snapshot. Deleting `snapshot.bin` and signing in again also works, but it spends an escrow attempt.

## A build fails looking for dbus

```
error: failed to run custom build command for `libdbus-sys`
```

The Secret Service backend needs `libdbus-1` headers and `pkg-config`. On Debian and Ubuntu:

```sh
sudo apt-get install -y libdbus-1-dev pkg-config cmake perl
```

On Arch, install `dbus`, `cmake`, `perl`, and `pkgconf`. A build without the keyring feature needs none of them: `cargo build --no-default-features`.

## apw login stops before the two-factor prompt

The anisette server is not answering at the configured URL. The default is `http://127.0.0.1:6969`. Check the URL and the server:

```sh
curl -s http://127.0.0.1:6969/
```

`APW_ANISETTE_URL` overrides `anisette_url` in the config. An empty variable is not a problem; a wrong one is.

## The two-factor code is rejected

Request a new code and enter it immediately. A clock more than a minute off breaks the code. Check the time:

```sh
timedatectl
```

## The escrow passcode is rejected

The code is the device passcode or the iCloud Security Code, not the Apple ID password. `apw` makes one attempt per run and stops.

Apple allows about ten attempts before the recovery record is destroyed. Do not rerun the command in a loop. Verify the code on a signed-in device first, then run `apw join` once. Set `APW_ESCROW_PASSCODE` for a non-interactive run.

## The escrow budget cannot be read

```
cannot read the escrow attempt budget; refusing to recover (set APW_SKIP_ESCROW_BUDGET=1 to join anyway)
```

Apple's reply did not include the remaining-attempt count, or the request failed. `apw` refuses to spend an attempt it cannot count. If you accept the risk, set `APW_SKIP_ESCROW_BUDGET=1` and run `apw join` once.

## Sync is inside the floor

```
last sync was 42s ago; the floor is 300s (use --force)
```

This is the rate limit working. Wait, or pass `--force` for a deliberate manual sync.

## Sync refuses a partial snapshot

```
sync could not decrypt 3 item(s); keeping the previous snapshot
```

One or more records did not decrypt, so `apw` kept the previous snapshot. Leave `APW_ALLOW_PARTIAL` unset and retry on the next timer tick. If the same items keep failing, set `APW_ALLOW_PARTIAL=1` to accept the partial result; the missing entries will be absent until a later sync succeeds.

## Sync says the session expired

`apw sync` already re-fetched the service map once, and Apple rejected `mmeAuthToken` as well. The token cannot be renewed without a password login, so run `apw login` again. The snapshot still answers `list`, `get`, `wifi`, and `otp` while you do.

## A shared group is empty

The group has no items, or its PCS key did not arrive. `apw sync` prints a warning and keeps the previous shared entries when a group cannot be read. Owned groups are the reliable path; shared-with-me is the least proven part of the design.

## The timer does not fire

```sh
systemctl --user status apw-sync.timer
journalctl --user -u apw-sync -n 50
```

If the user session is not active, enable lingering:

```sh
loginctl enable-linger "$USER"
```

Then reload and start the timer again.

## An upgrade from 0.1.5 cannot open the snapshot

0.1.5 could store a new random key in Secret Service while the snapshot used a passphrase. 0.2.0 prompts for the passphrase when the stored key fails. Clear the stale entry so the derived key can be cached:

```sh
secret-tool clear service apw account snapshot-key
```

Then run the command again.
