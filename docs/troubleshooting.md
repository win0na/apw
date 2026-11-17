# Troubleshooting

This page covers the failures a first install and first sync produce. Each heading is the symptom; the body names the cause and the fix.

## apw cannot find a snapshot

```
no snapshot at /home/you/.local/share/apw/snapshot.bin; run `apw sync` first
```

There is no snapshot yet. Run `apw login` once, then `apw sync`. In this build, use `apw sync --fixture tests/fixtures/vault.json` to exercise the CLI without an account.

## apw cannot reach Secret Service

```
no Secret Service key and no terminal for a passphrase; set APW_PASSPHRASE
```

There is no D-Bus session, or no keyring provider is running. Start one (GNOME Keyring, KWallet), or set `APW_PASSPHRASE` and let `apw` derive the key. A timer has no terminal, so it needs the variable or an unlocked keyring.

## apw cannot decrypt the snapshot

```
cannot decrypt the snapshot: wrong key or damaged file
```

The passphrase is wrong, the keyring entry changed, or the file is damaged. Use the passphrase that created the snapshot, or delete `snapshot.bin` and sign in again. A new keyring entry produces the same error.

## apw login stops before the two-factor prompt

The anisette URL is missing, unreachable, or not returning a device identity. Check the URL and the server:

```sh
curl -s http://127.0.0.1:6969/
```

`APW_ANISETTE_URL` overrides `anisette_url` in the config, so an empty variable is not a problem but a wrong one is.

## The two-factor code is rejected

Request a new code and enter it immediately. A clock more than a minute off breaks the code. Check the time:

```sh
timedatectl
```

## The escrow passcode is rejected

The code is the device passcode or the iCloud Security Code, not the Apple ID password. `apw` makes one attempt per run and stops.

Apple allows about ten attempts before the recovery record is destroyed. Do not rerun the command in a loop. Verify the code on a signed-in device first, then run `apw login` once.

## Sync is inside the floor

```
last sync was 42s ago; the floor is 300s (use --force)
```

This is the rate limit working. Wait, or pass `--force` for a deliberate manual sync.

## Sync is rate limited by Apple

A `Retry-After` header wins over the local schedule. Wait for the stated interval; the next timer tick will try again. Do not remove the timer and retry by hand.

## Sync says the session expired

`apw sync` already re-fetched the service map once, and Apple rejected `mmeAuthToken` as well. The token cannot be renewed without a password login, so run `apw login` again. The snapshot still answers `pw` and `otp` while you do.

## A shared group is empty

The group has no items, or its PCS key did not arrive. `apw sync` reports a locked group and keeps the rest of the sync. Owned groups are the reliable path; shared-with-me is the least proven part of the design.

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
