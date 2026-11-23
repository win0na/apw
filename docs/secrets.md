# Secrets

This page describes what `apw` stores, how it protects the snapshot, and which
secrets it handles.

## Snapshot key

The snapshot uses AES-256-GCM with a 32-byte key. The key comes from one of two
places:

- Secret Service on the session bus, stored under the `apw` service and the
  `snapshot-key` account.
- A passphrase, derived with Argon2id at 64 MiB, three iterations, and one lane.
  The KDF salt is in `config.toml`; the derived key is cached for the process.

`APW_PASSPHRASE` selects passphrase mode. Without it, `apw` uses Secret Service
when available, then asks for a new passphrase on a first write or an existing
passphrase on a read. The key cache lasts for one process, so each command that
touches the snapshot resolves it again.

The snapshot and the key are separate. Copying `snapshot.bin` to another machine
without the key or the passphrase yields ciphertext.

## What the snapshot holds

- Login passwords, usernames, sites, notes, and one-time-code secrets.
- Wi-Fi passwords.
- Secure note titles and bodies.
- Passkey credential IDs, user handles, and private keys.
- Session tokens for iCloud and CloudKit.
- The Octagon peer keys and sponsor keys.
- Pending operations, including their item payloads.
- Recently Deleted items.

Everything except the passphrase and Secret Service entry is inside the encrypted
snapshot. `state.json` holds counts, timestamps, the account, the source, and
failure counters, but no item secrets.

## Interface masking

The interface masks passwords with bullets. Press `r` to reveal the selected
password for 20 seconds. Moving the selection hides it again. Press `y` to copy
the password or `o` to copy the current one-time code.

`apw` does not write passwords, one-time codes, or passkey material to logs,
command history, or error text. JSON output only includes a password when the
command explicitly asks for it, such as `apw get --json` or `apw otp --json`.

## Escrow

The escrow passcode unlocks the Octagon recovery record. It is the device
passcode or the iCloud Security Code. `apw` sends it to Apple, keeps it in memory
for the join, and does not store it.

Each join spends one attempt. Apple allows about ten attempts before destroying
the record. A failed join increments the failure count in `state.json` and
automatic logins stop retrying until you run `apw join` again.

## Anisette

The anisette server holds a device identity that Apple associates with account
requests. It can link requests from every client that uses the same identity.
Run your own server, restrict who can reach it, and treat its data directory as
sensitive.

## Threat model

`apw` protects the snapshot at rest and keeps secrets out of its own output. It
does not protect against:

- A compromised user session that can read process memory or the unlocked
  Secret Service entry.
- A malicious anisette server.
- Apple account compromise.
- A modified binary.
- A snapshot copied together with its key.

The snapshot is local. `apw` does not run a daemon and does not listen on a
socket.

## Recovery

If the snapshot cannot decrypt, the key changed or the file is damaged. Keep a
copy of the key or the passphrase before changing passphrase mode.

If the escrow record is exhausted, sign in on an Apple device and reset the
iCloud Security Code, then join again. If the snapshot is lost, run `apw login`
and `apw sync` to rebuild it from iCloud.
