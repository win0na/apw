# Secrets

What `apw` stores, how it protects the snapshot, and which secrets it handles.

## Snapshot key

The snapshot uses AES-256-GCM with a 32-byte key. The key comes from one of two
places:

- Secret Service on the session bus, as an item with `application=apw`,
  `purpose=snapshot-key`, and `schema=1`. An item written by the keyring backend
  is copied to this one on the first read and left in place. A missing item is
  created; an item that exists but cannot be read is not replaced, and `apw`
  falls back to the passphrase instead.
- A passphrase, derived with Argon2id at 64 MiB, three iterations, and one lane.
  The KDF salt is in `config.toml`; the derived key lives for one process.

`APW_PASSPHRASE` selects passphrase mode. Without it, `apw` uses Secret Service
when available, then asks for a new passphrase on the first write or the existing
passphrase on a read. Each command that touches the snapshot resolves the key
again.

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

Everything except the passphrase and the Secret Service entry is inside the
encrypted snapshot. `state.json` holds counts, timestamps, the account, the
source, and failure counters, but no item secrets.

## Interface masking

The interface masks passwords with bullets. `r` reveals the selected password
for 20 seconds; moving the selection hides it again. `y` copies the password and
`o` copies the current one-time code.

`apw` does not write passwords, one-time codes, or passkey material to logs,
command history, or error text. JSON output includes a password only when the
command asks for it, such as `apw get --json` or `apw otp --json`.

## Escrow

The escrow passcode unlocks the Octagon recovery record. It is the device
passcode or the iCloud Security Code. `apw` sends it to Apple, keeps it in memory
for the join, and does not store it.

Each join spends one attempt. Apple allows about ten attempts before destroying
the record. A failed join increments the failure count in `state.json`, and
automatic logins stop retrying until you run `apw join` again.

## Device identity

`apw` holds the device identity Apple associates with account requests in
`$XDG_STATE_HOME/apw/adi/` (directory mode 0700, files mode 0600). Apple can link
requests from every client that uses the same identity, so treat the directory
as sensitive. Deleting it makes `apw` provision a new identity on the next
sign-in.

A configured external anisette server holds the identity instead. Run your own,
restrict who can reach it, and treat its data directory as sensitive.

## Threat model

`apw` protects the snapshot at rest and keeps secrets out of its own output. It
does not protect against:

- A compromised user session that can read process memory or the unlocked
  Secret Service entry.
- A malicious anisette server, when one is configured.
- Apple account compromise.
- A modified binary.
- A snapshot copied together with its key.

The snapshot is local. `apw` does not run a daemon and does not listen on a
socket.

## Recovery

If the snapshot cannot decrypt, the key changed or the file is damaged. Keep a
copy of the key or the passphrase before changing passphrase mode.

If the escrow record is exhausted, sign in on an Apple device, reset the iCloud
Security Code, and join again. If the snapshot is lost, run `apw login` and
`apw sync` to rebuild it from iCloud.
