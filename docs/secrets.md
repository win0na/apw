# Secrets

apw keeps one secret: the key that opens the snapshot. Everything else lives inside it.

## Snapshot key

The snapshot is encrypted with a random 256-bit key. The key comes from one of two places:

| Source | When | How |
| --- | --- | --- |
| Secret Service | A session bus is available | Entry `service=apw`, `account=snapshot-key` |
| Passphrase | No bus, or `APW_PASSPHRASE` is set | Argon2id, 64 MiB, 3 iterations, 1 lane |

The passphrase is never written to disk. Its 16-byte salt is `kdf_salt` in `config.toml`; the derived key exists only in memory.

`APW_PASSPHRASE` forces the passphrase path, which is what a headless timer uses. Without the variable and without a bus, apw prompts on the terminal.

## What the snapshot holds

| Data | Why it is sensitive |
| --- | --- |
| Passwords, notes, TOTP secrets | The vault itself |
| Passkey metadata | Which sites have passkeys, and under which account |
| Session tokens | Access to the iCloud account until they expire |
| Peer signing and encryption keys | Identity in the trust circle |
| Shared group keys | Access to shared items |

Treat the snapshot as a password database. It is one file, and one key opens all of it.

## Escrow

The device passcode or iCloud Security Code unlocks the keychain keys once, during `apw login`. apw does not store it, cache it, or send it anywhere except the escrow request.

Apple allows about ten attempts before the recovery record is destroyed. `apw login` makes one attempt per run. It does not retry on failure and does not loop. A wrong code ends the command.

## Anisette

The anisette server holds a device identity that Apple ties to the account. It does not see the Apple ID password or the keychain, but a hostile server can impersonate the device. Self-host it or use a host you trust.

## Threat model

| Adversary | Protected | Why |
| --- | --- | --- |
| Disk theft | Yes | The snapshot is AES-256-GCM; the key is in the keyring, not on disk. |
| Another local user | Yes | The keyring entry is per user, and the snapshot is mode `0600`. |
| A process running as you | No | It can read the keyring and the snapshot. |
| Root | No | It can read process memory and the keyring. |
| Network, or Apple | No | Apple holds the account and the server-side data; TLS protects transit only. |

Advanced Data Protection changes what Apple can read on its side. apw has not been tested against an ADP account.

## Recovery

A lost key means a lost snapshot. Delete `snapshot.bin` and sign in again; escrow attempts apply to the new login.

In keyring mode the key is not portable. Copying `snapshot.bin` to another machine does not make it readable. In passphrase mode, the snapshot moves with `APW_PASSPHRASE` and the same `kdf_salt`.

There is no key rotation command yet. Re-running `apw login` writes a new snapshot but keeps the same snapshot key.
