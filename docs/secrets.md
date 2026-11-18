# Secrets

`apw` keeps one secret: the key that opens the snapshot. Everything else lives inside it.

## Snapshot key

The snapshot is encrypted with a random 256-bit key. The key comes from one of two places:

| Source | When | How |
| --- | --- | --- |
| Secret Service | A session bus and a provider are available | Entry `service=apw`, `account=snapshot-key`, with a keyutils cache |
| Passphrase | No usable Secret Service, or `APW_PASSPHRASE` is set | Argon2id, 64 MiB, 3 iterations, 1 lane |

On first write the key is created in Secret Service. A read never creates a key, so a missing entry cannot produce a key that fails to open an existing snapshot.

The passphrase is not written to disk by `apw`. Its 16-byte salt is `kdf_salt` in `config.toml`, and the derived key exists only in memory. A timer that uses `APW_PASSPHRASE` reads the value from wherever you put it; `sync.env` is one option, and it protects nothing beyond file permissions.

`APW_PASSPHRASE` forces the passphrase path. Without the variable and without a usable Secret Service, `apw` prompts on the terminal.

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

The device passcode or iCloud Security Code unlocks the keychain keys once, during `apw login` or `apw join`. `apw` does not store it, cache it, or send it anywhere except the escrow request. It is never used as the snapshot passphrase.

Apple allows about ten attempts before the recovery record is destroyed. Each join makes one attempt. It does not retry on failure and does not loop. A wrong code ends the command.

## Anisette

The anisette server holds a device identity that Apple ties to the account. It does not see the Apple ID password or the keychain, but a hostile server can impersonate the device. Self-host it or use a host you trust.

## Threat model

| Adversary | Protected | Why |
| --- | --- | --- |
| Disk theft, key in Secret Service | Yes | The snapshot is AES-256-GCM, and the key is in the login keyring, not the snapshot file. |
| Disk theft, passphrase stored beside the snapshot | No | A `sync.env` or shell file with `APW_PASSPHRASE` gives the thief both halves. |
| Another local user | Yes | Keyring entries are per user, and the snapshot and state files are mode `0600`. |
| A process running as you | No | It can read the keyring and the snapshot. |
| Root | No | It can read process memory and the keyring. |
| Network, or Apple | No | Apple holds the account and the server-side data; TLS protects transit only. |

Advanced Data Protection changes what Apple can read on its side. `apw` has not been tested against an ADP account.

## Recovery

A lost key means a lost snapshot. Delete `snapshot.bin` and sign in again. Escrow attempts apply to the new login.

If an entry from an older release holds the wrong key, `apw` prompts for the snapshot passphrase and opens the file. A readable entry is never overwritten, because it may belong to another snapshot; clear the stale one once and the next passphrase unlock caches the derived key:

```sh
secret-tool clear service apw account snapshot-key
```

In Secret Service mode the key is not portable. Copying `snapshot.bin` to another machine does not make it readable. In passphrase mode, the snapshot moves with `APW_PASSPHRASE` and the same `kdf_salt`.

There is no key rotation command. Re-running `apw login` writes a new snapshot but keeps the same snapshot key.
