# Design

## Context

apw 1.x was a Deno CLI for macOS. It launched a private headless Chrome, loaded a patched copy of Apple's iCloud Passwords extension, and talked to Apple's macOS-only native messaging host. Linux has no such host, no public iCloud Keychain API, and no Passwords web app. That design cannot be ported.

This page records the decisions behind the Linux rewrite and the protocols it depends on.

## Decision

apw 2.0 is one Rust binary that reads Apple Passwords data from iCloud:

- Live iCloud Keychain access through Apple ID authentication and an Octagon trust join. Reads and writes use the same CloudKit gateway; writes cover personal logins, Wi-Fi networks and notes.
- No Chrome, no Apple extension, no native messaging host, no daemon.
- A local encrypted snapshot serves every query; a systemd user timer refreshes it.
- Logins, notes and titles, TOTP, passkey metadata, and shared groups, including shared-with-me.
- Group items can be added and removed. Group creation is out of scope: the client renders groups from the local keychain-sharing mirror, which raw CloudKit writes do not reach.
- Anisette comes from a server URL. No Apple-owned binary is shipped.

## Architecture

```
apw
├── cli        clap; login, join, sync, status, list, get, wifi, otp, add, edit, rm, pending, resolve, install-units
├── commands   one module per command
├── store      AES-256-GCM snapshot; Secret Service key with keyutils cache, or Argon2id
├── auth       GSA SRP-6a, anisette, 2FA, token exchange
├── wire       protobuf framing and the CloudKit gateway client
├── octagon    P-384 peer, escrow recovery, trust join, TLK shares
├── ckks       zones, records, AES-SIV decryption and sealing, item plists
├── push       queued writes, conflict checks, CloudKit save and delete
├── pcs        shared groups, PCSShareProtection
└── groups     shared keychain zones and entry mapping
```

The crypto uses `aes-gcm` and `argon2` for the snapshot, `p384`, `hkdf`, and `pbkdf2` for peers, escrow, and SRP, `aes-siv`, `plist`, and `prost` for CKKS records, and `reqwest` with rustls for the network paths.

Data flow:

1. `apw login` authenticates, joins the trust circle, recovers the keychain keys, decrypts the items, and writes the snapshot.
2. `apw sync` refreshes the tokens and the snapshot without asking for the password again.
3. `list`, `get`, `wifi`, and `otp` read the snapshot and never touch the network.

## Authentication

The login path follows Apple's device authentication, not the web login.

1. Read the anisette URL from `APW_ANISETTE_URL` or `config.toml`. When both are unset, fail with a message that names the variable.
2. GSA SRP-6a over HTTPS to `gsa.apple.com`: 2048-bit group, `g = 2`, `P' = PBKDF2-HMAC-SHA256(SHA-256(password), s, i)`, `x = H(s | H(":" | P'))`. The username is omitted from `x`.
3. Two-factor with a trusted-device code. Security keys are out of scope.
4. Exchange the GrandSlam session for `mmeAuthToken` and `cloudKitToken` through `setup.icloud.com`, then read the CloudKit and escrow endpoints from the account settings.
5. Call `ckAppInit` with HTTP Basic `dsid:mmeAuthToken` for container `com.apple.security.keychain`. The reply carries the per-container `cloudKitUserId`, which is not the DSID.
6. Generate or load the P-384 peer. Public keys are SPKI DER, private keys are X9.63. The peer ID is `SHA256:` plus base64 of SHA-256 over the permanent info and its ECDSA-P384-SHA384 signature.
7. Recover the trust circle escrow. Escrow SRP uses the DSID as the username and the device passcode as the password. The recovered bottle decrypts to `bottled_peer_entropy`, which HKDF-SHA384 expands into the sponsor's P-384 keys.
8. Fetch the trust state, sign the new peer's stable and dynamic info, and join with a voucher signed by the sponsor. Verify that the returned trust contains the new peer.
9. Fetch the TLK shares for the sponsor and the new peer, then union them.

The escrow passcode is used once and never stored. A join makes exactly one attempt per user action. The attempt count is read before recovery; if it cannot be read, the join stops unless `APW_SKIP_ESCROW_BUDGET=1`. Nothing retries automatically.

CloudKit is not the JSON web services API. The `cloudKitToken` authenticates the protobuf gateway at `gateway.icloud.com`, sent as `x-cloudkit-authtoken`. Requests are gzip-compressed protobuf with a varint length prefix; records sync through `ckdatabase/api/client/record/sync` with operation type 213, and Cuttlefish functions through `ckcoderouter/api/client/code/invoke`.

## Data model

CKKS keeps records in per-view private zones. `apw` reads `Passwords` (logins, notes, cards, passkeys), `Manatee` (keys), and `WiFi` (saved networks, which use the generic `apple` access group and store the SSID in `acct`).

| Record | Purpose | Decryption |
| --- | --- | --- |
| `tlkshare` | TLK view, wrapped to a peer | SF-ECIES to the peer encryption key |
| `synckey` | Class key | AES-SIV under the TLK |
| `item` | Credential | AES-SIV under the class key |
| `currentitem` | Pointer to the live item | None |

A TLK share wraps a `CuttlefishSerializedKey` as an NSKeyedArchiver plist with the sender's ephemeral P-384 key, an ECIES ciphertext, and an authentication code. ECDH and an X9.63 KDF produce a 32-byte AES-256-GCM key and a 16-byte IV.

Items are plists with `srvr` (domain), `acct` (username), `v_Data` (password, passkey blob, or card data), and `agrp` (access group):

- `com.apple.cfnetwork`: web logins.
- `com.apple.password-manager`: per-login metadata, including `customTitle`, notes, password history, and the `totp` seed.
- `com.apple.webkit.webauthn`: passkeys.
- `com.apple.safari.credit-cards` and other groups: decrypted and counted, not listed.

Item decryption authenticates the record metadata in lexicographic key order, without the key names. The ciphertext is padded in 20-byte blocks with an ISO 7816-4 marker, and the payload carries its own 16-byte IV.

Shared groups live in the `com.apple.security.shared.keychain` container, one zone per group named `group-<UUID>`. They are PCS-encrypted with `PCSShareProtection`: AES key wrap, an SP800-108 KDF, and AES-128-GCM v3.

Owned and shared-with-me zones use different key chains. An owned zone is opened with the account PCS service key. A shared-with-me zone is opened with the participant protection, then the invited PCS in the share record, then the zone protection. `apw sync` reads both databases and reports a locked group instead of failing the whole sync. It never calls `ShareAccept`.

## Storage

| Path | Contents |
| --- | --- |
| `$XDG_CONFIG_HOME/apw/config.toml` | Anisette URL, account, KDF salt |
| `$XDG_DATA_HOME/apw/snapshot.bin` | Encrypted snapshot |
| `$XDG_STATE_HOME/apw/state.json` | Last sync, source, counts, failures |

The snapshot is a JSON vault sealed with AES-256-GCM. The file is `APWSNAP\0`, a version byte, a random 12-byte nonce, and the ciphertext; the header is the AAD. The key is 32 random bytes in Secret Service, or an Argon2id key derived from a passphrase.

Writes go to a unique temporary file, fsync, then rename, with mode `0600`, and write commands hold an advisory lock. Tokens, peer keys, and TLK shares live inside the snapshot, so one secret protects everything.

## Sync and limits

`apw sync` refreshes `cloudKitToken` from `mmeAuthToken` when CloudKit answers 401, retries once, and stops. It never retries the password.

Syncs are at least five minutes apart; the systemd timer fires hourly and the binary enforces the floor, so a suspended laptop catches up on the next tick. There is no exponential backoff and no `Retry-After` handling.

A sync that cannot decrypt every item keeps the previous snapshot unless `APW_ALLOW_PARTIAL=1`. A shared group that cannot be read keeps its previous entries.

## Validation

There are no live Apple credentials in the development environment, and escrow attempts are destructive. Crypto is validated offline against RFC 5297 (AES-SIV), RFC 6238 (TOTP), RFC 5054 (SRP), HKDF-SHA384, and vectors from the prior-art projects below. Recorded CloudKit and anisette fixtures run behind a mock gateway. A live gate of one `apw login`, `apw sync`, `apw list`, and `apw otp` runs on the user's own account.

## Risks

- Two undocumented protocols to maintain (GSA, Octagon/CKKS). Apple can change them without notice.
- The CloudKit gateway is internal. Its request framing and error codes can change without notice.
- An anisette server is a hard prerequisite for login.
- Writes limited to personal logins, Wi-Fi networks and notes. No card, passkey or shared-item writes, no Recently Deleted.
- Shared-with-me depends on the owner's PCS key delivery in the share record. It is the least proven part of the design and the test account has no shared items.
- Apple's iCloud terms prohibit automated access. The client stays polite: paced syncs, no retries, one login attempt per action. The contract risk is the user's.

## Prior art

| Project | License | Use |
| --- | --- | --- |
| [Sank6/iCloud-Keychain-for-Linux](https://github.com/Sank6/iCloud-Keychain-for-Linux) | MIT | GSA, anisette, Octagon, and CKKS reference; test vectors |
| [euank/icloud-safari-rs](https://github.com/euank/icloud-safari-rs) | Apache-2.0 | Rust protocol reference; CRUD behind a flag |
| [cameroncooper/keychain](https://github.com/cameroncooper/keychain) | MIT | Experimental Rust client |
| [dahlia/coffer](https://github.com/dahlia/coffer) | GPL-3.0 | Authentication only |
| [deej1721/icloud-passwords-linux](https://github.com/deej1721/icloud-passwords-linux) | MIT | Windows VM relay |

The crypto was cross-checked against the first two.
