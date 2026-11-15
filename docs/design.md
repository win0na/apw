# Design

## Context

apw 1.x is a Deno CLI for macOS. It launches a private headless Chrome, loads a patched copy of Apple's iCloud Passwords extension, and talks to Apple's macOS-only native messaging host. Linux has no such host, no public iCloud Keychain API, and no Passwords web app. The macOS design cannot be ported.

This page records the decisions behind the Linux port and the protocols it depends on.

## Decision

apw 2.0 is one Rust binary that reads Apple Passwords data from iCloud:

- Live iCloud Keychain access through Apple ID authentication and an Octagon trust join, read-only.
- No Chrome, no Apple extension, no native messaging host, no daemon.
- A local encrypted snapshot serves every query; a systemd user timer refreshes it.
- Logins, notes and titles, TOTP, passkey metadata, and shared groups, including shared-with-me.
- Anisette comes from a server URL. No Apple-owned binary is shipped.

## Architecture

```
apw
├── cli        clap; login, sync, status, pw, otp, install-units
├── commands   one module per command
├── store      AES-256-GCM snapshot; Secret Service or Argon2id key
├── auth       GSA SRP-6a, anisette, 2FA, token exchange
├── wire       protobuf framing and the CloudKit gateway client
├── octagon    P-384 peer, escrow recovery, trust join, TLK shares
├── ckks       zones, records, AES-SIV decryption, item plists
└── pcs        shared groups, PCSShareProtection
```

| Crate | Use |
| --- | --- |
| `clap` | CLI |
| `serde`, `serde_json`, `toml` | Config, state, snapshot, fixtures |
| `aes-gcm`, `argon2`, `keyring` | Snapshot encryption and key storage |
| `sha1`, `sha2`, `hmac`, `data-encoding` | TOTP |
| `tokio`, `reqwest` with rustls | GSA, CloudKit, escrow |
| `p384`, `hkdf`, `pbkdf2` | Peer keys, escrow, SRP |
| `aes-siv`, `plist`, `prost` | CKKS records, item plists, protobuf |

The current build has the CLI, storage, SRP, anisette, GSA, and token exchange. The `wire`, `octagon`, and `ckks` modules arrive with pass 3.

Data flow:

1. `apw login` authenticates, joins the trust circle, recovers the keychain keys, decrypts the items, and writes the snapshot.
2. `apw sync` refreshes the tokens and the snapshot without asking for the password again.
3. `apw pw` and `apw otp` read the snapshot and never touch the network.

## Authentication

The login path follows Apple's device authentication, not the web login.

1. Read the anisette URL from `APW_ANISETTE_URL` or `$XDG_CONFIG_HOME/apw/config.toml`. When both are unset, fail with a message that names the variable and links [Install](install.md#set-up-anisette).
2. GSA SRP-6a over HTTPS to `gsa.apple.com`: 2048-bit group, `g = 2`, `P' = PBKDF2-HMAC-SHA256(SHA-256(password), s, i)`, `x = H(s | H(":" | P'))`. The username is omitted from `x`.
3. Two-factor with a trusted-device code. Security keys are out of scope for v1.
4. Exchange the GrandSlam session for `mmeAuthToken` and `cloudKitToken` through `setup.icloud.com`, then read the CloudKit and escrow endpoints from the account settings.
5. Call `ckAppInit` with HTTP Basic `dsid:mmeAuthToken` for container `com.apple.security.keychain`. The reply carries the per-container `cloudKitUserId`, which is not the DSID.
6. Generate or load the P-384 signing and encryption peer. Public keys are SPKI DER, private keys are X9.63. The permanent info is a `TPPBPeerPermanentInfo` protobuf; the signature is ECDSA-P384-SHA384 over `"TPPB.PeerPermanentInfo" || data`; the peer ID is `SHA256:` plus base64 of SHA-256 over `data || signature`.
7. Recover the trust circle escrow. Escrow SRP uses the DSID as the username and the device passcode or iCloud Security Code as the password. The recovered bottle decrypts to `bottled_peer_entropy`, which HKDF-SHA384 expands into the sponsor's P-384 keys.
8. Fetch the current trust state, sign the new peer's stable and dynamic info, and join with a voucher signed by the recovered sponsor.
9. Fetch the TLK shares for the sponsor and for the new peer, then union them.

The passcode is used once and never stored. Escrow allows about ten attempts before the record is destroyed, so `apw login` makes exactly one attempt per user action. A failure prints the remaining-attempts warning and stops. Nothing retries automatically.

The join must fetch the TLK shares as the recovered sponsor and union them with the new peer's shares. Fetching only the new peer's shares returns a clean, empty keychain.

CloudKit is not the JSON web services API. The `cloudKitToken` authenticates the protobuf gateway at `gateway.icloud.com`, sent as `x-cloudkit-authtoken`. Requests are gzip-compressed protobuf with a varint length prefix; records sync through `ckdatabase/api/client/record/sync` with operation type 213, and Cuttlefish functions through `ckcoderouter/api/client/code/invoke`. A missing zone (48) means the account has no state for it; a bad token (11) or HTTP 401 means re-authentication.

## Data model

CKKS keeps records in per-view private zones, including `Passwords` and `Manatee`.

| Record | Purpose | Decryption |
| --- | --- | --- |
| `tlkshare` | TLK view, wrapped to a peer | SF-ECIES to the peer encryption key |
| `synckey` | Class key | AES-SIV under the TLK |
| `item` | Credential | AES-SIV under the class key |
| `currentitem` | Pointer to the live item | None |

A TLK share wraps a `CuttlefishSerializedKey`. The wrapped key is an NSKeyedArchiver plist with the sender's ephemeral P-384 key, an ECIES ciphertext, and an authentication code. ECDH and an X9.63 KDF produce a 32-byte AES-256-GCM key and a 16-byte IV. The plaintext carries the TLK UUID, zone, class, and key.

Items are plists with `srvr` (domain), `acct` (username), `v_Data` (password, passkey blob, or card data), and `agrp` (access group):

- `com.apple.cfnetwork`: web logins.
- `com.apple.password-manager`: per-login metadata, including `customTitle`, notes, password history, and the `totp` seed (`secret`, `algorithm`, `digits`, `period`, `issuer`, `accountName`).
- `com.apple.webkit.webauthn`: passkeys.
- `com.apple.safari.credit-cards` and other groups: decrypted and counted, not surfaced in v1.

Item decryption authenticates the record metadata in lexicographic key order, without the key names. The ciphertext is padded in 20-byte blocks with an ISO 7816-4 marker, and the payload carries its own 16-byte IV.

Shared groups live in the `com.apple.security.shared.keychain` container, one zone per group named `group-<UUID>`. They are PCS-encrypted with `PCSShareProtection`: AES key wrap, an SP800-108 KDF, and AES-128-GCM v3.

Shared-with-me groups need share keys from the invite. `apw sync` accepts pending invites before reading the zone and reports per-group errors instead of failing the whole sync.

## Storage

| Path | Contents |
| --- | --- |
| `$XDG_CONFIG_HOME/apw/config.toml` | Anisette URL, account, KDF salt, sync settings |
| `$XDG_DATA_HOME/apw/snapshot.bin` | Encrypted snapshot |
| `$XDG_STATE_HOME/apw/state.json` | Last sync, source, counts |

The snapshot is a JSON vault sealed with AES-256-GCM. The file is `APWSNAP\0`, a version byte, a random 12-byte nonce, and the ciphertext; the header is the AAD. The key is 32 random bytes in Secret Service, or an Argon2id key derived from a passphrase.

Writes go to a temporary file, fsync, then rename, with mode `0600`. Tokens, peer keys, and TLK shares live inside the snapshot, so one secret protects everything.

## CLI

```
apw login [--anisette-url URL] [--account EMAIL]
apw sync [--force] [--fixture PATH]
apw status
apw pw list [QUERY]
apw pw get QUERY [--username NAME]
apw otp list [QUERY]
apw otp get QUERY
apw install-units
```

Every command accepts `--json`. Output keeps the apw contract: `{"results": [...], "status": 0}` on success and `{"error": "...", "status": N, "results": []}` on failure, with the same status numbers.

Read-only means `pw save` does not exist. The help text says so, and an unknown `pw save` names the read-only build.

## Sync and rate limits

`apw sync` refreshes `cloudKitToken` from `mmeAuthToken`. On 401 it records the failure and stops; it never retries the password.

Syncs are at least five minutes apart. Errors back off exponentially to six hours, and `Retry-After` wins over the local schedule. The systemd timer fires hourly and the binary enforces the floor, so a suspended laptop catches up on the next tick.

## Validation

There are no live Apple credentials in the development environment, and escrow attempts are destructive. Crypto is validated offline:

- Unit vectors: RFC 5297 (AES-SIV), RFC 6238 (TOTP), RFC 5054 (SRP), HKDF-SHA384, and vectors from the prior-art projects below.
- Integration: recorded, sanitized CloudKit and anisette fixtures behind a mock gateway.
- Live gate: one `apw login`, then `apw sync`, `apw pw list`, and `apw otp get` on the user's own account.

The escrow SRP padding rule is the one unresolved vector: implementations disagree on whether `u` hashes padded or trimmed public values. The padded form follows RFC 5054 and is the default; a live attempt should not run until the vectors agree.

## Packaging

- Static x86_64 and aarch64 binaries with SHA-256 sums.
- `apw-sync.service` and `apw-sync.timer` written by `apw install-units`.
- AUR `PKGBUILD`, a Debian package from `cargo-deb`, and a Nix flake.
- CI builds both architectures on a tag and runs the fixture suite.

## Alternatives

- Keeping Deno would keep the CLI but force hand-written AES-SIV, ECIES, and protobuf in TypeScript. Against a ten-attempt escrow limit, reusing Rust crypto is worth the rewrite.
- A daemon would preserve the socket but add lifecycle, protocol versioning, and a long-lived decrypted vault in memory, with no read-only benefit.
- A local vault with CSV import would ship sooner but would not be a port of Apple Passwords.

## Risks

- Two undocumented protocols to maintain (GSA, Octagon/CKKS). Apple can change them without notice.
- The CloudKit gateway is internal. Its request framing and error codes can change without notice.
- An anisette server is a hard prerequisite for login.
- Read-only v1: no save, no passkey assertion.
- Shared-with-me depends on invite acceptance and share-key delivery. It is the least proven part of the plan.
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

## Passes

1. Skeleton: Rust crate, CLI, XDG paths, encrypted snapshot, Secret Service and passphrase unlock, fixture backend, `pw` and `otp` end to end.
2. Auth: GSA SRP, anisette, 2FA, token exchange.
3. Octagon and CKKS: protobuf gateway, peer keys, escrow, join, TLK recovery, records, decryption.
4. Shared groups: PCS, invite acceptance, passkey and note surfacing.
5. Sync timer, packaging, live gate.
