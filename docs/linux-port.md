# apw on Linux

## Context

apw is a CLI for Apple Passwords, written in Deno for macOS. It works by launching a private headless Chrome with a patched copy of Apple's iCloud Passwords extension, which talks to Apple's macOS-only native messaging host. Linux has no Apple host, no public iCloud Keychain API, and no Passwords web app, so the macOS design cannot be ported as-is.

This document records the decisions from the research and interview, and the implementation plan that follows from them.

## Decision

We rewrite apw as a single Rust binary that reads Apple Passwords data directly from iCloud:

- Live iCloud Keychain (CKKS) access through Apple ID authentication and an Octagon trust join, read-only.
- No Chrome, no Apple extension, no native messaging host.
- A local encrypted snapshot serves all queries; a systemd user timer refreshes it.
- Everything read-only: logins, notes and titles, TOTP, passkey metadata, and shared groups including shared-with-me.
- Anisette is supplied by a server URL; nothing Apple-owned is shipped.

## Architecture

```
apw (single binary)
├── cli        clap; login, sync, status, pw, otp, install-units
├── store      encrypted snapshot, key from Secret Service or passphrase
├── auth       GSA SRP-6a, anisette, 2FA, trust, accountLogin
├── octagon    peer keys, trust join, escrow recovery, bottles, TLK
├── ckks       CloudKit CKCode, zones, records, AES-SIV decryption
└── pcs        shared groups, PCSShareProtection
```

Crates: `clap`, `tokio`, `serde`, `reqwest` with rustls, `p384`, `aes-siv`, `aes-gcm`, `hkdf`, `sha2`, `pbkdf2`, `prost`, `plist`, `secrecy`, `zeroize`, `keyring`, `argon2`, `rusqlite`.

Data flow:

1. `apw login` authenticates, joins the trust circle, recovers the keychain keys, decrypts the items, and writes the snapshot.
2. `apw sync` refreshes tokens and the snapshot without asking for the password again.
3. `apw pw` and `apw otp` read the snapshot and never touch the network.

## Authentication

The login path follows Apple's device authentication, not the web login:

1. Read the anisette URL from `$XDG_CONFIG_HOME/apw/config.toml` or `APW_ANISETTE_URL`. When it is unset, fail with a message that names the variable and links to the setup section.
2. GSA SRP-6a over HTTPS to `gsa.apple.com`: 2048-bit group, `g = 2`, `P' = PBKDF2-HMAC-SHA256(SHA-256(password), s, i)`, `x = H(s | H(":" | P'))` with the username omitted from `x`.
3. Two-factor: trusted-device code in v1; security keys later.
4. Exchange the GrandSlam session for `mmeAuthToken` and `cloudKitToken` through `setup.icloud.com`.
5. Generate or load a P-384 signing and encryption peer, then join Octagon through CloudKit `CKCode` calls (`joinWithVoucher`, `fetchViableBottles`, `fetchRecoverableTLKShares`).
6. Recover the trust circle with escrow, using the device passcode or iCloud Security Code.

The passcode is used once and never stored. Escrow allows about ten attempts before the record is destroyed, so `apw login` makes exactly one attempt per user action. On failure it prints the remaining-attempts warning and stops. Nothing retries automatically.

After the join, fetch TLK shares as the recovered sponsor and union them with the shares for the new peer. Fetching only the new peer's shares returns a clean, empty keychain.

## Data model

CKKS stores records in per-view private zones (`Passwords`, `Manatee`, and others):

| Record | Purpose | Decryption |
|---|---|---|
| `tlkshare` | TLK for a view, wrapped to a peer | SF-ECIES to the peer encryption key |
| `synckey` | class key | AES-SIV under the TLK |
| `item` | a credential | AES-SIV under the class key |
| `currentitem` | pointer to the live item | none |

Items are plists with `srvr` (domain), `acct` (username), `v_Data` (password, passkey blob, or card data), and `agrp`:

- `com.apple.cfnetwork`: web logins.
- `com.apple.password-manager`: per-login metadata, including `customTitle`, `notes`, password history, and the `totp` seed (`secret`, `algorithm`, `digits`, `period`, `issuer`, `accountName`).
- `com.apple.webkit.webauthn`: passkeys.
- `com.apple.safari.credit-cards` and other groups: decrypted and counted, not surfaced in v1.

Shared groups live in a separate container, `com.apple.security.shared.keychain`, zone `group-<UUID>`. They are PCS-encrypted with `PCSShareProtection`: AES key wrap, an SP800-108 KDF, and AES-128-GCM v3. Shared-with-me groups need the share keys from the invite; `apw sync` accepts pending invites before reading the zone and reports per-group errors instead of failing the whole sync.

## Storage

Paths:

| Path | Contents |
|---|---|
| `$XDG_CONFIG_HOME/apw/config.toml` | anisette URL, account hint, sync settings |
| `$XDG_DATA_HOME/apw/snapshot.bin` | encrypted snapshot |
| `$XDG_STATE_HOME/apw/state.json` | last sync, backoff, token expiry |
| `$XDG_RUNTIME_DIR/apw/lock` | sync lock |

The snapshot is a serialized, compressed image of the decrypted vault. It is encrypted with AES-256-GCM under a random 256-bit key stored in Secret Service (`service=apw`, `account=snapshot-key`). Without a session bus, the key is derived with Argon2id from a passphrase and the snapshot is unlocked per command, or cached by `systemd-ask-password` when started from the timer. Tokens and peer keys live inside the snapshot, so there is one secret to protect.

Snapshot writes are atomic: write to `snapshot.bin.tmp`, fsync, rename. The sync lock prevents two writers.

## CLI

```
apw login [--anisette-url URL]
apw sync [--force]
apw status [--json]
apw pw list <url> [--json]
apw pw get <url> [username] [--json]
apw otp list <url> [--json]
apw otp get <url> [--json]
apw install-units
```

Output keeps apw's JSON contract: `{"results": [...], "status": 0}` on success and `{"error": "...", "status": N, "results": []}` on failure, with the same status codes. `--json` is accepted on every query command; tables are the default on a TTY.

Read-only means `pw save` does not exist. `apw --help` says so, and the error for an unknown `pw save` names the read-only build.

## Sync and rate limits

`apw sync` refreshes `cloudKitToken` from `mmeAuthToken`. On 401 it records `needs_login` and stops; it never retries the password. Syncs are at least 5 minutes apart, back off exponentially to 6 hours on errors, and honor `Retry-After`. The systemd timer fires hourly and the binary enforces the floor, so a laptop that was asleep catches up on the next tick.

## Validation

No live Apple credentials exist in the development environment, and escrow attempts are destructive, so the crypto is validated offline:

- Unit vectors: RFC 5297 (AES-SIV), RFC 6238 (TOTP), RFC 5054 (SRP), HKDF-SHA384, and the prior-art test suites from `Sank6/iCloud-Keychain-for-Linux` (MIT) and `euank/icloud-safari-rs` (Apache-2.0).
- Integration: recorded, sanitized CloudKit and anisette fixtures behind a mock HTTP server.
- Live gate: the user runs one `apw login`, then `apw sync`, `apw pw list`, and `apw otp get` on their own account.

## Packaging

- Static `x86_64` and `aarch64` binaries, tarball with SHA256 sums.
- `apw-sync.service` and `apw-sync.timer` under `~/.config/systemd/user/`, installed by `apw install-units`.
- AUR `PKGBUILD`, Debian package via `cargo-deb`, and a Nix flake in v1.
- CI builds both architectures on every tag and runs the fixture suite.

## Why not the alternatives

- Deno kept the CLI but forced hand-written AES-SIV, ECIES, and protobuf in TypeScript. Against a ten-attempt escrow limit, reusing battle-tested Rust crypto is worth the rewrite.
- A daemon preserved apw's socket but added lifecycle, protocol versioning, and a long-lived decrypted vault in memory, for no read-only benefit.
- A local vault with CSV import shipped faster but was not a port of Apple Passwords.

## Consequences and risks

- Two undocumented protocols to maintain (GSA, Octagon/CKKS). Apple can change them without notice.
- An anisette server is a hard prerequisite for login.
- Read-only v1: no save, no passkey assertion.
- Shared-with-me groups depend on invite acceptance and share-key delivery; that path is the least proven part of the plan.
- Apple's iCloud terms prohibit automated access. This is a contract risk the user accepts, and the client stays polite: paced syncs, no retries, one login attempt per action.

## Passes

1. Skeleton: Rust workspace, CLI, XDG paths, encrypted snapshot, Secret Service and passphrase unlock, fixture backend, `pw` and `otp` end to end.
2. Auth: GSA SRP, anisette, 2FA, trust, accountLogin, token refresh.
3. Octagon and CKKS read: peer keys, join, escrow, TLK recovery, records, decryption.
4. Shared groups: PCS, invite acceptance, passkey and note surfacing.
5. Sync timer, packaging, live gate.
