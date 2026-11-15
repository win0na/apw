# Reference

Commands, files, configuration, output, and limits.

This page describes the 2.0 target. This build signs in, joins the trust, and syncs. None of it has run against a live account yet. See [Project status](../README.md#project-status).

## Commands

| Command | Does |
| --- | --- |
| `apw login [--anisette-url URL] [--account EMAIL]` | Save the anisette URL, sign in, write the first snapshot. |
| `apw join [--passcode CODE]` | Join the Octagon trust. Spends one escrow attempt. |
| `apw sync [--force] [--fixture PATH]` | Refresh the snapshot. |
| `apw status` | Print account, counts, last sync, and snapshot path. |
| `apw pw list [QUERY]` | List logins, filtered by domain, title, or username. |
| `apw pw get QUERY [--username NAME]` | Print the password for the matches. |
| `apw otp list [QUERY]` | List current one-time codes. |
| `apw otp get QUERY` | Print the current one-time code. |
| `apw install-units` | Write the systemd user service and timer. |

`--json` is global and works on every command. Tables are the default on a terminal; a pipe or a redirect gets JSON.

`QUERY` matches a substring of the domain, URL, title, or username, case-insensitive.

## Files

| Path | Contents |
| --- | --- |
| `$XDG_CONFIG_HOME/apw/config.toml` | Anisette URL, account, KDF salt, sync settings |
| `$XDG_DATA_HOME/apw/snapshot.bin` | Encrypted snapshot |
| `$XDG_STATE_HOME/apw/state.json` | Last sync, source, counts |
| `$XDG_CONFIG_HOME/systemd/user/apw-sync.{service,timer}` | Timer units |

Defaults are `~/.config/apw`, `~/.local/share/apw`, and `~/.local/state/apw`.

## Configuration

```toml
anisette_url = "http://127.0.0.1:6969"
account = "you@example.com"
kdf_salt = "..."          # written on the first passphrase unlock

[sync]
min_interval_seconds = 300
max_backoff_seconds = 21600
```

`kdf_salt` is the base64 salt for the Argon2id fallback. Leave it alone. Changing it makes the existing snapshot unreadable.

## Environment

| Variable | Effect |
| --- | --- |
| `APW_ANISETTE_URL` | Overrides `anisette_url`. |
| `APW_PASSPHRASE` | Uses the Argon2id key instead of Secret Service. |
| `APW_FIXTURE` | Fixture path when `--fixture` is absent. |
| `APW_CONFIG_DIR` | Replaces `$XDG_CONFIG_HOME/apw`. |
| `APW_DATA_DIR` | Replaces `$XDG_DATA_HOME/apw`. |
| `APW_STATE_DIR` | Replaces `$XDG_STATE_HOME/apw`. |

The three directory variables exist for tests and for running from a removable volume.

## JSON output

Every command prints one object. Success:

```json
{"results":[{"id":"login-example","username":"alice","domain":"example.com","sites":["example.com"],"title":"Example","password":"hunter2"}],"status":0}
```

Failure goes to stderr, and the process exits with the status code:

```json
{"error":"no login matches example.org","status":3,"results":[]}
```

| Status | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Generic error |
| 2 | Invalid parameter |
| 3 | No results |
| 100 | Server error, reserved |

The codes match the macOS apw build, so scripts that check `status` keep working.

`pw list` results carry `id`, `username`, `domain`, `sites`, `title`, `notes`, and `group` when present. `pw get` adds `password`. `otp` results carry `id`, `username`, `domain`, `source`, and `code`.

## Snapshot format

The snapshot is one AES-256-GCM message:

| Field | Size | Contents |
| --- | --- | --- |
| Magic | 8 bytes | `APWSNAP\0` |
| Version | 1 byte | `1` |
| Nonce | 12 bytes | Random per write |
| Ciphertext | rest | JSON vault, authenticated with the header as AAD |

Writes go to a temporary file, fsync, then rename, with mode `0600`. A reader sees the old snapshot or the new one, never a partial file.

## Vault model

| Field | Contents |
| --- | --- |
| `account` | Apple ID |
| `generated_at` | Snapshot time, RFC 3339 |
| `source` | `fixture` or `icloud` |
| `entries` | Logins, notes, passkey metadata |
| `groups` | Shared groups |

An entry has `id`, `kind` (`login`, `note`, `passkey`, `card`, `wifi`, `other`), `title`, `url`, `sites`, `username`, `password`, `notes`, `totp`, `passkey`, `group`, and `updated_at`.

A TOTP seed has `secret` (base32), `algorithm` (`SHA1`, `SHA256`, `SHA512`), `digits` (default 6), `period` (default 30), `issuer`, and `account_name`.

## Limits

| Limit | Value |
| --- | --- |
| Sync floor | 300 seconds |
| Sync backoff ceiling | 6 hours |
| Escrow attempts | About 10, then the recovery record is destroyed |
| Snapshot key | 32 bytes |
| Argon2id | 64 MiB, 3 iterations, 1 lane |

Apple's iCloud terms prohibit automated access. `apw` stays polite: paced syncs, no automatic retries, one escrow attempt per user action. The contract risk is yours.
