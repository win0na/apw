# Reference

Commands, files, configuration, output, and limits.

This build signs in, joins the trust, and syncs against a live account. See [Project status](../README.md#project-status).

## Commands

| Command | Does |
| --- | --- |
| `apw login [--anisette-url URL] [--account EMAIL] [--passcode CODE] [--join] [--no-join] [--refresh]` | Sign in. On the first run it joins the trust and syncs; the apw passcode is reused for escrow unless `--passcode` is given. |
| `apw join [--passcode CODE]` | Join the trust again with a new peer. Spends one escrow attempt. |
| `apw sync [--force] [--fixture PATH]` | Refresh the snapshot. |
| `apw status` | Print account, counts, last sync, and snapshot path. |
| `apw list [QUERY] [--personal] [--group UUID]` | List logins by name. |
| `apw get QUERY [--username NAME] [--group UUID] [--personal] [--password-only]` | Print every match, including Wi-Fi networks. |
| `apw wifi [QUERY]` | List saved Wi-Fi networks. |
| `apw otp [QUERY]` | List current codes, or print the code for a query. |
| `apw install-units` | Write the systemd user service and timer. |

`--json`, `--wide`, and `--no-header` are global. Tables are the default on a terminal; a pipe or a redirect gets JSON. `--wide` and `--no-header` keep the text form through a pipe.

`QUERY` matches a substring of the name, domain, URL, or username, case-insensitive. `get` prints all matches as labeled blocks, best match first; `--password-only` prints one password per line and always stays text. `otp` with a query prints just the code, so `$(apw otp github.com)` works.

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

Every command prints one object. Lists put an array in `data`; single results put an object:

```json
{"status":0,"data":[{"id":"login-example","name":"Example","username":"alice","domain":"example.com","sites":["example.com"]}]}
```

Failure goes to stderr, and the process exits with the same status:

```json
{"status":3,"error":{"code":"not_found","message":"no entry matches example.org"}}
```

| Status | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Generic error |
| 2 | Invalid parameter |
| 3 | No results |
| 4 | Not signed in, or the session expired |
| 5 | Network or Apple service failure |
| 6 | Locked: wrong snapshot passcode, or an undecryptable item |

`error.code` is one of `usage`, `not_found`, `auth`, `network`, `locked`, or `error`.

`list` and `wifi` results carry `id`, `name`, `username`, `domain`, `sites`, `title`, `notes`, and `group` when present. `name` is the stored title, or the domain when the title only repeats it. `get` adds `password`. `otp` results carry `id`, `name`, `username`, `domain`, `source`, and `code`.

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
