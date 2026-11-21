# Reference

Commands, files, configuration, output, and limits.

## Commands

| Command | Does |
| --- | --- |
| `apw login [--anisette-url URL] [--account EMAIL] [--refresh] [--join] [--no-join]` | Sign in. On the first run it joins the trust and syncs. `--refresh` re-reads the service URLs from the stored session. |
| `apw join` | Join the trust again with a new peer. Spends one escrow attempt. |
| `apw sync [--force] [--fixture PATH]` | Refresh the snapshot and push queued changes. |
| `apw status` | Print account, counts, last sync, snapshot path, and size. |
| `apw list [QUERY] [--personal] [--group UUID]` | List logins by name. |
| `apw get QUERY [--username NAME] [--group UUID] [--personal] [--password-only]` | Print every match, including Wi-Fi networks. |
| `apw wifi [QUERY]` | List saved Wi-Fi networks. |
| `apw otp [QUERY]` | List current codes, or print the code for a query. |
| `apw add login URL [--username NAME] [--title TEXT] [--notes TEXT] [--totp URI\|BASE32] [--password-stdin] [--generate] [--dry-run]` | Add a personal login and queue it. |
| `apw add wifi SSID [--password-stdin] [--generate] [--dry-run]` | Add a Wi-Fi network and queue it. |
| `apw add note TITLE [--body TEXT] [--body-stdin] [--dry-run]` | Add a note and queue it. |
| `apw notes [QUERY]` | List notes. |
| `apw edit QUERY [--id UUID] [--title TEXT] [--notes TEXT] [--clear-notes] [--totp URI\|BASE32] [--clear-totp] [--password-stdin] [--generate] [--dry-run]` | Change a login, note or Wi-Fi network and queue the change. |
| `apw rm QUERY [--id UUID] [--yes] [--dry-run]` | Move a login, note or Wi-Fi network to Recently Deleted and queue it. |
| `apw trash [QUERY]` | List Recently Deleted entries from the last sync. |
| `apw restore QUERY \| --id UUID [--dry-run]` | Move a Recently Deleted entry back, title, notes and password included. |
| `apw pending` | List changes that have not been pushed. |
| `apw resolve ID [--local] [--remote]` | Force or drop a blocked change. |
| `apw group list` | List shared groups with owner and member count. |
| `apw group show GROUP` | Show a group and the items in it. |
| `apw group add GROUP [QUERY] [--id UUID] [--dry-run]` | Add a personal login to a group you own. |
| `apw group remove GROUP ITEM [--yes] [--dry-run]` | Remove an item from a group you own. |
| `apw install-units` | Write the systemd user service and timer. |

`--json`, `--wide`, and `--no-header` are global. Tables are the default on a terminal; a pipe or a redirect gets JSON. `--wide` and `--no-header` keep the text form through a pipe.

`QUERY` matches a substring of the name, domain, URL, or username, case-insensitive. `get` prints all matches as labeled blocks, best match first; `--password-only` prints one password per line and always stays text. `otp` with a query prints only the code, so `$(apw otp github.com)` works.

`--id` selects one entry by record id instead of by query.

Hidden `probe` subcommands exist for development. They are not part of the stable interface.

## Writes

`add`, `edit`, and `rm` write the encrypted snapshot and append a pending operation. Nothing goes to Apple until `apw sync`, which pushes the queue after the read and before saving. The sync interval does not hold back a queued change.

A queued change stores the base it was made from. On push, `apw` reads the server record, decrypts it, and compares it with that base. A record that still matches is written with a fresh item key under the same class key. A record that changed elsewhere blocks the operation: the change stays queued with its reason and id. `apw resolve <id> --local` pushes the local copy anyway; `--remote` drops it and keeps the server copy.

Writes cover personal logins, Wi-Fi networks and notes. Cards, shared entries and passkey creation stay read-only.

Logins and notes live in the Passwords zone; Wi-Fi networks live in the WiFi zone and are sealed under its classC key. A login is an item plus password-manager metadata. A note is an empty item plus metadata that carries the title and body. A Wi-Fi entry is one item with the network name in `acct` and `labl` and no metadata. A create or edit writes the item first and the metadata second; a delete removes the metadata first. If the second write fails, the next sync sees the first one already done and writes only the rest.

`rm` re-saves the record with the `-recently-deleted` access group and a fresh modification date. Apple Passwords keeps it in Recently Deleted for 30 days. `apw trash` lists those entries and `apw restore` queues the inverse edit, stripping the marker and refreshing the modification date for the item and its metadata sidecar. A delete queued but not yet pushed is cancelled instead, so the record never leaves the account.

A push that fails for a transient reason stays queued with a retry time: 30 seconds after the first failure, doubling to an hour. After five failures it blocks until `apw resolve`. The queue is capped at 200 operations or 16 MiB of stored payload; `add`, `edit` and `rm` refuse to enqueue past that.

Passwords enter through `--password-stdin` (one line, trailing newline removed), `--generate` (20 characters, printed once), or a prompt that asks twice. There is no `--password` flag. A password edit appends the old value to Apple's password history.

`--totp` accepts an `otpauth://` URI or a bare base32 secret. It is stored in the login's metadata the way Apple stores it: raw secret bytes, algorithm, digits, period, and the original URI when one was given. `--clear-totp` removes the key. A note's body is metadata `notes`; `apw edit` changes it with `--notes` or `--body-stdin`. A Wi-Fi edit accepts only a password, because the SSID is the join key.

Changing a site or username is refused, because the item and its metadata join on both. Delete the entry and add a new login instead.

Groups are read, and their items can be added and removed. `apw` cannot create or delete a group: Apple Passwords renders groups from a local mirror kept by the keychain-sharing daemon, and a group written straight to CloudKit never enters that mirror. Create the group on an Apple device first.

## Files

| Path | Contents |
| --- | --- |
| `$XDG_CONFIG_HOME/apw/config.toml` | Anisette URL, account, KDF salt |
| `$XDG_DATA_HOME/apw/snapshot.bin` | Encrypted snapshot |
| `$XDG_DATA_HOME/apw/snapshot.bin.prev` | Copy of the snapshot before the last replace |
| `$XDG_DATA_HOME/apw/snapshot.lock` | Advisory lock held by write commands |
| `$XDG_STATE_HOME/apw/state.json` | Last sync, source, counts, failures |
| `$XDG_CONFIG_HOME/systemd/user/apw-sync.{service,timer}` | Timer units |

Defaults are `~/.config/apw`, `~/.local/share/apw`, and `~/.local/state/apw`.

## Configuration

```toml
anisette_url = "http://127.0.0.1:6969"
account = "you@example.com"
kdf_salt = "..."          # written on the first passphrase key derivation

[sync]
min_interval_seconds = 300
```

`kdf_salt` is the base64 salt for the Argon2id passphrase key. Leave it alone. Losing it makes a passphrase snapshot unreadable; changing it does the same.

## Environment

| Variable | Effect |
| --- | --- |
| `APW_ANISETTE_URL` | Overrides `anisette_url`. |
| `APW_PASSPHRASE` | Uses the Argon2id key instead of Secret Service. Also the non-interactive passphrase input. |
| `APW_ESCROW_PASSCODE` | Escrow passcode for a non-interactive `login` or `join`. |
| `APW_PASSWORD` | Apple ID password for a non-interactive `login`. |
| `APW_2FA_CODE` | Two-factor code for a non-interactive `login`. |
| `APW_ALLOW_PARTIAL` | Set to `1` to write a snapshot after a partial decrypt. |
| `APW_SKIP_ESCROW_BUDGET` | Set to `1` to join when the escrow attempt count cannot be read. |
| `APW_FIXTURE` | Fixture path when `--fixture` is absent. |
| `APW_CONFIG_DIR` | Replaces `$XDG_CONFIG_HOME/apw`. |
| `APW_DATA_DIR` | Replaces `$XDG_DATA_HOME/apw`. |
| `APW_STATE_DIR` | Replaces `$XDG_STATE_HOME/apw`. |
| `APW_DEBUG` | Prints protocol and sync diagnostics to stderr. Never prints secrets. |

The three directory variables exist for tests and for running from a removable volume.

## JSON output

Every command prints one object. Lists put an array in `data`; single results put an object:

```json
{"status":0,"data":[{"id":"login-example","name":"Example","username":"alice","domain":"example.com","url":"https://example.com","sites":["example.com"]}]}
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
| 6 | Locked: wrong snapshot key, or an undecryptable item |

`error.code` is one of `usage`, `not_found`, `auth`, `network`, `locked`, or `error`.

`list` and `wifi` results carry `id`, `name`, `url`, `username`, `domain`, `sites`, and `title`, `notes`, or `group` when present. `name` is the title Apple Passwords stores for the entry, or an empty string when Apple stored none; a host is never used as a name. `url` is the stored site URL, and `domain` is its host. `get` adds `password`. `otp` results carry `id`, `name`, `username`, `domain`, `source`, and `code`. `sync` adds `partial`.

## Snapshot format

The snapshot is one AES-256-GCM message:

| Field | Size | Contents |
| --- | --- | --- |
| Magic | 8 bytes | `APWSNAP\0` |
| Version | 1 byte | `1` |
| Nonce | 12 bytes | Random per write |
| Ciphertext | rest | JSON vault, authenticated with the header as AAD |

Writes use a unique temporary file, fsync, and rename, with mode `0600`. A reader sees the old snapshot or the new one, never a partial file. Write commands also take an advisory lock on `snapshot.lock`, so a manual sync and the timer do not interleave.

## Vault model

| Field | Contents |
| --- | --- |
| `account` | Apple ID |
| `generated_at` | Snapshot time, RFC 3339 |
| `source` | `fixture` or `icloud` |
| `entries` | Logins, notes, passkey metadata, Wi-Fi networks |
| `groups` | Shared groups |

An entry has `id`, `kind` (`login`, `note`, `passkey`, `card`, `wifi`, `other`), `title`, `url`, `sites`, `username`, `password`, `notes`, `totp`, `passkey`, `group`, and `updated_at`.

A TOTP seed has `secret` (base32), `algorithm` (`SHA1`, `SHA256`, `SHA512`), `digits` (default 6), `period` (default 30), `issuer`, and `account_name`.

## Limits

| Limit | Value |
| --- | --- |
| Sync floor | 300 seconds |
| Escrow attempts | About 10, then the recovery record is destroyed |
| Snapshot key | 32 bytes |
| Argon2id | 64 MiB, 3 iterations, 1 lane |
| HTTP connect timeout | 10 to 15 seconds |
| HTTP request timeout | 30 to 120 seconds |

Apple's iCloud terms prohibit automated access. `apw` stays polite: paced syncs, no automatic retries, one escrow attempt per user action. The contract risk is yours.
