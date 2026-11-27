# Reference

Commands, files, environment variables, and output formats for the command line.
The terminal interface is the primary front end; its keys and slash commands are
in [Operate](operate.md).

## Commands

Global options apply to every command:

| Option | Effect |
| --- | --- |
| `--json` | Print JSON even on a terminal |
| `--wide` | Do not truncate tables to the terminal width |
| `--no-header` | Omit table headers |

### Account and sync

```sh
apw login [--account EMAIL] [--anisette-url URL] [--refresh] [--join|--no-join]
apw join
apw sync [--force] [--fixture FILE]
apw status
apw install-units
```

`login` signs in and writes the first snapshot. `join` spends one escrow
attempt. `sync` refreshes the snapshot and pushes queued writes. `status` prints
the account, source, counts, last sync, and snapshot path.

### Read

```sh
apw list [QUERY] [--personal] [--group GROUP]
apw get QUERY [--username USER] [--group GROUP] [--personal] [--password-only]
apw wifi [QUERY]
apw notes [QUERY]
apw otp [QUERY]
apw pending
apw trash [QUERY]
```

`get` accepts a login or a Wi-Fi network; an exact match wins over a partial one.
`--password-only` prints one password per match, with no JSON and no labels.
`otp QUERY` prints one code; `otp` without a query lists every code and the
seconds left in the TUI.

### Write

```sh
apw add login URL [--username USER] [--title NAME] [--notes TEXT]
                  [--totp URI] [--password-stdin|--generate] [--dry-run]
apw add wifi SSID [--password-stdin|--generate] [--dry-run]
apw add note TITLE [--body TEXT|--body-stdin] [--dry-run]
apw edit [QUERY] [--id ID] [--title NAME] [--notes TEXT|--clear-notes]
         [--totp URI|--clear-totp] [--password-stdin|--generate] [--dry-run]
apw rm [QUERY] [--id ID] --yes [--dry-run]
apw restore [QUERY] [--id ID] [--dry-run]
apw resolve ID [--local|--remote]
```

`--generate` writes a 20-character password and prints it on stderr.
`--password-stdin` reads one line. An empty `--title` clears the title. `rm`
requires `--yes`; the item moves to Recently Deleted for 30 days.

`resolve --local` clears a blocked pending operation and marks it forced.
`resolve --remote` drops the operation without pushing it. `--local` pushes on
the next sync even inside the floor.

### Groups

```sh
apw group list
apw group show GROUP
apw group add GROUP [QUERY] [--id ID] [--dry-run]
apw group remove GROUP ITEM --yes [--dry-run]
```

`GROUP` accepts a name from the last sync, a `group-` zone name, or a UUID.
`group add` moves one personal login into the group and seals it with the group
record key. `group remove` permanently removes a shared item; it does not use
Recently Deleted.

### Passkeys

```sh
apw passkey import FILE [--dry-run]
apw passkey export FILE [--force]
```

`import` reads a Credential Exchange Format 1.0 JSON file; `export` writes one
and refuses to overwrite without `--force`. Import is local and queues creates;
export reads the snapshot only.

## Files

| Path | Contents |
| --- | --- |
| `$XDG_CONFIG_HOME/apw/config.toml` | Anisette URL, account, sync floor, interface preferences |
| `~/.config/apw/sync.env` | Optional environment for the systemd timer, mode 0600 |
| `$XDG_DATA_HOME/apw/snapshot.bin` | Encrypted snapshot |
| `$XDG_DATA_HOME/apw/snapshot.lock` | Per-operation lock file |
| `$XDG_STATE_HOME/apw/state.json` | Last sync, source, counts, failures, retry time |
| `$XDG_STATE_HOME/apw/adi/{macos,windows}.json` | Device identity files, mode 0600 in a mode 0700 directory |
| `$XDG_CONFIG_HOME/apw/config.lock` | Config read-modify-write lock |

The snapshot is written to a mode 0600 temporary file and renamed into place.

## Configuration

```toml
# anisette_url = "http://your-anisette-server:6969"   # optional; native ADI is the default
account = "you@example.com"
kdf_salt = "..."       # written by apw; leave it alone

[sync]
min_interval_seconds = 300
max_backoff_seconds = 21600

[tui]
last_category = "logins"
split = true
show_wordmark = true
```

`[tui].last_category` accepts `logins`, `notes`, `wifi`, `passkeys`, `groups`,
`trash`, or `pending`. `split = true` requests the list/detail split on wide
screens; `split = false` requests the stacked layout. `show_wordmark = false`
hides the dashboard wordmark. Unknown keys are ignored, so an older binary can
read a newer file.

## Environment

| Variable | Use |
| --- | --- |
| `APW_ANISETTE_URL` | Anisette server URL; unset uses the native device identity |
| `APW_PASSPHRASE` | Derive the snapshot key from this passphrase |
| `APW_PASSWORD` | Apple ID password for `login` |
| `APW_2FA_CODE` | Trusted-device code for the device identity |
| `APW_ESCROW_PASSCODE` | Escrow passcode for `join` |
| `APW_FIXTURE` | Fixture file for `sync` |
| `APW_CONFIG_DIR` | Override the config directory |
| `APW_DATA_DIR` | Override the data directory |
| `APW_STATE_DIR` | Override the state directory |
| `APW_DEBUG` | Print PET source diagnostics to stderr |

`APW_ANISETTE_URL` wins over `--anisette-url` and `anisette_url`.

## JSON output

Success:

```json
{"status":0,"data":{}}
```

Failure:

```json
{"status":2,"error":{"code":"usage","message":"a note title is required"}}
```

`data` is an object for status, add, edit, delete, and restore; query commands
return an array, including one match. Error codes are `usage`, `not_found`,
`auth`, `network`, `locked`, `cloudkit`, and `error`.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | General failure |
| 2 | Invalid arguments |
| 3 | No matching record |
| 4 | Authentication required |
| 5 | Network failure |
| 6 | Snapshot locked or cannot decrypt |

When stdout is a pipe, JSON is the default. `--wide`, `--no-header`,
`--password-only`, a bare `apw otp QUERY`, and a terminal keep text output.

## Snapshot format

The snapshot starts with the ASCII header `APWSNAP` and a version byte. The body
is AES-256-GCM over the serialized vault. The key is 32 random bytes, held in
Secret Service or derived from a passphrase with Argon2id at 64 MiB, three
iterations, and one lane.

The vault stores entries, groups, session tokens, the peer, Recently Deleted,
pending operations, sync keys, and group operations. Each entry keeps the
original CloudKit plist payload beside the parsed fields, so a write can
preserve unknown Apple keys.

## Limits

| Limit | Value |
| --- | --- |
| Pending operations | 200 |
| Pending payload | 16 MiB |
| Sync floor | 300 seconds |
| Escrow attempts | About 10 |
| Recently Deleted retention | 30 days |
| Password generator | 20 characters |
| Generated password alphabet | `A-Z a-z 0-9 !@#$%^&*-_=+` |
| TOTP digits | 6, 7, or 8 |
| TOTP default period | 30 seconds |
| TOTP algorithms | SHA-1, SHA-256, SHA-512 |
