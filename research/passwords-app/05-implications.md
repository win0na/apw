# 05. What this means for `apw`

The personal read path is done. The missing 89 logins are in shared-group zones.
This file turns the research into an implementation plan. It is deliberately
scoped to the read-only contract: no `ShareAccept`, no `ShareDecline`, no writes
to Apple's keychain or CloudKit.

## 1. The gap in the current code

Today `apw sync` does:

1. `ckAppInit` for `com.apple.security.keychain`.
2. `record/sync` on the `Passwords` and `Manatee` zones in the private database.
3. TLK/class-key unwrap from `fetchRecoverableTLKShares`.
4. Item decryption and the metadata merge.

It never asks CloudKit for a zone list, and it never sets a database scope. That
is why group zones are invisible: they are separate zones, and the shared ones
are in a different database.

## 2. Minimum viable group read

### Step 1: enumerate zones

Add a zone-list call to `src/cloudkit.rs`:

- Private database: `zone/sync` (op 203), scope `PRIVATE`.
- Shared database: `zone/sync` (op 203), scope `SHARED`.
- Keep names starting with `group-`.
- Store the zone owner id from each zone identifier; the shared database needs
  it on every subsequent request.

This is the first new wire operation. It is read-only.

### Step 2: fetch the share record

For each group zone, `record/sync` with the zone id and the right scope. The
response contains the `cloudkit.zoneshare` record and the `item-*` records.

The share record gives:

- `displayName` (PCS-encrypted) for the group name.
- Participants, their handles, permission levels, and state.
- The owner, which distinguishes owned from shared-with-me.

### Step 3: get the zone protection

`zone/retrieve` (op 201) returns `protectionInfo` and `recordProtectionInfo`.
Each is a DER `PCSShareProtection`. Decode it with the PCS key.

### Step 4: find the PCS key

The key is a synced keychain item that `apw` already decrypts:

```
agrp == com.apple.ProtectedCloudStorage
type == 211
vwht == Manatee
labl starts with "PCS com.apple.security.keychain.shared"
```

Select it from the decrypted Manatee items, parse `v_Data` as `PCSPrivateKey`,
and use it to unwrap the zone keyset. This is the only genuinely new crypto in
the project. `00-prior-art.md` §3.4 has the RFC 6637 unwrap and the `meta`
structure; `03-kcsharing.md` §7 has the item shape.

### Step 5: decrypt fields

`payload` and `displayName` are field type 20. The AAD is:

```
<zoneName>-<recordName>-<fieldName>
```

Reuse the existing AEAD code, with the field AAD instead of the item AAD. The
ciphertext header is the v3 layout in `00-prior-art.md` §3.6.

### Step 6: decode the item

`payload` decodes to `KCSharingPBRemoteItem`. For v1:

- `internetPassword` → `Entry` with `domain = server`, `username = account`,
  `password = data`, `notes`, `totp`, and the original `agrp`.
- `privateKey` → passkey entry (metadata only), or skip if the passkey model is
  not ready.

Apply the same metadata-sidecar merge as personal items. The access group in the
proto is the original one, so `com.apple.cfnetwork` items are logins and
`com.apple.password-manager` items are sidecars.

## 3. Model and CLI changes

### Model

Add:

```rust
pub struct Group {
    pub id: String,          // UUID, without the group- prefix
    pub name: Option<String>,
    pub owned: bool,
    pub participants: usize,
    pub zone: String,        // group-<UUID>
}

pub struct Entry {
    // existing fields
    pub group: Option<String>, // group UUID, None for personal
    pub shared: bool,          // true when the zone came from the shared DB
}
```

`Vault` gains `groups: Vec<Group>`. `State` gains `groups` and `shared_entries`.

### CLI

- `pw list` includes group items by default, with a `group` column in text mode
  and a `group` field in JSON.
- `pw list --personal` restricts to personal items; `pw list --group <uuid>`
  restricts to one group.
- `status` reports `groups`, `owned_groups`, `shared_groups`, and the login count
  split between personal and shared.
- New hidden probes for the live bring-up:
  `probe-zones`, `probe-group <uuid>`, `probe-group-items <uuid>`.

Keep the JSON envelope and status codes unchanged. Add fields, do not rename
existing ones.

## 4. Order of work

1. **Probe the account.** List private and shared zones; print every `group-*`
   zone with its owner and record count. No decryption yet. This answers whether
   shared-with-me zones are visible without `ShareAccept`.
2. **Share records.** Fetch `cloudkit.zoneshare`, log its fields and participant
   states. Confirm the record name/type split.
3. **PCS.** Select the key item, parse it, unwrap the zone protection, decrypt
   `displayName`. This is the make-or-break step.
4. **Items.** Decrypt one `payload`, decode the proto, print the fields. Confirm
   the field numbers and the AAD.
5. **Integration.** Add groups to the vault, merge sidecars, update counts and
   CLI output.
6. **Live comparison.** `apw status` should approach 417. Investigate any
   remainder by `agrp` and record type before calling it done.

## 5. Test plan

Offline:

- PCS DER parser: fixture from a recorded `zone/retrieve` response.
- RFC 6637 unwrap: RFC vector plus the fixture key.
- Field AAD: a recorded ciphertext with a known plaintext.
- Proto decode: a recorded `payload` with known account/server.

Live (one run, no writes):

- `probe-zones` lists `group-*` in private and shared.
- `probe-group` prints the share record and participants.
- `probe-group-items` prints the decrypted item count and a sample.
- `sync --force` includes group items; `status` shows the split.
- `pw get <domain>` returns a shared password.

Guard rails:

- No `ShareAccept`, `ShareDecline`, `record/save`, `record/delete`, `zone/create`,
  or `zone/delete` in the client.
- If a zone has no PCS key, skip it and report the group as locked; do not guess.
- If a record schema version is unknown, skip it and count it as opaque.

## 6. Risks

| Risk | Mitigation |
|---|---|
| PCS unwrap is more complex than expected | Implement the RFC 6637 path first against the fixture; fall back to reporting locked groups if it stalls |
| Shared database requires an owner id or a different auth scope | Probe with the owner id from the zone list; log the exact 401/403 |
| The account has no shared-with-me groups | Still ship owned groups; the shared path is exercised by fixtures |
| Record name/type differs from prior art | Log every record name and type on the first live fetch; adapt the filter |
| Group items duplicate personal items | Deduplicate by record id, then by domain plus username |
| Token chain expiry during the work | Keep the session; re-login only once, after the probes are ready |

## 7. Decisions for the interview

The research settles the protocol. The remaining choices are product choices:

1. **Default visibility.** Should `pw list` include shared-group items by
   default, or require `--group`/`--all`?
2. **Scope of v1.** Ship owned groups first and add shared-with-me after the
   live probe, or block v1 on both?
3. **Passkeys in groups.** Include group passkeys in v1, or list them as metadata
   only?
4. **Pending invites.** Show them in `status` and `group list`, or ignore them
   until accepted?
5. **Schema-version policy.** Skip unknown-version records silently, or surface
   them as opaque entries with a warning?
