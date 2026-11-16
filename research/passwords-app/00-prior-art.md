# Passwords.app and iCloud Keychain shared groups: prior art

Scope: everything needed to read Apple Passwords entries out of iCloud Keychain from
Linux, including the shared groups that `apw sync` currently misses. Two halves:

- **Artifact side** — getting `Passwords.app` and the security daemons out of the iOS 27
  IPSW (`iPhone17,1`, `27.2.1`, `24B156`) so the binary can be interrogated.
- **Protocol side** — what the KCSharing container, zones, records and PCS protection
  actually look like, and what public code already implements (owned groups) or does
  not implement (shared-with-me).

Evidence markers used throughout:

- **Fact** — observed in Apple open source, in a public implementation, or in tool
  output. Link given.
- **Inference** — follows from facts plus Apple's documented cryptex design; not
  observed on this IPSW.
- **Speculation** — explicitly flagged, needs binary confirmation.

Captured tool versions: `ipsw` v3.1.749 (`BuildCommit a7dfadbcaca8375b424c12a68dae40767e5e07c1`,
Linux amd64 static, `/tmp/opencode/ipsw`), `rustpush` `b3c96c23e1aae78d1229ebaccb12027624f1eaff`,
`Sank6/iCloud-Keychain-for-Linux` `1044fdd093922fa3952807fe43d6b1fb995a3384`,
`einyx/apple-passwords` `867bdbe6cf08bbb051d7fa6597c5c1a2a541c44c`,
`dahlia/coffer` `ce7011940101407529122218a62d9afcbe73d7e9`,
`apple-oss-distributions/Security` main (2026-11 tree).

---

## 1. Where system apps live in iOS 17+ and how to get them out

### 1.1 Layout

| Layer | Path on device | Contents |
|---|---|---|
| Root filesystem (SSV, `.dmg` inside IPSW) | `/System/...` | kernel, base system dylibs, most `/System/Library` content |
| System cryptex (`Cryptex1,SystemOS`) | grafted at `/System/Cryptexes/OS` → visible as `/System` | OS frameworks and the dyld shared cache on newer builds |
| App cryptex (`Cryptex1,AppOS`) | grafted at `/System/Cryptexes/App` | system **applications**, including the ones Apple ships out-of-band with the OS |
| Preboot | `/private/preboot/Cryptexes/{App,OS}` | mount parents for the above ([Apple Wiki](https://theapplewiki.com/wiki/Filesystem:/private/preboot/Cryptexes)) |

**Inference:** on iOS 18+ `Passwords.app` is not on the root filesystem. It is a
system *application*, and system applications that Apple can update independently live
in the App cryptex, so the on-device path is
`/System/Cryptexes/App/System/Applications/Passwords.app`. On macOS the equivalent is
`/System/Volumes/Preboot/Cryptexes/App/System/Applications/Passwords.app`, with
`/System/Applications/Passwords.app` as the visible path. This must be confirmed on
`24B156` with the commands in §1.4 before relying on it; the discovery commands do not
assume the path.

Since iOS 18 the root filesystem *and* the cryptexes ship as AEA-encrypted DMGs
(`*.dmg.aea`) inside the IPSW, so nothing can be read out of the archive without
decrypting AEA first ([Apple Encrypted Archive](https://theapplewiki.com/wiki/Apple_Encrypted_Archive)).

### 1.2 `ipsw` v3.1.749 subcommands

Relevant top-level commands in this build (from `/tmp/opencode/ipsw --help`):

```
info      list IPSW/OTA contents, JSON, DMG key lookup
extract   kernel, dyld, DeviceTree, DMGs, filesystem files, AEA fcs keys
mount     mount app|sys|fs|exc|rdisk|rosetta DMGs
fw aea    parse/decrypt AEA1 DMGs
macho     info, search, class-dump-adjacent analysis
dyld      DSC parse, dylib extract, string search
ent       entitlement search, including directly against an IPSW filesystem
class-dump / swift-dump   ObjC and Swift dumps of a Mach-O or a DSC member
plist     plist → JSON
lsbom     list BOM contents
disk dmg  🚧 list/extract DMG partitions without mounting
ota       OTA payload/cryptex handling (cryptex extraction requires a full OTA)
```

**List the archive** (works on Linux, pure zip):

```sh
/tmp/opencode/ipsw info -l iPhone17,1_27.2.1_24B156_Restore.ipsw | tee ipsw-files.txt
/tmp/opencode/ipsw info --json iPhone17,1_27.2.1_24B156_Restore.ipsw > ipsw-info.json
grep -E '\.dmg|BuildManifest|SystemVersion' ipsw-files.txt
```

**Extract the DMGs.** `--dmg` takes a name, not a flag:

```sh
mkdir -p out
/tmp/opencode/ipsw extract --dmg fs  -o out iPhone17,1_27.2.1_24B156_Restore.ipsw   # root filesystem
/tmp/opencode/ipsw extract --dmg sys -o out iPhone17,1_27.2.1_24B156_Restore.ipsw   # SystemOS cryptex
/tmp/opencode/ipsw extract --dmg app -o out iPhone17,1_27.2.1_24B156_Restore.ipsw   # AppOS cryptex — Passwords.app
/tmp/opencode/ipsw extract --dmg exc -o out iPhone17,1_27.2.1_24B156_Restore.ipsw   # ExclaveOS
```

The published guide still shows the older boolean form (`-m, --dmg`); in 3.1.749 it is
`--dmg <app|sys|fs|exc>`. Trust `ipsw extract --help` on the local binary over the docs.

`--dmg app` is enough to answer "is Passwords.app here" if you then mount or walk the
resulting image. `--fcs-key` dumps the AEA1 keys for the SystemOS/Filesystem DMGs, and
`--pem-db` / `--lookup` (`-l`) supply AEA private keys or DMG keys from
theapplewiki.com.

**AEA.** Two paths exist and both matter for Linux:

```sh
# inspect without keys: header, metadata, archive id
/tmp/opencode/ipsw fw aea -i 043-XXXXXX-XXX.dmg.aea

# decrypt with a key you already have
/tmp/opencode/ipsw fw aea --key-val 'base64:...' 043-XXXXXX-XXX.dmg.aea -o out

# decrypt with an extracted PEM
/tmp/opencode/ipsw fw aea --pem 043-XXXXXX-XXX.dmg.aea.pem 043-XXXXXX-XXX.dmg.aea -o out

# derive the key material for the IPSW's own DMGs
/tmp/opencode/ipsw extract --fcs-key -o out iPhone17,1_27.2.1_24B156_Restore.ipsw
```

`ipsw` historically shelled out to macOS `/usr/bin/aea`; a pure-Go AEA implementation was
added as a fallback in Dec 2025 ([ipsw#999](https://github.com/blacktop/ipsw/issues/999),
"add fallback to pure Go implementation if 'aea' binary …"), so 3.1.749 decrypts AEA on
Linux. Some AEA operations still print `only supported on macOS (due to 'aea' binary
requirement)` — that string is present in this build, so treat *AEA re-encryption* and
`fw aea --encrypt` as macOS-only, decryption as Linux-capable. **Fact** for the fallback
commit, **inference** for which call sites still require the binary.

**Mounting** is the one step that is not self-contained:

```sh
# Linux: needs apfs-fuse on PATH (or IPSW_APFS_FUSE_PATH), plus FUSE access
/tmp/opencode/ipsw mount app iPhone17,1_27.2.1_24B156_Restore.ipsw --mount-point /mnt/app
/tmp/opencode/ipsw mount sys iPhone17,1_27.2.1_24B156_Restore.ipsw --pem-db pem.json
/tmp/opencode/ipsw mount fs  iPhone17,1_27.2.1_24B156_Restore.ipsw --detach
```

The binary searches `/usr/bin/apfs-fuse`, `/usr/local/bin/apfs-fuse`,
`/opt/apfs-fuse/bin/apfs-fuse`, `/home/linuxbrew/.linuxbrew/bin/apfs-fuse` and the snap
path, and errors with `apfs-fuse not found in PATH or common locations … set
IPSW_APFS_FUSE_PATH`. On macOS it uses `hdiutil attach` / `hdiutil detach`. Docker form
documented upstream: `--device /dev/fuse --cap-add=SYS_ADMIN
--security-opt apparmor=unconfined` ([extract guide](https://blacktop.github.io/ipsw/docs/guides/extract)).

**File extraction without a mount:** `extract --files` is the path that avoids you
writing an APFS walker yourself, and `macho search` / `ent --fs` read the DMGs directly:

```sh
/tmp/opencode/ipsw extract --files -p 'Passwords\.app/.*' -o out --flat iPhone17,1_27.2.1_24B156_Restore.ipsw
/tmp/opencode/ipsw macho search iPhone17,1_27.2.1_24B156_Restore.ipsw --class 'KCSharing'
/tmp/opencode/ipsw macho search iPhone17,1_27.2.1_24B156_Restore.ipsw --import 'ProtectedCloudStorage'
/tmp/opencode/ipsw ent --fs iPhone17,1_27.2.1_24B156_Restore.ipsw \
    --has com.apple.private.keychain.kcsharing.client --file-only
```

### 1.3 Linux vs macOS matrix

| Step | Linux | macOS | Notes |
|---|---|---|---|
| `info -l`, `info --json` | yes | yes | zip only |
| `extract --dmg {fs,sys,app,exc}` | yes | yes | AEA via Go fallback (3.1.6xx+) |
| AEA decrypt (`fw aea`, `--pem`, `--key-val`) | yes | yes | `/usr/bin/aea` used when present |
| AEA *encrypt* / re-sign | no | yes | `only supported on macOS` |
| `ent --fs`, `macho search`, `dyld *` on IPSW | yes | yes | own DMG/APFS readers |
| `mount fs/sys/app` | apfs-fuse + FUSE | `hdiutil` | fuse is the only Linux dependency |
| `ota extract --cryptex` | yes | yes | full OTA, not a restore IPSW |
| `disk dmg` / `pkg` | 🚧 | 🚧 | don't build on these |

`extract --files` and `--dmg` internally log `Mounting DMG`; whether they need
apfs-fuse in 3.1.749 was not determinable without the IPSW. Install apfs-fuse before
the first run rather than debugging a half-extracted tree. **Inference**, cheap to
settle.

### 1.4 Recipe: locate `com.apple.Passwords`

```sh
IPSW=iPhone17,1_27.2.1_24B156_Restore.ipsw

# 1. which DMG is which cryptex (BuildManifest keys Cryptex1,AppOS / Cryptex1,SystemOS)
/tmp/opencode/ipsw info --json "$IPSW" | jq -r '.. | objects | to_entries[]?
  | select(.key|test("Cryptex1,(AppOS|SystemOS|AppTrustCache)")) | "\(.key) \(.value)"' | sort -u

# 2. pull the App cryptex, decrypt, mount
/tmp/opencode/ipsw extract --dmg app -o out "$IPSW"
/tmp/opencode/ipsw mount app "$IPSW" --mount-point /mnt/pw

# 3. does the bundle exist, and under which root?
ls -d /mnt/pw/System/Applications/Passwords.app
/mnt/pw/System/Applications/Passwords.app/Passwords 2>/dev/null || true
find /mnt/pw -maxdepth 4 -name 'Passwords.app'

# 4. if the app is not in the App cryptex, fall back to the filesystem image
/tmp/opencode/ipsw extract --files -p 'Passwords\.app' -o out "$IPSW"

# 5. confirm the bundle id, not the directory name
/tmp/opencode/ipsw plist /mnt/pw/System/Applications/Passwords.app/Info.plist \
  | jq '{CFBundleIdentifier, CFBundleExecutable, CFBundleVersion, NSExtension}'
```

`ipsw plist` prints JSON, so `jq` works directly. If the bundle id is not
`com.apple.Passwords`, search by identifier instead of by name:

```sh
/tmp/opencode/ipsw ent --fs "$IPSW" --file 'Passwords' --format jsonl | head
```

---

## 2. `Passwords.app` internals

### 2.1 Confirmed

| Item | Value | Source |
|---|---|---|
| Marketing bundle id | `com.apple.Passwords` | App Store listing `id6473799789`; consistent with Apple's naming for the iOS 18+ app |
| First shipped | iOS 18 / iPadOS 18 / macOS 15 / visionOS 2 (Sept 2024) | [Apple support 120758](https://support.apple.com/en-us/120758) |
| Backing store | iCloud Keychain (`Manatee` view for local items, `Passwords` zone for synced logins) | existing `apw` behaviour, §3 |
| Group sharing backend | CloudKit container `com.apple.security.shared.keychain`, XPC service `com.apple.security.kcsharing` | `Security/keychain/securityd/KCSharingStubXPCListenerDelegate.m`, rustpush `src/passwords.rs:65` |
| Documented API surface | AuthenticationServices (`ASCredentialProviderViewController`), Security/SecItem, CloudKit, CryptoKit | [Password AutoFill](https://developer.apple.com/documentation/security/password-autofill) |
| Known non-public entitlement on the app | `com.apple.authentication-services.access-credential-identities` (bool) | Apple Developer Forums report, community-verified only — treat as lead, not fact |
| System AutoFill UI service | `AutoFillPanelService` (macOS) | same forum thread |

### 2.2 Expected, to be confirmed on `24B156`

**Inference / speculation, ordered by confidence:**

1. `Passwords.app/PlugIns/` contains at least one `.appex`: an AutoFill credential
   provider (AuthenticationServices) and, on iOS, an intents/widget extension. Name
   unknown; enumerate rather than guess (§2.3).
2. The app links `AuthenticationServices`, `Security`, `CloudKit`, `CryptoKit`,
   `LocalAuthentication`, and the private framework `/System/Library/PrivateFrameworks/ProtectedCloudStorage.framework`
   (the PCS key hierarchy is only exposed there; rustpush's `src/icloud/pcs.rs` is a
   reimplementation of that interface).
3. Group UI state (names, participants, pending invites) lives in a Swift/ObjC layer
   over `KCSharingGroupManager` (`base/Security_Private.h:135-145`), not in the
   Passwords app itself.
4. Keychain items for groups are not written by `Passwords.app`; `securityd` and
   `keychainsharingmessagingd` own them. The app talks to
   `com.apple.security.kcsharing`.

### 2.3 Where the symbols are

Swift and ObjC land in different sections of the same Mach-O:

| What | Section / load command | Dump with |
|---|---|---|
| ObjC classes, protocols, categories | `__TEXT.__objc_classlist`, `__objc_protolist`, `__objc_catlist` (+ `__objc_opt_*` on iOS 18+) | `ipsw macho info <bin> -o`, `ipsw class-dump <bin>` |
| Swift types, demangled names | `__TEXT.__swift5_types`, `__swift5_proto`, `__swift5_fieldmd`, `__swift5_mpenum`, `__swift5_entry` | `ipsw macho info <bin> -w` / `--swift-all`, `ipsw swift-dump` (🚧 in 3.1.749) |
| Strings (error text, XPC names, zone names) | `__TEXT.__cstring`, `__TEXT.__oslogstring` | `ipsw macho info <bin> -c` |
| Entitlements | code signature blob | `ipsw macho info <bin> -e` (and `--ent-der`) |
| Linked dylibs and versions | `LC_LOAD_DYLIB` | `ipsw macho info <bin> -l` |
| Imports (who calls `PCSShareProtection` etc.) | bind opcodes | `ipsw macho info <bin> -n`, `ipsw macho search --import` |

Framework symbols are **not** in the app binary; the app imports them. To read the
actual PCS/KCSharing implementations, extract the dylibs from the dyld shared cache:

```sh
/tmp/opencode/ipsw extract --dyld --dyld-arch arm64e -o dsc "$IPSW"
/tmp/opencode/ipsw dyld extract dsc/dyld_shared_cache_arm64e \
    /System/Library/PrivateFrameworks/ProtectedCloudStorage.framework/ProtectedCloudStorage \
    --objc --stubs -o dsc/lib
/tmp/opencode/ipsw dyld extract dsc/dyld_shared_cache_arm64e \
    /usr/lib/libsecurityd_client.dylib --objc -o dsc/lib       # KCSharing* client classes
/tmp/opencode/ipsw dyld str dsc/dyld_shared_cache_arm64e \
    "com.apple.security.kcsharing" "com.apple.security.shared.keychain" \
    "cloudkit.zoneshare" "groupaccesskeys"
```

`dyld str` is a plain byte search over the cache, so it finds the strings regardless of
which image owns them — the fastest way to prove a string exists on this build.

---

## 3. The KCSharing protocol (shared password groups)

### 3.1 Five different names for five different things

These are constantly conflated in writeups. Keeping them apart is the whole game:

| Namespace | Value | Where it appears |
|---|---|---|
| CloudKit container | `com.apple.security.shared.keychain` | `x-cloudkit-containerid` header; `SHARED_PASSWORDS_CONTAINER` in rustpush `src/passwords.rs:65` |
| CloudKit "bundle" / service id | `com.apple.security.kcsharing` | `x-cloudkit-bundleid`; mach service `com.apple.security.kcsharing` (`KCSharingStubXPCListenerDelegate.m:29`) |
| Keychain **access group** (PCS keys) | `com.apple.ProtectedCloudStorage` | `agrp` on PCS key items, `securityd/entitlements.plist` |
| Keychain/PCS **service name** | `com.apple.security.keychain.shared` | `com.apple.private.cloudkit.serviceNameForContainerMap` in `keychain/securityd/entitlements.plist:13-16`; rustpush `SHARED_PASSWORDS_SERVICE.name` (`src/passwords.rs:73`) |
| Zone (one per group) | `group-<UUID>` | zone name; `create_group` uses `format!("group-{group}")` with an uppercase UUID (`src/passwords.rs:1407`) |

The `securityd` entitlement map is the authoritative link between the container and the
service name:

```xml
<key>com.apple.private.cloudkit.serviceNameForContainerMap</key>
<dict>
    <key>com.apple.security.shared.keychain</key>
    <string>com.apple.security.keychain.shared</string>
</dict>
```

So "shared group access group" in Apple's own terms is `com.apple.security.keychain.shared`,
not `group-<UUID>`; `group-<UUID>` is a CloudKit zone. **Fact.**

### 3.2 Zones and databases

- Groups you **own**: one zone `group-<UUID>` in the **private** database of the sharing
  container.
- Groups **shared with you**: the same zone name, in the **shared** database, owned by
  the inviter's CloudKit user id.

rustpush enumerates both by running the same zone-changes sync against the private and
the shared container and splitting on owner (`src/passwords.rs:1235-1305`):

```rust
let is_shared = i.id.owner_identifier.as_ref().unwrap().name() != &container.user_id;
let is_db_shared = container.database_type == Database::SharedDb;
is_shared == is_db_shared
```

and `sync_zones` sets `this_group.is_owner = container.database_type != Database::SharedDb;`
(`src/passwords.rs:1340`). Filter for `identifier.starts_with("group-")` and drop
`change_type == 2` (deleted).

Operations are CloudKit HTTP protobuf, not CKSyncEngine:

| Purpose | Endpoint | Op | Notes |
|---|---|---|---|
| List changed zones | `gateway.icloud.com/ckdatabase/api/client/zone/sync` | 203 (RetrieveZoneChanges) | per database scope |
| Get one zone + its protection | `.../api/client/zone/retrieve` | 201 (ZoneRetrieve) | `ZoneRetrieveRequest{zoneIdentifier=1}` |
| Get records in a zone | `.../api/client/record/sync` | 213 (RecordRetrieveChanges) | paged, `max_changes=500` |
| Resolve invite URL | CloudKit `ResolveToken` | — | only needed to accept |
| Accept | CloudKit `ShareAccept` | — | write, see §3.7 |

Header requirement: `x-cloudkit-databasescope: SHARED` (uppercase) for the shared
database; `PRIVATE` otherwise. The zone identifier carries an `ownerIdentifier`; the
shared database rejects a request without it.

### 3.3 Records inside a group zone

| Record | Type | Fields | Meaning |
|---|---|---|---|
| `item-<UUID>` | `item` | `payload` (encrypted bytes), `type` (int) | a shared credential; `payload` is a `SharingItem` protobuf (§3.6) |
| `cloudkit.zoneshare` | `cloudkit.share` | `displayName` (encrypted), share info (participants, public keys, URL) | the zone-wide share; record **name** is `cloudkit.zoneshare`, record **type** is `cloudkit.share` |

The name/type split is the reason the public implementations disagree: rustpush matches
on the identifier `identifier == "cloudkit.zoneshare"` (`src/passwords.rs:1311`, `1365`),
while Sank6 and einyx match on `record_type == "cloudkit.share"`
(`icp/sharing/groups.py` `_parse_record`, `crates/icp-core/src/groups.rs:218`). Both are
right about different axes. Read the group name by decrypting `displayName` with the
zone's record keys and taking `EncryptedValue.stringValue` (field 6).

**Ownership metadata does not live in the item records.** Membership is in the
`cloudkit.share` share info: `participants[]` with `user_id`, `public_key`
(a `ProtectionInfo`), `participant_id`, `public_key_version`, `state` (3 = accepted),
`contact_information{email_address, phone_number}`. rustpush filters removed
participants with `if participant.state() != 3 { continue }`
(`src/passwords.rs:1366-1376`).

### 3.4 Zone protection: `PCSShareProtection`

Zone retrieve returns `zone.protectionInfo(3)` and `zone.recordProtectionInfo(6)`, each
a `ProtectionInfo{ protectionInfo=1: bytes, protectionInfoTag=2 }`. The bytes are DER,
`[APPLICATION 1] SEQUENCE` (rustpush `src/icloud/pcs.rs:566-580`):

```
PCSShareProtection ::= [APPLICATION 1] SEQUENCE {
  keyset:            { INTEGER, SET OF { keytype(3), OCTET pubKey }, OCTET wrapped, INTEGER flags OPTIONAL },   -- "PCSKeySet"
  [0] meta:          OCTET STRING,           -- encrypted; holds zone identity keys
  [1] signatureData: SEQUENCE { version: INTEGER, data: OCTET STRING },
  hmac:              OCTET STRING,
  [2] truncatedKeyId: OCTET STRING,
  [3] signature:      OPTIONAL,
  [4] attributes:     OPTIONAL SEQUENCE OF { key: INTEGER, value: OCTET STRING }
}
```

Signature `version` meanings noted in rustpush: absent = 1, `5` = 2, `4` = 3,
classic = 2, share = 3 (`src/icloud/pcs.rs:556-563`). For a shared-group zone you will
see the share variant; read-only participants keep the master key unwrapped directly
(no `MsaeEooevaX fooo 012` derivation) when `flags & 1` is set — Sank6's RESEARCH.md §5.4
has the precise condition.

Attribute keys seen in the wild:

| Attribute | Content | Meaning |
|---|---|---|
| 1 | `PCSBuildAndTime{build, time}` | provenance of the key |
| 3 | `PCSManateeFlags{flags}` | Manatee policy flags (0 for service keys) |
| 8 | `PCSKeyRef{keytype:3, pubKey}` | signing key for the share |
| 9 | `PCSKeyRef{keytype:3, pubKey}` | **share key**, handed to a new participant |

Attributes 8 and 9 are written by `PCSShareProtection::create(..., Some(participant_meta), true)`
(`src/icloud/pcs.rs:805-822`) and read back on accept:

```rust
let share_key: PCSKeyRef = rasn::der::decode(&parsed_invitation.get_key_attribute(9).expect("No share key??")).unwrap();
```

`get_key_attribute` is a linear scan of `keyset.attributes` for the numeric key, so
attribute 9 is the one to hunt for in the binary (**Fact** for the encoding, **inference**
that it is the only share-key carrier).

Unwrapping a keyset entry: `wrapped = u16 bits || ephemeralX || u8 len || AES-KW blob`,
ECDH on P-256 using **X only**, RFC 6637 KDF
(`sha256(00000001 || Z || <id-ecPublicKey OID> || 12 03 01 08 07 || "Anonymous Sender    " || "fingerprint".ljust(20,0))[:16]`),
AES key unwrap, then strip `01 || key || sum16 || pad`
(Sank6 `icp/sharing/pcs.py::rfc6637_unwrap`; independent of rustpush's
`rfc6637_unwrap_key`).

Then `meta` (AAD empty) decrypts to the identities structure:

```
{ [0] SET OF OCTET symmetricKeys,
  [1] { u32, OCTET },
  [2] SET OF { INTEGER, OCTET keyset }  -- each keyset is itself a PCSShareProtectionKeySet
}
```

Open `[2]` entries with the PCS private key to get zone identity keys; open
`recordProtectionInfo` with those to get default record keys; a record with its own
`protectionInfo(13)` overrides them (`src/icloud/pcs.rs:993-1000`, Sank6 RESEARCH.md §5.6-5.7).

### 3.5 Where the private key comes from

The PCS service key for `com.apple.security.keychain.shared` is a normal keychain item —
which is why this works from a Linux client that already syncs the `Manatee` view.
rustpush's `save_key` shows the exact shape (`src/icloud/pcs.rs:283-312`):

```
invi=1  sdmn=ProtectedCloudStorage  class=inet  srvr=<dsid>  path=""
labl="PCS com.apple.security.keychain.shared - <base64(pubKey[..6])>"
agrp=com.apple.ProtectedCloudStorage  pdmn=ck  type=211
atyp=sha256(pubKey)[..20]  port=0  vwht=Manatee
v_Data=DER(PCSPrivateKey)  acct=base64(pubKey)
```

`PCSService` for the shared keychain is
`{name: "com.apple.security.keychain.shared", view_hint: "Manatee", zone: "Manatee", type: 211, keychain_type: 211, v2: true, global_record: true}`
(`src/passwords.rs:72-80`). `PCSPrivateKey` is V1 (`SEQUENCE{OCTET X||d}`) or V2
(`[APPLICATION 5]{OCTET protobuf{1:{1:X||d},2:signing}}`).

Implication for `apw`: selecting `agrp == com.apple.ProtectedCloudStorage` && `type == 211`
&& `vwht == Manatee` in the already-decrypted Manatee items is enough to find candidate
zone keys. No new key material is required. **Fact** from rustpush, **inference** that the
same items exist for a Linux-joined peer (they are ordinary synced keychain items, so they
should — verify with a counts log).

### 3.6 Ciphertexts and field AAD

Sank6's `icp/sharing/pcs.py` documents the v3 layout, which is the only public
byte-level description:

```
ct = 0x03 || keyId[0:2] || n || keyId[2:2+n] || iv(12) || tag(12) || data
encKey = KDF(master, "encryption key key m")            # SP800-108 CTR, HMAC-SHA256
keyId  = HMAC(KDF(master, "master key id labell"), "M key input data 2 u")
AAD    = ct_header || callerAAD
callerAAD(field) = "<zoneName>-<recordName>-<fieldName>"
```

`payload` and `displayName` are field type 20 (`encryptedBytes`). Getting the AAD string
wrong is the most likely single cause of a "decryption failed" on a group read; the
existing personal-item code already uses this format.

### 3.7 Item payload

`SharingItem` is a protobuf (`rustpush src/passwords.proto:41-77`):

```proto
message SharingItem {
  optional SharingPrivateKey privateKey = 2;        // passkeys — skip for v1
  optional SharingInternetPassword internetPassword = 3;
}
message SharingInternetPassword {
  optional string accessGroup = 1;  optional double modificationDate = 2;
  optional double creationDate = 3; optional string account = 4;
  optional string protocol = 5;     optional string server = 6;
  optional int32 port = 7;          optional string authenticationType = 8;
  optional bytes data = 9;          optional string path = 10;
  optional string comment = 11;     optional string label = 12;
  optional string accessibility = 13; optional string viewHint = 14;
  optional string securityDomain = 15; optional bytes notes = 16;
  optional bytes history = 17;      optional bytes clientDefined0..3 = 18..21;
  optional int64 creator = 22;      optional int64 type = 23;
  optional string itemDescription = 24; optional int64 isInvisible = 26;
  optional int64 isNegative = 27;   optional int64 customIcon = 28;
  optional int64 scriptCode = 29;   optional bytes alias = 30;
}
```

`internetPassword.data` (field 9) is the password/secret blob, equivalent to `v_Data`.
`accessGroup` (field 1) carries the same values as private items — `com.apple.cfnetwork`
for web logins, `com.apple.password-manager` for metadata sidecars — so the same
`agrp`-based filtering already in `apw` applies to shared items unchanged
(Sank6 RESEARCH.md §5, final paragraph).

### 3.8 Invite and accept (the write path)

Invites travel over **IDS**, not CloudKit, on topic
`com.apple.private.alloy.kcsharing.invite` (`src/passwords.rs:1488-1500`,
`src/findmy.rs:34`), sent by the daemon calling itself
`com.apple.keychainsharingmessagingd`. Payload is a binary plist
(`src/passwords.rs:84-118`):

```
{ uID: <uuid>, s: <status>, c: { cS: "com.apple.keychainsharingmessagingd", cT: 1,
  cD: { invitationToken: <bytes>, groupID: <uuid-without-prefix>, sentTime: <date>,
        groupName: <string>, shareURL: <https://…>, inviteeHandle: <handle> } } }
```

`status` 1 = invite, 3 = revoke; IDS command 246 for invite, 247 for revoke.

Accept is two CloudKit calls (`src/icloud/cloudkit.rs:1616-1720`):

1. `ResolveToken{ routing_key = URL path minus last 22 chars, short_token_hash = sha256(last22) }`
   → `share_metadata.caller_participant`, `share_record.share_info`.
2. `ShareAccept{ share_id, participant_id, public_key_version,
   public_key = ProtectionInfo{ usingKey.pubKey }, accepted_in_process = true,
   protection_info = <new PCSShareProtection> }`
   where the new protection is built by `PCSShareProtection::create_participant(...)`
   from the invitation's decrypted key material plus attribute 9's share key.

**Read-only conflict.** Accepting an invite mutates account state (`ShareAccept`, and
`ShareDecline` for the negative case). `apw`'s stated contract is "it never writes to
Apple", and `docs/design.md:95` ("`apw sync` accepts pending invites before reading the
zone") contradicts it. Recommendation: **do not accept**. A CKShare acceptance is
per-CloudKit-user, not per-device, so if the user already accepted the invitation on
their iPhone, the zone is already in the shared database for that account and the PCS
share key should already be in the synced `Manatee` view. Reading is then identical to
the owned-group read minus the database scope. **Inference, high confidence, and the
first thing to test** (§5, Q1). Pending invites are still visible as
`cloudkit.zoneshare` records with a participant entry in state != 3, which is enough to
report "N pending invites" without writing.

---

## 4. Prior art

| Repo | Commit | License | Platform | Covers | Shared groups |
|---|---|---|---|---|---|
| [OpenBubbles/rustpush](https://github.com/OpenBubbles/rustpush) | `b3c96c2` | SSPL-1.0 (+ exceptions) | Rust, cross-platform | GSA/CloudKit/Octagon, KCKS personal, **full KCSharing read + write** | **Both owned and shared-with-me**, plus invite/accept/remove. `src/passwords.rs`, `src/icloud/pcs.rs` |
| [Sank6/iCloud-Keychain-for-Linux](https://github.com/Sank6/iCloud-Keychain-for-Linux) | `1044fdd` | MIT | Python, Linux | Auth, Octagon, personal CKKS, owned groups | owned only; README says shared-with-me is not implemented, `icp diag sharing` reports zones |
| [einyx/apple-passwords](https://github.com/einyx/apple-passwords) | `867bdbe` | MIT | Rust, Linux | Personal CKKS, owned groups | owned only (`DB_PRIVATE` at `crates/icp-core/src/groups.rs:253`), README overstates |
| [dahlia/coffer](https://github.com/dahlia/coffer) | `ce70119` | GPL-3.0 | Rust, Linux | Offline CKKS key-graph unwrap; spec docs `crates/coffer-protocol/CKKS*.md` | no |
| [au2001/icloud-passwords-firefox](https://github.com/au2001/icloud-passwords-firefox) | `a7130be` | Apache-2.0 | Firefox ext, macOS | Fills from local macOS keychain via native helper | no |
| [cameroncooper/keychain](https://github.com/cameroncooper/keychain) | `5dce7f4` | MIT | Rust, Linux/Asahi | CoreADI emulation, CLI + browser host, `docs/CLOUDKIT-WRITE-PROTOCOL.md` | not in README |
| [n0fate/iChainbreaker](https://github.com/n0fate/iChainbreaker) | `a922219` | GPL-2.0 | Python, macOS | Offline analysis of `~/Library/Keychains/<UUID>` (pre-CKKS "Local Items") | no, historical |
| [keithvassallomt/icloudbridge](https://github.com/keithvassallomt/icloudbridge) | `ad14f60` | GPL-3.0 | macOS only | Automation of Passwords.app for export | via the app, not the protocol |

`bendews/apw` (`0fb01c3`, GPL-3.0, TypeScript) is this project's upstream ancestor and
has no group support; `apw` supersedes it.

**Licensing note.** rustpush is SSPL, not OSI-approved. Read it for wire-format facts
(op numbers, field numbers, attribute keys) and reimplement; do not copy code into a
GPL/MIT-licensed tree. Sank6 does exactly this and says so in RESEARCH.md.

**What nobody has published:** a working read of a shared-with-me zone without accepting
the invite first. That is the gap `apw` can fill, and §3.8 explains why it is probably
free.

---

## 5. Open questions the binary must answer

Each item lists what to look for and the command that settles it. `P` = the IPSW path.

### Q1. Does a shared-with-me zone read work without `ShareAccept`?

Look for a request path that sets the shared database scope with a zone owner, and for
PCS key lookup that tolerates a share-variant protection.

```sh
/tmp/opencode/ipsw dyld str dsc/dyld_shared_cache_arm64e "SHARED" "sharedDatabase" "databaseScope"
strings /mnt/pw/System/Applications/Passwords.app/Passwords | grep -iE 'shared.?db|databasescope|zoneshare'
```

Practical test: log the zone-changes sync against `SHARED` for container
`com.apple.security.shared.keychain` and record every `group-*` zone with its
`ownerIdentifier`; then attempt §3.4 against each with the keys found in §3.5. If the
zone lists and the keys open, accept is unnecessary.

### Q2. Is the share record named `cloudkit.zoneshare` or typed `cloudkit.share`?

Both. Confirm on `24B156` by logging the actual record name and type per zone rather
than trusting either implementation.

```sh
/tmp/opencode/ipsw dyld str dsc/dyld_shared_cache_arm64e "cloudkit.zoneshare" "cloudkit.share"
```

### Q3. Where do the shared PCS keys live on iOS 27?

Targets: `type=211`, `vwht=Manatee`, `agrp=com.apple.ProtectedCloudStorage`,
`labl` starting `PCS com.apple.security.keychain.shared`.

```sh
strings /mnt/pw/System/Applications/Passwords.app/Passwords \
  | grep -E 'security\.keychain\.shared|ProtectedCloudStorage|groupaccess'
/tmp/opencode/ipsw dyld str dsc/dyld_shared_cache_arm64e "groupaccesskeys" "accesskeys" "pcsservice"
```

`groupaccesskeys` is **not** present in any public implementation, Apple open source, or
the Security private headers reviewed here. Treat it as an unverified lead: plausible
readings are (a) a keychain `svce`/`labl` for group key bundles, (b) a CloudKit field on
the share record, (c) a log/telemetry key. Do not build on it until a string hit lands in
`securityd`, `keychainsharingmessagingd` or `ProtectedCloudStorage`.

### Q4. Which entitlements gate group reads?

Confirmed entitlements from Apple open source (`sectask/SecEntitlements.h:202-208`):

```
com.apple.private.keychain.kcsharing.client
com.apple.private.keychain.kcsharing.invitation.notifier
com.apple.private.keychain.kcsharing.invitation.manager
```

```sh
/tmp/opencode/ipsw ent --fs "$P" --has com.apple.private.keychain.kcsharing.client --format jsonl
/tmp/opencode/ipsw ent --fs "$P" --has com.apple.private.keychain.kcsharing.invitation.manager --format jsonl
/tmp/opencode/ipsw macho info /mnt/pw/System/Applications/Passwords.app/Passwords -e
```

These tell you *who* is allowed to be a KCSharing client. They do **not** appear in the
CloudKit request path — rustpush reads groups with plain `cloudKitToken` + anisette
headers — so they should not block a Linux client. Confirm that no `x-apple-*` header
carries an entitlement assertion.

### Q5. Do group items ever carry an `agrp` that is the group id?

Check whether `SharingInternetPassword.accessGroup` (field 1) or the enclosing keychain
item's `agrp` is rewritten to `group-<UUID>`/`com.apple.security.keychain.shared`, or
whether items keep `com.apple.cfnetwork`.

```sh
strings dsc/lib/ProtectedCloudStorage | grep -iE 'agrp|accessGroup|group-'
```

Current evidence (Sank6, einyx) says items keep their original access groups; if true,
group membership is solely zone-level and `apw`'s existing filter is correct.

### Q6. Group name and membership presentation

- `displayName` decryption path: `EncryptedValue.stringValue` (field 6) under the zone's
  record keys. Confirm field number on this build.
- Participant removal signal: `ShareInfo.participants[].state` (3 = accepted); rustpush
  treats `!= 3` as removed. Confirm the enum on iOS 27.
- `is_owner` derivation: `database_type != SharedDb` (rustpush) vs
  `zone.ownerIdentifier != user_id`; check which one the app uses when both are available.

### Q7. What does the app do when a group is unreadable?

Useful for UX parity: does Passwords.app hide the group, show it empty, or show a
"couldn't load" state? Suggests the intended error surface for `apw`.

```sh
strings /mnt/pw/System/Applications/Passwords.app/Passwords \
  | grep -iE "couldn.t (load|open)|shared group|unable to (load|decrypt)"
```

### Q8. Is there a plist/LaunchDaemon for the messaging daemon?

```sh
/tmp/opencode/ipsw extract --files -p '(LaunchDaemons|LaunchAgents)/.*kcsharing.*' -o out "$P"
/tmp/opencode/ipsw extract --files -p '(LaunchDaemons|LaunchAgents)/.*keychainsharing.*' -o out "$P"
```

Expect a daemon whose MachServices include `com.apple.security.kcsharing` and whose
binary is `keychainsharingmessagingd` (referenced by name as the invite sender). This
nails down which process owns the IDS topic and the share-key lifecycle.

---

## 6. Reference list

- blacktop/ipsw — https://github.com/blacktop/ipsw, guides:
  [extract](https://blacktop.github.io/ipsw/docs/guides/extract),
  [AEA](https://blacktop.github.io/ipsw/docs/guides/aea)
- ipsw AEA pure-Go fallback — https://github.com/blacktop/ipsw/issues/999
- Apple Encrypted Archive format — https://theapplewiki.com/wiki/Apple_Encrypted_Archive
- `/private/preboot/Cryptexes` — https://theapplewiki.com/wiki/Filesystem:/private/preboot/Cryptexes
- `cryptex(5)` man page — https://keith.github.io/xcode-man-pages/cryptex.5.html
- Apple Platform Security, iCloud Keychain and credential provider extensions —
  https://support.apple.com/guide/security/ (see "Credential provider extensions", "iCloud Keychain security overview")
- Passwords app availability — https://support.apple.com/en-us/120758
- Keychain access groups — https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps
- Password AutoFill / credential provider extensions — https://developer.apple.com/documentation/security/password-autofill
- `Security/keychain/securityd/entitlements.plist` (container → service map) —
  https://github.com/apple-oss-distributions/Security/blob/main/keychain/securityd/entitlements.plist
- `Security/sectask/SecEntitlements.h` (kcsharing entitlements) —
  https://github.com/apple-oss-distributions/Security/blob/main/sectask/SecEntitlements.h
- `Security/base/Security_Private.h` (KCSharing* private headers) —
  https://github.com/apple-oss-distributions/Security/blob/main/base/Security_Private.h
- `Security/keychain/securityd/KCSharingStubXPCListenerDelegate.m` (mach service name) —
  https://github.com/apple-oss-distributions/Security/blob/main/keychain/securityd/KCSharingStubXPCListenerDelegate.m
- rustpush `src/passwords.rs`, `src/passwords.proto`, `src/icloud/pcs.rs`,
  `src/icloud/cloudkit.rs` — https://github.com/OpenBubbles/rustpush (SSPL-1.0)
- Sank6 `RESEARCH.md` §5 "Shared password groups", `icp/sharing/{groups,pcs}.py` —
  https://github.com/Sank6/iCloud-Keychain-for-Linux (MIT)
- einyx `crates/icp-core/src/{groups,pcs,ckks}.rs` —
  https://github.com/einyx/apple-passwords (MIT)
- coffer offline CKKS key graph docs — https://github.com/dahlia/coffer (GPL-3.0)
