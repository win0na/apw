# 04. Verification against the iOS 27.2.1 binaries

This file checks the claims in `00-prior-art.md` against what is actually in the
24B156 image. It also lists what the binary adds that the prior art did not have.

## 1. Claim check

| # | Claim | iOS 27.2.1 evidence | Verdict |
|---|---|---|---|
| 1 | System apps live in a cryptex, not `/Applications` | `Passwords.app` is at `private/var/staged_system_apps/Passwords.app` in the root filesystem; `/Applications/Passwords.app` is absent | **Corrected**: staged system app, root FS |
| 2 | The app is a thin client over PasswordManagerUI | 154 KB executable; links `PasswordManagerUI`; Swift types are only `AppLifecycleActions`, `PMPasswordsApp`, `DetailsScene` | **Confirmed** |
| 3 | Shared groups use Security's KCSharing API | App imports `KCSharingGroupManager`, `KCSharingGroup`, `KCSharingParticipant`; entitlement `com.apple.private.keychain.kcsharing.client` | **Confirmed** |
| 4 | The implementation is in `securityd` | 29 `KCSharing*` classes in `securityd`; `KCSharingSyncController` owns the CloudKit container and sync engines | **Confirmed** |
| 5 | `KeychainCircle` handles sharing | `KeychainCircle` has only pairing/Octagon types; no group classes | **Refuted**; it is Octagon pairing |
| 6 | Container `com.apple.security.shared.keychain` | CFString in `securityd` | **Confirmed** |
| 7 | Bundle/service `com.apple.security.kcsharing` | CFString plus XPC mach service and entitlements | **Confirmed** |
| 8 | PCS service `com.apple.security.keychain.shared` | CFString in `securityd` | **Confirmed** |
| 9 | PCS key `agrp` is `com.apple.ProtectedCloudStorage` | CFString in `securityd`; `vwht` and `Manatee` also present | **Confirmed** |
| 10 | Zones are `group-<UUID>` | CFString `group-` in the record-building block | **Confirmed** (prefix) |
| 11 | Item record type is `item`, fields `payload`, `type` | Same CFString block: `item`, `type`, `payload`, `displayName`, `KCSharingRecord` | **Confirmed** |
| 12 | Share record is `cloudkit.zoneshare` of type `cloudkit.share` | Both strings in `CloudKit.framework` | **Confirmed** |
| 13 | Payload is a protobuf with password/passkey oneof | `KCSharingPBRemoteItem` with `internetPassword` and `privateKey`; both credential messages present | **Confirmed** |
| 14 | Shared items keep their original `agrp` | `KCSharingPBInternetPasswordCredential.accessGroup` exists; the app's access-group list is the same set as personal items | **Confirmed** |
| 15 | Owned groups are in the private DB, shared groups in the shared DB | `KCSharingSyncController` has `privateCloudDB`/`sharedCloudDB` and `privateSyncEngine`/`sharedSyncEngine` | **Confirmed** |
| 16 | Reading shared-with-me needs no `ShareAccept` | No static contradiction; the daemon exposes both accept and read paths separately | **Inferred**, live test required |
| 17 | `apw`'s 328 logins are short of the app's 417 because of groups | Group items are in separate zones; personal zones contain 328 logins; no other source of 89 logins was found in the personal data | **Inferred**, strong |
| 18 | The app has an AutoFill extension in the bundle | No `PlugIns`, no `Frameworks`, no `.appex` in the bundle; AutoFill is a separate app | **Refuted** |

## 2. New findings not in the prior art

### 2.1 The app is staged, and the placeholder is separate

`/private/var/staged_system_apps/Passwords.app` is the real bundle. The
`System/Library/AppPlaceholders/Passwords.app` directory holds a 2.7 KB
`Info.plist`, a 7.4 KB `PlaceholderEntitlements.plist`, the 1.9 MB asset catalog,
and `Library/SharedWebCredentials/passwords.apple.com.json`. The signature record
is `System/Library/AppSignatures/com.apple.Passwords`.

Any extraction recipe that looks only in `/Applications` or in the App cryptex
will miss the app. The App cryptex on this build is 16 MB and contains no
applications.

### 2.2 The complete access-group list

The app's `keychain-access-groups` entitlement is the authoritative set of
password-related `agrp` values. It adds four groups to what `apw` currently
knows:

```
com.apple.password-manager.personal
com.apple.password-manager.generated-passwords
com.apple.password-manager.password-evaluations
com.apple.password-manager.automatic-security-upgrades
```

and one sharing-local group:

```
com.apple.sharing.safaripasswordsharing
```

The live snapshot had no items in `.personal`; the histogram showed
`com.apple.password-manager` 394 and `com.apple.password-manager.website-metadata`
303. The new groups are worth logging on the next sync, because they may be
where iOS 27 puts data that older builds put elsewhere.

### 2.3 The daemon gates records by access group and schema version

`KCSharingAccessGroups` carries `entryAccessGroup` and `entrySchemaVersion`, and
answers:

```
-recordTypeIsKnown:
-recordHasKnownFields:
-recordIsFullyDecoded:
-remoteItemProtoIsFullyDecoded:
```

This is a forward-compatibility gate. A client that decodes a record with an
unknown schema version should not guess at the fields. Log the version and skip
the item, or surface it as opaque.

### 2.4 The daemon repairs its own state

`KCSharingFixUpManager` (`performFixUpOneWithStore:lockStateTracker:WithCompletion:`)
and `KCSharingPingPong` exist to reconcile local state after crashes or partial
syncs. A read-only client does not need them, but their presence explains why the
daemon can be authoritative about group state without a full re-download.

### 2.5 The daemon uses CKSyncEngine, not raw protobuf

The prior art describes the CloudKit HTTP protobuf operations that a custom client
must issue. The daemon itself uses `CKSyncEngine`, one instance per database. This
does not change what `apw` must implement; it confirms that the private/shared
split is a first-class part of the design rather than an implementation detail.

### 2.6 TOTP import is in the app's URL surface

`CFBundleURLTypes` contains `otpauth`, `apple-otpauth`, `otpauth-migration`, and
`apple-otpauth-migration`. `apw` already handles `otpauth`; the migration scheme
is the Google Authenticator export format and is in scope for import parity.

## 3. Where the prior art is imprecise

| Statement | Precision |
|---|---|
| "system apps live in the app cryptex" | Only App Store apps do. System apps are staged in the root filesystem. |
| "shared group access group" | The access group for the keys is `com.apple.ProtectedCloudStorage`; the *service* is `com.apple.security.keychain.shared`; the *zone* is `group-<UUID>`. Three names, three things. |
| "`KeychainCircle` implements sharing" | It implements Octagon pairing. The sharing types are in `Security.framework` and `securityd`. |
| "`ipsw mount` works on Linux" | It needs `apfs-fuse` on `PATH` and FUSE access. `7z` alone reads APFS but does not decompress decmpfs. |
| "`ipsw extract --dmg sys` decrypts the system image" | It copies the `.aea`. Use `ipsw fw aea -k` and `-b` explicitly. |

## 4. Unverified claims and how to settle them

| Claim | How to verify |
|---|---|
| Item record name is `item-<UUID>` | Live `record/sync` on a group zone; log every record name and type. |
| Proto field numbers (2 = privateKey, 3 = internetPassword) | Decode one payload and compare field numbers; or disassemble `KCSharingPBRemoteItem writeTo:`. |
| PCS attribute 9 carries the share key | Decode a zone `ProtectionInfo` and inspect the attribute set. |
| Shared-with-me reads without `ShareAccept` | List zones in the shared database for this account and fetch one item. |
| The 89 missing logins are all group items | Compare group item count with 417 - 328 after the read path works. |
| `com.apple.password-manager.personal` is unused on this account | Log the `agrp` histogram on the next sync. |

## 5. Count arithmetic

The live snapshot after cleanup:

```
328 logins
 34 passkeys
 47 TOTP codes
```

The app reports 417 in All. If All counts logins only, the gap is 89 logins. If
All includes passkeys, the gap is 55. The group zones are the only known source
of additional logins; the personal zones were exhaustively counted by `agrp`.

The raw CKKS histogram was:

```
374 cfnetwork           (328 after dropping 46 empty placeholders)
394 password-manager    (metadata sidecars, merged)
303 website-metadata    (dropped)
106 ProtectedCloudStorage
 37 webauthn
 38 tombstones
```

None of the dropped classes can account for 89 logins. That is why the group
zones are the leading explanation, not a metadata bug.

## 6. Confidence

- The container, service, zone prefix, record type/field names, payload oneof,
  private/shared split, and the app's use of KCSharing are **seen** and
  unambiguous.
- The exact record name format, proto field numbers, PCS attribute numbers, and
  the no-accept read are **inferred** from consistent prior art and adjacent
  evidence. Each is cheap to settle with one live request.
- Nothing in the static analysis suggests a second, undocumented sharing
  mechanism. The app's strings, entitlements, imports, and the daemon's class
  graph all point at the same KCSharing path.
