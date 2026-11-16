# 03. KCSharing: how shared password groups work

The shared-group feature is implemented by `securityd`, not by Passwords.app and
not by `KeychainCircle`. `KeychainCircle` is the Octagon pairing channel; it has
no group types. `securityd` contains a complete KCSharing subsystem, and the app
is a client of it through `Security.framework`.

## 1. Names, kept apart

| Namespace | Value | Evidence |
|---|---|---|
| CloudKit container | `com.apple.security.shared.keychain` | **seen** in `securityd` strings |
| CloudKit bundle id | `com.apple.security.kcsharing` | **seen** in `securityd` strings |
| XPC mach service | `com.apple.security.kcsharing` | **seen** in `securityd` strings |
| Client entitlement | `com.apple.private.keychain.kcsharing.client` | **seen** in `securityd` and in the app's entitlements |
| PCS keychain access group | `com.apple.ProtectedCloudStorage` | **seen** in `securityd` strings |
| PCS service name | `com.apple.security.keychain.shared` | **seen** in `securityd` strings |
| CloudKit zone | `group-<UUID>` | **seen** prefix `group-`; UUID format from prior art |
| Group item record | name `item-<UUID>`, type `item` | **inferred** from strings + prior art; verify live |
| Share record | name `cloudkit.zoneshare`, type `cloudkit.share` | **seen** in `CloudKit.framework` strings |
| Local state access group | `com.apple.sharing.safaripasswordsharing` | **seen** in the app's entitlements |

`group-<UUID>` is a zone name. It is not an access group, despite the name. Shared
items keep the access group they had when personal (`com.apple.cfnetwork` for web
logins), so the existing `apw` item filter applies to group items unchanged.

## 2. Architecture

```
Passwords.app / PasswordManagerUI
        |  KCSharingGroupManager (Security.framework)
        v
Security.framework: KCSharingDaemonConnection  --NSXPC-->  securityd
                                                            KCSharingXPCListenerDelegate
                                                            KCSharingXPCServer
                                                            KCSharingDaemonGroupManager
                                                            KCSharingSyncController
                                                              |            |
                                                    CKSyncEngine   CKSyncEngine
                                                     private        shared
                                                              |
                                                        CloudKit container
                                                 com.apple.security.shared.keychain
```

Invites use a second daemon:

```
securityd --(KCSharingMessagingdConnection)--> keychainsharingmessagingd
        --IDS topic com.apple.private.alloy.kcsharing.invite--> recipient device
```

`keychainsharingmessagingd` is 213 KB and contains only the invite transport:
`KCSharingMessagingdXPCServer`, `shareURL`, `inviteToken`, `senderHandle`,
`inviteeHandle`, `displayName`, and `KCSharingGroupInvite` construction. It does
not touch CloudKit.

## 3. Security.framework API

`ipsw class-dump` of Security.framework shows the client surface. The types are
small and fully described by their properties:

### `KCSharingGroup`

```
groupID          NSString
displayName      NSString
participants     NSArray<KCSharingParticipant>
shareURL         NSURL
isOwned          BOOL
joinState        NSInteger
currentUserParticipant  KCSharingParticipant
ownerParticipant        KCSharingParticipant
```

Initializers: `initWithGroupID:participants:displayName:shareURL:` and
`initWithParticipants:displayName:`. It is `NSSecureCoding` and `NSCopying`.

### `KCSharingParticipant`

```
participantID    NSString
handle           NSString
permissionLevel  NSInteger
isCurrentUser    BOOL
isOwner          BOOL
inviteStatus     NSInteger
invitedBy        KCSharingParticipant
sharingInvitationData  NSData
```

### Requests

- `KCSharingGroupFetchRequest`: `+all`, `+pending`, `+groupName:`,
  `predicateMatchingAllGroups`, `predicateMatchingGroupsWithInviteStatus:`.
- `KCSharingGroupCreateRequest`: wraps a new `KCSharingGroup`.
- `KCSharingGroupUpdateRequest`: group plus update info.
- `KCSharingGroupDeleteRequest`, `KCSharingGroupLeaveRequest`.
- `KCSharingGroupInvite`: `groupID`, `shareURL`, `inviteToken`, `senderHandle`,
  `inviteeHandle`, `sentTime`, `displayName`.

### `KCSharingGroupManager`

A singleton with one daemon connection:

```
+sharedInstance
-getGroupsWithRequest:completion:
-getGroupByGroupID:completion:
-createGroupWithRequest:completion:
-updateGroupWithRequest:completion:
-leaveGroupWithRequest:completion:
-deleteGroupWithRequest:completion:
-acceptInviteForGroupID:completion:
-declineInviteForGroupID:completion:
-checkAvailabilityForHandle:completion:
-checkAvailabilityForHandles:completion:
-fetchCurrentUserIdentifierWithReply:
-performMaintenanceWithCompletion:
-resyncWithCompletion:
-verifyGroupsInSyncAndResyncMissingGroupsWithCompletion:
-provisionWithReply:
```

This is the complete group lifecycle. Read-only use needs only the fetch calls,
but the XPC surface is useful as a checklist for what the daemon can do.

## 4. securityd internals

`ipsw class-dump securityd` (14,309 lines) exposes the daemon classes. The sharing
subsystem is:

| Class | Role |
|---|---|
| `KCSharingXPCListenerDelegate` | accepts client connections, checks entitlement, fans out group updates |
| `KCSharingXPCServer` | per-connection server object, mirrors the manager API |
| `KCSharingDaemonGroupManager` | group lifecycle, participants, invites, share metadata |
| `KCSharingSyncController` | owns `CKContainer`, private and shared `CKSyncEngine`, and the store |
| `KCSharingStore` | local staging: outgoing changes, incoming records, mirror, fingerprints |
| `KCSharingFixUpManager` | one-shot repair of local state |
| `KCSharingPingPong` | Swift helper used by the sync controller |
| `KCSharingCloudCoreUtilities` | Swift wrappers for CKShare accept/decline/fetch |

### Sync controller

Properties, **seen** in the class dump:

```
container          CKContainer
privateCloudDB     CKDatabase
sharedCloudDB      CKDatabase
privateSyncEngine  CKSyncEngine
sharedSyncEngine   CKSyncEngine
store              KCSharingStore
fixUpManager       KCSharingFixUpManager
cloudCoreUtilities KCSharingCloudCoreUtilities
lockStateTracker   CKKSLockStateTracker
```

The presence of two sync engines and two databases is the implementation-level
confirmation of the zone model: owned groups sync through the private database,
groups shared with you sync through the shared database. `CKSyncEngine` is the
modern API; the daemon does not issue raw `record/sync` protobuf requests itself.

`KCSharingCloudCoreUtilities` has these Swift methods (demangled):

```
acceptCKShares(_:)
declineCKShares(_:)
fetchCKShareMetadatas(_:invitationTokensByShareURL:)
fetchShareParticipants(for:)
```

### Store

`KCSharingStore` is the bridge between the keychain database and CloudKit. Its
methods, **seen**:

```
-stageAllOutgoingChangesWithError:
-stageAllOutgoingChangesInTransaction:error:
-stageAllOutgoingChangedPrivateKeysInTransaction:error:
-stageAllOutgoingNewPrivateKeysInTransaction:error:
-stageAllOutgoingChangedPasswordsInTransaction:error:
-stageAllOutgoingNewPasswordsInTransaction:error:
-stageAllOutgoingDeletionsInTransaction:error:
-stageIncomingRow:error:
-stageIncomingRecord:error:
-stageIncomingDeletionForRecordID:error:
-stageOutgoingShares:deletionsForShares:error:
-applyIncomingShareDeletionsInTransaction:updateInfos:error:
-fingerprintAllPrivateKeysInTransaction:error:
-fingerprintAllPasswordsInTransaction:error:
```

`KCSharingAccessGroups` carries `entryAccessGroup` and `entrySchemaVersion`, and
answers `recordTypeIsKnown:`, `recordHasKnownFields:`, `recordIsFullyDecoded:`,
`remoteItemProtoIsFullyDecoded:`. This is forward-compatibility: the daemon refuses
to stage a record whose access group or schema version it does not understand.

The row classes map one-to-one onto the protocol:

```
KCSharingLocalItem / KCSharingLocalFingerprint
KCSharingOutgoingEntry / KCSharingOutgoingDeletion / KCSharingOutgoingChangeset
KCSharingIncomingEntry / KCSharingIncomingDeletion
KCSharingMirrorEntry
KCSharingRemoteItem
KCSharingInternetPasswordCredential / KCSharingPrivateKeyCredential
```

`KCSharingOutgoingEntry` and `KCSharingIncomingEntry` both expose
`-record` (a `CKRecord`), `-remoteItemWithAccessGroups:error:`,
`-shareWithAccessGroups:error:`, and `-attributesWithAccessGroups:error:`. The
record is the wire object; the remote item is the decoded protobuf.

## 5. CloudKit schema

### Zones

One zone per group. The name is the literal prefix `group-` followed by the group
UUID. The zone exists in the private database for a group you own and in the
shared database for a group shared with you. The owner identifier in the zone ID
is the CloudKit user id of the owner; the shared database requires it.

**Seen**: the `group-` CFString in `securityd`; `CKSyncEngine` private/shared
properties. **Inferred**: the exact UUID formatting and the owner-id requirement
(from prior art and CloudKit semantics).

### Records

| Record name | Record type | Fields | Meaning |
|---|---|---|---|
| `item-<UUID>` | `item` | `payload`, `type` | one shared credential |
| `cloudkit.zoneshare` | `cloudkit.share` | `displayName`, share metadata | the zone-wide CKShare |

**Seen**: the CFString block in `securityd` at `0x100368cb8` contains, in order,
`KCSharingXPCServer`, `operation`, `resyncXPC`, `time`, `error`,
`verifyGroupsInSyncXPC`, `verifyGroupsInSyncAndResyncMissingGroupsXPC`,
`maintenanceXPC`, `%@.%@`, `group-`, `item`, `type`, `payload`, `displayName`,
`%@%@`, `KCSharingRecord`, `+`, `KCSharingXPCListenerDelegate`,
`com.apple.security.kcsharing`, the two kcsharing entitlements, `%@ %@`,
`privateKey`, `internetPassword`, `Unknown Fields`.

`cloudkit.share` and `cloudkit.zoneshare` are **seen** in
`CloudKit.framework`'s string table, not in `securityd`.

`displayName` is encrypted. Its plaintext is a string inside the PCS-protected
field. `payload` is encrypted bytes. `type` is an integer selecting the payload
variant.

Membership is not in the item records. It is in the share record: participants
with `userID`, `publicKey` (`ProtectionInfo`), `participantID`,
`publicKeyVersion`, `state` (3 = accepted), and contact information. This is the
same `CKShare` model used by every CloudKit sharing app.

## 6. Item payload

`KCSharingPBRemoteItem` is a `PBCodable` with a oneof:

```
KCSharingPBRemoteItem
  internetPassword : KCSharingPBInternetPasswordCredential   (field 3)
  privateKey       : KCSharingPBPrivateKeyCredential         (field 2)
```

Field numbers are from prior art (`SharingItem` in rustpush's `passwords.proto`);
the class names and property lists below are **seen** in `securityd`'s class dump.

`KCSharingPBInternetPasswordCredential`:

```
accessGroup, accessibility, account, alias, authenticationType,
clientDefined0..3, comment, creationDate, creator, customIcon, data,
history, isInvisible, isNegative, itemDescription, label,
modificationDate, notes, path, port, protocol, scriptCode,
securityDomain, server, type, viewHint
```

`KCSharingPBPrivateKeyCredential`:

```
accessGroup, alias, applicationLabel, applicationTag, canDecrypt,
canDerive, canEncrypt, canSign, canSignRecover, canUnwrap, canVerify,
canVerifyRecover, canWrap, creationDate, effectiveKeySize, endDate,
isExtractable, isModifiable, isPermanent, keySizeInBits, keyType,
modificationDate, startDate
```

The password message is a keychain row in protobuf form. `data` is the secret
blob equivalent to `v_Data`; `account` is the username; `server` is the domain.
`accessGroup` carries the original `agrp`.

## 7. Encryption

The zone is protected with PCS. `ZoneRetrieve` returns two `ProtectionInfo`
values: `protectionInfo` for the zone and `recordProtectionInfo` for records.
Each is a DER `PCSShareProtection`.

`payload` and `displayName` are field type 20 (`encryptedBytes`). The ciphertext
header carries the key id and IV; the AAD is:

```
<zoneName>-<recordName>-<fieldName>
```

This is the same construction the personal CKKS path already uses. The field AAD
is the most common source of "decryption failed" when reading groups.

The zone key is unwrapped with the PCS private key for the
`com.apple.security.keychain.shared` service. That key is an ordinary synced
keychain item:

```
agrp = com.apple.ProtectedCloudStorage
type = 211
vwht = Manatee
acct = base64(public key)
v_Data = DER(PCSPrivateKey)
labl = "PCS com.apple.security.keychain.shared - <base64(pubkey[..6])>"
```

**Seen** in `securityd` strings: `com.apple.ProtectedCloudStorage`, `Manatee`,
`vwht`, `PCSShareProtection`, `PCS SHARE PROTECTION`, `PCS ZONE SHARE PROTECTION`.
**Inferred**: the exact item attribute set, from prior art. `apw` already syncs
the Manatee view, so these items are in the local snapshot.

The PCS unwrap itself is documented in `00-prior-art.md` §3.4: RFC 6637 ECDH on
P-256, AES key unwrap, then open the `meta` field to get the zone identity keys,
then open `recordProtectionInfo` to get the default record keys. A record with its
own `protectionInfo` overrides the default.

## 8. The read path a Linux client needs

1. Authenticate to CloudKit with the existing token chain and the container
   `com.apple.security.shared.keychain`.
2. List zones in the private database. Keep `group-*`.
3. List zones in the shared database. Keep `group-*`; record the owner id from
   each zone ID.
4. For each zone, fetch the share record (`cloudkit.zoneshare`) to get
   `displayName` and participants. A participant in state 3 is an accepted member.
5. Fetch `item-*` records in the zone.
6. Select the PCS key item for `com.apple.security.keychain.shared` from the
   already-decrypted Manatee items.
7. Unwrap the zone protection and record protection; decrypt `displayName` and
   `payload` with the field AAD.
8. Decode `KCSharingPBRemoteItem`; map `internetPassword` to an `Entry`, and
   `privateKey` to a passkey entry.
9. Merge by the same rules as personal items: metadata sidecars by record id or
   domain plus username.

Read-only constraint: **do not call `ShareAccept` or `ShareDecline`**. If the user
accepted the invitation on an iPhone, the zone is already in the shared database
for the account. A pending invite is visible as a share record with a participant
whose state is not 3, which is enough to report it.

## 9. What is still unknown

- The exact record name format (`item-<UUID>` vs another separator) is from prior
  art. The string table has `item` and `%@%@`, not `item-`.
- The protobuf field numbers were not re-derived from the iOS 27 binary. The
  class names, field names, and oneof are seen; the numbers are prior art.
- The PCS DER attribute layout (1, 3, 8, 9) is from prior art. The binary strings
  confirm the object and the service, not the attribute numbers.
- Whether a shared-with-me zone reads without `ShareAccept` on this account is
  the first live test. Nothing in the static analysis contradicts it.
- `KCSharingAccessGroups.entrySchemaVersion` is not mapped to a value. The daemon
  rejects records it does not understand; a client should log the version and
  fall back rather than guess.
