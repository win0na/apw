# Passwords.app, iOS 27.2.1: reverse-engineering notes

Reference material for the `apw` Linux port. Everything here was taken from the
retail IPSW for iPhone17,1, iOS 27.2.1 (build 24B156), and from static analysis of
the binaries it contains. The goal is to settle how Apple stores shared password
groups in iCloud Keychain, and what a read-only Linux client has to implement.

## Evidence rules

- **seen**: read directly from an extracted file, a symbol table, a class dump, a
  string table, or a plist. The command or path is cited.
- **inferred**: follows from seen evidence plus prior art, but was not observed at
  runtime.
- **unknown**: not established by this work. Not the same as absent.

No claim here comes from running the iOS binaries. This is static analysis only.

## Target

| Field | Value |
|---|---|
| Device | iPhone17,1 (iPhone 16 Pro, D93AP, t8140) |
| OS | iOS 27.2.1, build 24B156 |
| IPSW | `iPhone17,1_27.2.1_24B156_Restore.ipsw`, 12,992,259,527 bytes |
| SHA-256 | `e2916731a8d655d3d2d5aec75ebab1fde569a2fe3aa01092ac096d75582bea8d` |
| App | `com.apple.Passwords` 8625.2.8.10.7 (short version 3.2) |
| UI framework | `PasswordManagerUI` 8625.2.8.10.7 |
| Daemon | `securityd` (iOS 27.2) |

## Findings that matter for `apw`

1. **The Passwords app is a shell.** `Passwords.app/Passwords` is 154 KB and links
   `PasswordManagerUI.framework`, `SafariServices`, `SafariCore`, `SwiftUI`, and
   `UIKit`. All model and UI code lives in `PasswordManagerUI`, which has no
   on-disk Mach-O; it is only in the dyld shared cache.
2. **The app does not own the sharing protocol.** It uses Security.framework's
   `KCSharingGroupManager` / `KCSharingGroup` API. The implementation is in
   `securityd`, in classes named `KCSharing*`. `KeychainCircle` is Octagon
   pairing, not KCSharing.
3. **Shared groups are ordinary CloudKit zones.** One zone per group, named
   `group-<UUID>`, in the private database when you own the group and in the
   shared database when someone shared it with you. The container is
   `com.apple.security.shared.keychain`; the PCS service is
   `com.apple.security.keychain.shared`.
4. **The record schema is small.** A group zone holds `item-<UUID>` records of
   type `item` with `payload` and `type` fields, plus a `cloudkit.zoneshare`
   record of type `cloudkit.share` carrying `displayName` and the participant
   list. The binary's string table contains `item`, `type`, `payload`,
   `displayName`, `group-`, and `KCSharingRecord` in one CFString block.
5. **The item payload is a protobuf**, `KCSharingPBRemoteItem`, with a oneof:
   `internetPassword` or `privateKey`. The password message mirrors keychain
   attributes (`account`, `server`, `protocol`, `port`, `data`, `label`, dates,
   access group).
6. **Zone protection is PCS.** The share key is a normal synced keychain item in
   access group `com.apple.ProtectedCloudStorage`, `type` 211, `vwht` `Manatee`,
   labelled `PCS com.apple.security.keychain.shared - …`. `apw` already decrypts
   those items as part of the Manatee view.
7. **Reading a shared-with-me group probably needs no `ShareAccept`.** A CKShare
   acceptance is per Apple account, not per device. If the user accepted on an
   iPhone, the zone is already in the shared database and the key is already
   synced. This is the first live test to run; it keeps `apw` read-only.
8. **The app is staged, not in `/Applications`.** The real bundle is
   `/private/var/staged_system_apps/Passwords.app`. `/Applications/Passwords.app`
   does not exist; `System/Library/AppPlaceholders/Passwords.app` is a placeholder
   with icons, entitlements, and a Shared Web Credentials association.
9. **The 417-vs-328 gap is consistent with shared groups.** Personal zones gave
   328 logins; the app counts 417 in All. Group zones are not in `Passwords` or
   `Manatee`, so a client that reads only those zones cannot see them.
10. **The app has no AutoFill extension inside the bundle.** AutoFill and
    credential-provider surfaces are separate system apps
    (`AuthenticationServicesUI`, `AutoFillSuggestions`), which is why the bundle
    is so small.

## Documents

| File | Contents |
|---|---|
| `01-acquisition.md` | IPSW identity, DMG map, Linux extraction pipeline, artifacts, traps |
| `02-passwords-app.md` | Bundle layout, Info.plist, entitlements, linked frameworks, UI surface |
| `03-kcsharing.md` | KCSharing architecture in `securityd`, zones, records, protobuf, PCS, read path |
| `04-verification.md` | Claim-by-claim check of prior art against the iOS 27.2.1 binaries |
| `05-implications.md` | What `apw` must change, in what order, and what to test live |

`00-prior-art.md` is the external research that preceded this work: public
implementations, wire formats, and the open questions this analysis answers.

## Reproducing

The pipeline is in `01-acquisition.md`. In short: download the IPSW, decrypt the
system and filesystem DMGs with `ipsw fw aea`, read APFS with `7z` or `apfs-fuse`,
extract `Passwords.app` from the filesystem image, and pull
`PasswordManagerUI`, `Security`, `CloudKit`, and `ProtectedCloudStorage` out of
the dyld shared cache with `ipsw dyld extract`.

The extracted tree is not committed. It is about 25 GB and reproducible from the
IPSW. Only text evidence (commands, hashes, dumps, notes) lives in this directory.
