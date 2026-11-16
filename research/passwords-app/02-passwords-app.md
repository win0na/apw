# 02. Passwords.app and PasswordManagerUI

## 1. Where the bundle lives

The app is not in `/Applications`. On iOS 27.2.1 the bundle is:

```
/private/var/staged_system_apps/Passwords.app
```

`/Applications/Passwords.app` does not exist in the filesystem image. There is a
placeholder at `System/Library/AppPlaceholders/Passwords.app` and an app signature
record at `System/Library/AppSignatures/com.apple.Passwords`. The staged location
is the one with the executable.

Bundle identifier: `com.apple.Passwords`.
Bundle version: `8625.2.8.10.7` (short version `3.2`).
Minimum OS: `27.2`.

The bundle is 2.4 MB. The executable is 154 KB. This is a shell: the app is a
SwiftUI scene plus a lifecycle object, and all real work is in
`PasswordManagerUI.framework`.

## 2. Bundle layout

| Path | Notes |
|---|---|
| `Passwords` | 154 KB arm64e executable, PAC, PIE |
| `Info.plist` | bundle id, versions, URL schemes, scene manifest |
| `Assets.car` | 1.9 MB asset catalog |
| `InfoPlist.loctable`, `Localizable.loctable` | localized strings |
| `UninstallDialog.loctable` | uninstall confirmation strings |
| `Library/SharedWebCredentials/passwords.apple.com.json` | associated-domain file |
| `*.lproj/` | 40+ localizations |
| `_CodeSignature/` | signature resources |

There are no `PlugIns`, no `Frameworks`, and no app extensions inside the bundle.
AutoFill, credential-provider UI, and the migration extension are separate system
components:

- `System/Library/ExtensionKit/Extensions/PasswordsDataMigration.appex`
  (`PasswordsDataMigration`, 106 KB)
- `Applications/AuthenticationServicesUI.app`
- `Applications/AutoFillSuggestions.app`

## 3. Info.plist

The plist is small and was read with `plistlib` from the `apfs-fuse` mount:

| Key | Value |
|---|---|
| `CFBundleIdentifier` | `com.apple.Passwords` |
| `CFBundleVersion` | `8625.2.8.10.7` |
| `CFBundleShortVersionString` | `3.2` |
| `CFBundleDisplayName` | `Passwords` |
| `MinimumOSVersion` | `27.2` |
| `CFBundleURLTypes` | `otpauth`, `apple-otpauth`, `otpauth-migration`, `apple-otpauth-migration` |
| `UIApplicationSceneManifest` | multiple scenes, empty scene configurations |

The URL schemes mean the app owns TOTP import, including the Google Authenticator
migration format. This matches the `otpauth` handling in `apw`.

## 4. Entitlements

`ipsw macho info --ent` prints a 60-key entitlement dictionary. The entries that
matter for this project:

| Entitlement | Value |
|---|---|
| `application-identifier` | `0000000000.com.apple.Passwords` |
| `com.apple.application-identifier` | `com.apple.Safari` |
| `com.apple.private.keychain.kcsharing.client` | true |
| `com.apple.authentication-services.access-credential-identities` | true |
| `com.apple.accounts.appleaccount.fullaccess` | true |
| `com.apple.authkit.client.private` | true |
| `com.apple.cdp.statemachine` | true |
| `com.apple.private.LocalAuthentication.CallerName` | true |
| `com.apple.private.Safari.History` | true |
| `com.apple.private.Safari.PasswordBreachHelper` | true |
| `com.apple.private.associated-domains` | true |

The keychain access groups are the complete list of password-related `agrp`
values the app can see:

```
com.apple.cfnetwork
com.apple.password-manager
com.apple.webkit.webauthn
com.apple.password-manager.website-metadata
com.apple.Passwords.LocalState
com.apple.sharing.safaripasswordsharing
com.apple.safari.history
com.apple.password-manager.personal
com.apple.password-manager.generated-passwords
com.apple.password-manager.password-evaluations
com.apple.password-manager.automatic-security-upgrades
```

Each has a `.testing` twin, and the three sync classes also have
`-recently-deleted` twins (`com.apple.cfnetwork-recently-deleted`,
`com.apple.password-manager-recently-deleted`,
`com.apple.webkit.webauthn-recently-deleted`,
`com.apple.password-manager.personal-recently-deleted`).

Two of these are new information for `apw`:

- `com.apple.password-manager.personal` is a separate access group from
  `com.apple.password-manager`. The live histogram from our account showed 394
  items in `com.apple.password-manager` and none in `.personal`, so this is
  either unused on this account or used only on newer data.
- `com.apple.password-manager.generated-passwords` is the home of generated
  passwords. Our sync kept them out via the metadata filter; if they should be
  listed, this is the group to select.

`com.apple.sharing.safaripasswordsharing` is the local state group for Safari's
password sharing. It is not the CloudKit zone; shared items keep their original
`agrp` (`com.apple.cfnetwork`).

## 5. Linked frameworks

From `ipsw macho info --loads`:

```
/System/Library/Frameworks/SafariServices.framework/SafariServices
/System/Library/PrivateFrameworks/PasswordManagerUI.framework/PasswordManagerUI (625.2.8)
/System/Library/Frameworks/Foundation.framework/Foundation
/usr/lib/libobjc.A.dylib
/usr/lib/libSystem.B.dylib
/System/Library/Frameworks/Combine.framework/Combine
/System/Library/Frameworks/SwiftUI.framework/SwiftUI
/System/Library/Frameworks/UIKit.framework/UIKit (weak)
/System/Library/PrivateFrameworks/SafariCore.framework/SafariCore (625.2.8)
```

The rest are Swift runtime libraries. The app does not link CloudKit, Security, or
ProtectedCloudStorage directly. It reaches them through `PasswordManagerUI` and
`Security.framework`'s KCSharing API.

## 6. The app's own code

`ipsw macho info --swift` on the executable shows three types:

- `Passwords.AppLifecycleActions`, holding `PMDependency` wrappers for
  `PMAccountStore`, `_ASPasswordManagerIconController`,
  `PMAutomaticPasswordChangeManaging`, and `WBSAutoFillQuirksManager`.
- `Passwords.PMPasswordsApp`, a SwiftUI `App` with an
  `UIApplicationDelegateAdaptor` for `PMUIApplicationDelegate`.
- `Passwords.DetailsScene`, a generic scene over `PMWindowGroupIdentifier`.

There is no group, share, CloudKit, or keychain code in the app binary. Its string
table contains only `sharedLogger` and `sharedStore`.

## 7. PasswordManagerUI

Version `8625.2.8.10.7`. The binary is only in the dyld shared cache; the on-disk
framework directory has resources and an `Info.plist` but no Mach-O.

The ObjC metadata and symbol table show the sharing surface:

- `PMSharingGroupsProviderMain` and its nested `GroupUpdateHandler`
- `PMSharedAccountsGroupMemberPickerViewController`
- `PMAddGroupMembersViewControllerRepresentable`
- `PMSharedAccountsGroupMemberPickerViewController` ivars:
  `_addressToEligibility`, `_addressesCurrentlyBeingCheckedForAvailability`,
  `_addressesThatHaveBeenFetched`, `_alreadyAddedAddresses`,
  `_contactsSearchManager`, `_currentSearchTaskID`, `_delegate`

It imports Security's sharing classes directly:

```
KCSharingGroup
KCSharingGroupCreateRequest
KCSharingGroupDeleteRequest
KCSharingGroupLeaveRequest
KCSharingGroupManager
KCSharingGroupUpdateRequest
KCSharingParticipant
```

It also uses AuthenticationServices' sharing presentation types
(`_ASAccountSharingGroupMemberDataManager`,
`_ASAccountSharingGroupInvitationAcceptanceFlowContent`, …) and SafariCore's
`WBSOngoingSharingGroupProvider`.

The string table contains the user-visible feature set:

```
Shared Groups
Stop Sharing
Shared Passwords Groups are unavailable.
Passwords and passkeys %@ shared with this group will be removed.
Any passwords and passkeys you shared with this group will be unshared.
%@, %@, and other group members may still have access to accounts you shared in this group.
No result returned from KCSharing availability check for handle: %{sensitive}@.
```

This is conclusive: the app's shared groups are Security's KCSharing groups, not
a Passwords-specific mechanism. The protocol work belongs in `securityd`, which
is covered in `03-kcsharing.md`.

## 8. What this means for `apw`

- Do not look for group logic in the app binary. It is a client of
  `KCSharingGroupManager`.
- The access-group list is the authoritative filter for item kinds. It adds
  `com.apple.password-manager.personal`, `generated-passwords`,
  `password-evaluations`, and `automatic-security-upgrades` to the set already
  handled by `apw`.
- The TOTP URL schemes confirm that `otpauth-migration` is in scope for import,
  not just display.
- There is no AutoFill extension to reverse engineer for the CLI. The CLI needs
  the keychain data path, not the UI path.
