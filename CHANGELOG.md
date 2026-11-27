# Changelog

Changes worth knowing between releases. 0.5.0 covers everything since `v0.3.0`;
0.4.0 was never tagged.

## [0.5.0] - 2026-11-27

### Added

- A full-screen terminal interface. `apw` with no arguments browses, searches,
  adds, edits, deletes, restores, and syncs the vault; `/` opens a command
  palette and the item pane lists the keys for that item.
- Apple device identities are provisioned in process. The separate anisette
  service is no longer required; a configured server URL still takes precedence.
- A macOS identity authorizes account requests and escrow. The Windows identity
  remains the fallback when macOS provisioning fails.
- Prebuilt release assets and `scripts/install.sh`, which installs the
  executable and `libopentui.so` under `~/.local` by default.
- Interface views for passkeys, groups, Recently Deleted, and pending changes,
  plus a sign-in wizard that asks for the two-factor code.

### Changed

- The snapshot key is stored in Secret Service directly, without the `keyring`
  crate. Items use `application=apw`, `purpose=snapshot-key`, `schema=1`. An
  existing keyring item is copied once and left in place.
- `libopentui.so` is linked dynamically and installed in `lib/apw` beside the
  executable, in the tarball, the Debian package, the AUR recipe, and the Nix
  output. The tarball now carries both files.
- TLS uses rustls with ring. The AWS-LC build is gone.
- The release profile uses fat LTO, one codegen unit, abort on panic,
  `opt-level = "z"`, and stripped symbols.
- Headless runs need an unlocked Secret Service collection or
  `APW_PASSPHRASE`; the kernel keyring cache is no longer read.
- Building from source needs Zig 0.17.1 for the OpenTUI library.

### Fixed

- Escrow recovery exchanges the PET on every path, names the macOS two-factor
  prompt, and gives the Windows PET its own code.
- Identity state resolves and recovers when files are missing or half-written.
- A 434 retry keeps the remote backend.
- Interface focus after the tab bar, and sign-in dialogs that stayed open.
- Nix builds get a writable Zig cache and keep their build phase.
- Debug and test binaries find `libopentui.so`.
- `cargo install --path .` resolves the repository's OpenTUI shim without
  `--locked`.

[0.5.0]: https://github.com/win0na/apw/compare/v0.3.0...v0.5.0
