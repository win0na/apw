# Changelog

Changes worth knowing between releases. 0.5.0 covers everything since `v0.3.0`;
0.4.0 was never tagged.

## [Unreleased]

### Changed

- The terminal interface is rebuilt on opencode's chrome and the terminal
  System palette: a single `┃` rail, flat dialogs on a scrim, one line per item
  with an inline description and right-aligned metadata, a 12-cell detail label
  column, a grouped command palette, and footer hints drawn from the live keys.
- The dashboard is a centered column: wordmark, status, counts, prompt, then
  `Recent`. The category strip carries counts and overflow markers.

### Fixed

- Closing the command palette restores the prompt and footer instead of leaving
  the search bar over the page. Help and forms return the layout to the base
  screen.
- Dialogs dim the page behind a full-screen scrim and hide the prompt and app
  footer while they are open.
- The command palette scrolls to the selected row and shows a scrollbar, so
  every command is reachable on short terminals.
- Forms scroll their field area on short terminals and keep the action band and
  hints in place.
- Help no longer draws the search bar over its body or clips its last group,
  and `enter` closes it back to the screen that opened it.
- Footer hints drop whole key and label pairs at narrow widths instead of
  leaving bare keys.
- Copy actions report success or a missing value in a toast.

## [0.5.1] - 2026-11-27

### Changed

- OpenTUI is linked statically. The executable is self-contained, so
  `cargo install --git` works in one command and packages no longer install
  `libopentui.so`. The stripped executable is 8.9 MB.
- The install script, README, and docs present the install script, Cargo, and
  package managers as one-line installs, with the terminal interface first.

### Fixed

- The install script finds the newest release when it is a pre-release.

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

[0.5.1]: https://github.com/win0na/apw/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/win0na/apw/compare/v0.3.0...v0.5.0
