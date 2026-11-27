# AGENTS.md

Rules for docs and releases in this repository. Build, test, fixtures, and the
live gate are in [CONTRIBUTING.md](CONTRIBUTING.md); do not repeat them here.

## Voice

- MUST write the README and docs pages in the house voice. With the ghostwriter
  skill, read `~/.config/ghostwriter/soul.md`, then `readme.md` for the README
  and `docs.md` for docs pages. Without it: plain, concrete, evidence beside the
  claim.
- MUST NOT use marketing adjectives, "simply", "just", "easy", emoji,
  exclamation marks, or em dashes.
- MUST describe the interface action first (`/login`, `/sync`, a key) and the
  command-line equivalent second; the CLI serves scripts and the timer.
- MUST cut a sentence that restates the title or the heading.

## README

- MUST open with the app icon and `apw` in an `h1`, one sentence on what the
  tool does, one real screenshot or demo, then `## Install`.
- MUST order install: `scripts/install.sh` first, a source build with Cargo
  second, package managers last, each as a single copyable command.
- MUST present the terminal interface first and the command line second.
- MUST name only real things: package names (the `apw` Debian package, the
  `apw-cli` AUR package, the Nix flake), flags, files, and versions that exist
  in this tree.
- MUST keep the README under 90 lines; detail belongs in `docs/`.
- MUST capture the screenshot from the fixture vault in a clean HOME, never from
  the live vault.
- MUST NOT show a mockup, a placeholder, or a screenshot from an unbuilt tree.
- MUST give every image alt text and a path under `assets/`.

## Docs

- MUST keep one job per page and the existing filenames: `design.md`,
  `install.md`, `operate.md`, `reference.md`, `secrets.md`, `troubleshooting.md`.
- MUST keep exact paths, flags, defaults, versions, and limits, and change them
  in the same change as the code.
- MUST resolve every link and anchor, and link to the page that owns the detail
  instead of repeating it.
- MUST NOT publish "coming soon", a dated plan, or an empty section.
- MUST update `docs/install.md` when the install layout, build requirements, or
  package names change.

## Releases

- MUST keep the version in `Cargo.toml`, the tag `vX.Y.Z`, and the
  `CHANGELOG.md` section `## [X.Y.Z]` equal.
- MUST write the release body from that CHANGELOG section. The workflow does
  this and appends the full-history link.
- MUST publish a pre-release until the maintainer says otherwise.
- MUST attach the versioned tarball, the Debian package, a `.sha256` for each,
  and `install.sh` to the release.
- MUST keep `scripts/install.sh` checksum-verified, x86_64, and honest: on
  aarch64 it stops and points at a source build.
- MUST keep the executable self-contained: OpenTUI is linked statically and no
  runtime library is installed beside the binary.
- MUST NOT advertise a package or asset the release does not produce.

## Verify

Before a release or a docs change:

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
sh -n scripts/install.sh
```

- Version consistency: `git describe --tags --exact-match` equals
  `v$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml)`.
- Stale version strings: `rg -n '<old version>' Cargo.toml Cargo.lock README.md
  CHANGELOG.md docs packaging` returns nothing.
- Links: `rg -o '\]\([^)]*\)' README.md docs/*.md` lists every target; open
  each relative one.
- Install: `cargo install --path . --force`, copy the OpenTUI library to
  `${CARGO_HOME:-$HOME/.cargo}/lib/apw/`, then run `apw --version` from `/`.
- Packaging: `packaging/tarball.sh` and `packaging/debian/build.sh` exit 0 and
  produce the names below.

| Artifact | Name |
| --- | --- |
| Tarball | `apw-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Debian | `apw_<version>_amd64.deb` |
| Checksum | `<artifact>.sha256` |
| Installer | `install.sh` |

## Changing these rules

Change this file only with the maintainer's agreement, and update the verifiers
in the same change.
