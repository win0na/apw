# Packaging

Four artifacts, all built from a release binary.

| Artifact | Source | Output |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.1.5-<host-target>.tar.gz` |
| Debian package | `packaging/debian/build.sh` | `dist/apw_0.1.5_<arch>.deb` |
| AUR | `packaging/aur/PKGBUILD` | `makepkg -si` output |
| Nix flake | `flake.nix` | `nix build` output |

## Build commands

```sh
packaging/tarball.sh
packaging/debian/build.sh
```

Both scripts build with `cargo build --release --locked` first. Set
`APW_SKIP_BUILD=1` to reuse an existing `target/release/apw`; the scripts honour
`CARGO_TARGET_DIR`.

```sh
cd packaging/aur && makepkg -si
nix build
```

## Notes

- The package is published on the AUR as `apw-cli`, version 0.1.5-2. The binary
  is still `/usr/bin/apw`; the recipe declares `conflicts=('apw')` because an
  unrelated wrapper already owns that path.
- On a release, run `updpkgsums` and regenerate `.SRCINFO` with
  `makepkg --printsrcinfo`, then push both to
  `ssh://aur@aur.archlinux.org/apw-cli.git`.
- Arch's `LDFLAGS` break the aws-lc static link, so `build()` and `check()`
  clear them for cargo. The tests are not run offline: `build()` does not fetch
  dev-dependencies.
- `flake.nix` pins `nixos-unstable` and has no `flake.lock` committed.
