# Packaging

Four artifacts, all built from a release binary.

| Artifact | Source | Output |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.2.1-<host-target>.tar.gz` |
| Debian package | `packaging/debian/build.sh` | `dist/apw_0.2.1_<arch>.deb` |
| AUR | `packaging/aur/PKGBUILD` | `makepkg -si` output |
| Nix flake | `flake.nix` | `nix build` output |

## Build commands

```sh
packaging/tarball.sh
packaging/debian/build.sh
```

Both scripts build with `cargo build --release --locked` first. Set `APW_SKIP_BUILD=1` to reuse an existing `target/release/apw`; the scripts honour `CARGO_TARGET_DIR`.

```sh
cd packaging/aur && makepkg -si
nix build
```

The binary links `libdbus-1` for the Secret Service backend. The Debian package declares `libdbus-1-3`; the AUR recipe declares `dbus` and builds with `dbus`, `cmake`, and `perl` as makedepends; the flake uses `dbus` as a build input.

## Notes

- The package is published on the AUR as `apw-cli`, version 0.2.0-1. The binary is `/usr/bin/apw`; the recipe declares `provides=('apw')` and `conflicts=('apw')` because an unrelated wrapper already owns that path.
- On a release, tag first, then run `updpkgsums` and regenerate `.SRCINFO` with `makepkg --printsrcinfo`, then push both to `ssh://aur@aur.archlinux.org/apw-cli.git`. The checksum in both files must match the `vX.Y.Z` archive.
- Arch's `LDFLAGS` break the aws-lc static link, so `build()` and `check()` clear them for cargo. The tests are not run offline: `build()` does not fetch dev-dependencies.
- `flake.nix` pins `nixos-unstable`; `flake.lock` is committed.
