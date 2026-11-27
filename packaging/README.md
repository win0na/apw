# Packaging

Four apw artifacts, all built from a release binary. Each one installs the
executable and `libopentui.so`; the executable loads the library from `lib/apw`
relative to itself.

| Artifact | Source | Output |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.4.0-<host-target>.tar.gz` |
| Debian package | `packaging/debian/build.sh` | `dist/apw_0.4.0_<arch>.deb` |
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
```

From the repository root:

```sh
nix build
```

The binary links `libdbus-1` for the Secret Service backend and loads
`libopentui.so` from `lib/apw`. The Debian package declares `libdbus-1-3` and
installs the library at `/usr/lib/apw`; the AUR recipe's makedepends are
`cargo`, `rust`, `dbus`, and `zig`; the flake uses `dbus` as a build input.

## Notes

- The AUR package is `apw-cli` (`ssh://aur@aur.archlinux.org/apw-cli.git`); `packaging/aur/` holds the tracked copies of `PKGBUILD` and `.SRCINFO`. The binary is `/usr/bin/apw`; the recipe declares `provides=('apw')` and `conflicts=('apw')` because an unrelated wrapper already owns that path.
- On a release, tag first, then run `updpkgsums` and regenerate `.SRCINFO` with `makepkg --printsrcinfo`, then push both to `ssh://aur@aur.archlinux.org/apw-cli.git`. The checksum in both files must match the `vX.Y.Z` archive.
- The TLS provider is ring, so the aws-lc archive and the Arch `LDFLAGS`
  workaround are gone. The tests run in the default profile because the release
  profile aborts on panic. The tests are not run offline: `build()` does not
  fetch dev-dependencies.
- Every installed layout puts `libopentui.so` in `lib/apw` beside the
  executable: `$ORIGIN/../lib/apw` is the runpath.
- `flake.nix` pins `nixos-unstable`; `flake.lock` is committed.
