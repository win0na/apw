# Packaging

Four artifacts, all built from a release binary.

| Artifact | Source | Output |
| --- | --- | --- |
| Tarball | `packaging/tarball.sh` | `dist/apw-0.1.2-<host-target>.tar.gz` |
| Debian package | `packaging/debian/build.sh` | `dist/apw_0.1.2_<arch>.deb` |
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

- `packaging/aur/PKGBUILD` carries `sha256sums=('SKIP')`. Replace it with the
  release checksum (`updpkgsums`) before submitting to the AUR.
- The AUR `check()` runs the test suite with `--offline`; it needs no network.
- `flake.nix` pins `nixos-unstable` and has no `flake.lock` committed.
- The AUR source points at the `v0.1.2` tag, which must exist on the remote
  before `makepkg` can fetch it.
