#!/usr/bin/env bash
# Build a Debian package: dist/apw_<version>_<arch>.deb
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
ARCH="$(dpkg --print-architecture)"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

STAGE="dist/debian/apw_${VERSION}_${ARCH}"
DEB="dist/apw_${VERSION}_${ARCH}.deb"

if [[ "${APW_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --release --locked
fi

BIN="${TARGET_DIR}/release/apw"
if [[ ! -x "$BIN" ]]; then
  echo "error: no release binary at $BIN (unset APW_SKIP_BUILD to build it)" >&2
  exit 1
fi

HOST_TARGET="$(rustc -vV | awk '/^host: /{print $2}')"
case "$HOST_TARGET" in
  x86_64-unknown-linux-gnu) LIB_PLATFORM=x86_64-linux ;;
  aarch64-unknown-linux-gnu) LIB_PLATFORM=aarch64-linux ;;
  *) echo "error: no OpenTUI library for $HOST_TARGET" >&2; exit 1 ;;
esac
LIB="${OPENTUI_LIB_DIR:-${ROOT}/opentui/packages/native/lib/${LIB_PLATFORM}}/libopentui.so"
if [[ ! -f "$LIB" ]]; then
  echo "error: no OpenTUI library at $LIB" >&2
  exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/lib/apw" "$STAGE/usr/share/doc/apw"

install -m 0755 "$BIN" "$STAGE/usr/bin/apw"
# The executable finds this at $ORIGIN/../lib/apw.
install -s -m 0755 "$LIB" "$STAGE/usr/lib/apw/libopentui.so"
install -m 0644 README.md LICENSE "$STAGE/usr/share/doc/apw/"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: apw
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: win0na <winona@winneon.moe>
Section: utils
Priority: optional
Homepage: https://github.com/win0na/apw
Depends: libc6, libgcc-s1, libdbus-1-3
Description: read Apple Passwords on Linux
  apw keeps an encrypted local snapshot of Apple Passwords and answers
  queries offline from a single Rust binary, so the keychain is readable
  from a Linux terminal without a browser or a running desktop session.
EOF

cat > "$STAGE/usr/share/doc/apw/changelog" <<EOF
apw (${VERSION}) unstable; urgency=medium

  * Initial release.

 -- win0na <winona@winneon.moe>  $(date -R)
EOF

mkdir -p dist
rm -f "$DEB"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB"

echo "$DEB"
