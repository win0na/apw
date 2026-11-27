#!/usr/bin/env bash
# Build a relocatable tarball: dist/apw-<version>-<host-target>.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
HOST_TARGET="$(rustc -vV | awk '/^host: /{print $2}')"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

NAME="apw-${VERSION}-${HOST_TARGET}"
STAGE="dist/${NAME}"
ARCHIVE="dist/${NAME}.tar.gz"

if [[ "${APW_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --release --locked
fi

BIN="${TARGET_DIR}/release/apw"
if [[ ! -x "$BIN" ]]; then
  echo "error: no release binary at $BIN (unset APW_SKIP_BUILD to build it)" >&2
  exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/docs"

install -m 0755 "$BIN" "$STAGE/bin/apw"
install -m 0644 LICENSE README.md "$STAGE/"
install -m 0644 docs/*.md "$STAGE/docs/"

rm -f "$ARCHIVE"
tar --owner=0 --group=0 --numeric-owner -czf "$ARCHIVE" -C dist "$NAME"

echo "$ARCHIVE"
