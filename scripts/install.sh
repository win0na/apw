#!/bin/sh
# Install apw from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/win0na/apw/main/scripts/install.sh | sh
#
# Options:
#   --prefix DIR     install under DIR (default: $APW_PREFIX or ~/.local)
#   --version TAG    install a specific release tag (default: newest release)
#   -h, --help       show this text
set -eu

REPO=win0na/apw
PREFIX=${APW_PREFIX:-$HOME/.local}
VERSION=${APW_VERSION:-}

die() {
    echo "apw: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Install apw from a GitHub release.

  curl -fsSL https://raw.githubusercontent.com/win0na/apw/main/scripts/install.sh | sh

Options:
  --prefix DIR     install under DIR (default: $APW_PREFIX or ~/.local)
  --version TAG    install a specific release tag (default: newest release)
  -h, --help       show this text
EOF
}

while [ $# -gt 0 ]; do
    case $1 in
        --prefix)
            [ $# -ge 2 ] || die "--prefix needs a directory"
            PREFIX=$2
            shift 2
            ;;
        --version)
            [ $# -ge 2 ] || die "--version needs a tag such as v0.5.1"
            VERSION=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

for tool in curl tar sha256sum install; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

case $(uname -m) in
    x86_64|amd64) target=x86_64-unknown-linux-gnu ;;
    aarch64|arm64)
        die "no aarch64 release yet; build from source:
  cargo install --git https://github.com/$REPO --locked"
        ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
    # `releases/latest` skips pre-releases, so fall back to the API while the
    # newest release is one.
    latest=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest" 2>/dev/null || true)
    VERSION=${latest##*/}
    case $VERSION in
        v[0-9]*) ;;
        *)
            VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=1" 2>/dev/null |
                sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
            ;;
    esac
fi
case $VERSION in
    v[0-9]*) ;;
    *) die "cannot find a release; pass --version vX.Y.Z" ;;
esac

number=${VERSION#v}
archive="apw-$number-$target.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "apw: downloading $archive"
curl -fsSL "$base/$archive" -o "$tmp/$archive" ||
    die "no $archive in $VERSION"
curl -fsSL "$base/$archive.sha256" -o "$tmp/$archive.sha256" ||
    die "no checksum for $archive in $VERSION"
(cd "$tmp" && sha256sum -c "$archive.sha256" >/dev/null) ||
    die "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp"
tree="$tmp/apw-$number-$target"
[ -x "$tree/bin/apw" ] || die "archive has no bin/apw"

install -d "$PREFIX/bin"
install -m 0755 "$tree/bin/apw" "$PREFIX/bin/apw"

if "$PREFIX/bin/apw" --version >/dev/null 2>&1; then
    echo "apw: installed $PREFIX/bin/apw ($("$PREFIX/bin/apw" --version))"
else
    echo "apw: installed $PREFIX/bin/apw, but it did not start" >&2
    echo "apw: check that glibc and libdbus-1 are present" >&2
fi

case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "apw: add $PREFIX/bin to PATH, then run: apw login" ;;
esac
