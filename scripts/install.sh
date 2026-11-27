#!/bin/sh
# Install apw from a GitHub release: the executable and libopentui.so.
#
#   curl -fsSL https://github.com/win0na/apw/releases/latest/download/install.sh | sh
#
# Options:
#   --prefix DIR     install under DIR (default: $APW_PREFIX or ~/.local)
#   --version TAG    install a specific release tag (default: latest)
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
Install apw from a GitHub release: the executable and libopentui.so.

  curl -fsSL https://github.com/win0na/apw/releases/latest/download/install.sh | sh

Options:
  --prefix DIR     install under DIR (default: $APW_PREFIX or ~/.local)
  --version TAG    install a specific release tag (default: latest)
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
            [ $# -ge 2 ] || die "--version needs a tag such as v0.5.0"
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
  git clone --recurse-submodules https://github.com/$REPO
  cd apw && cargo install --path . --locked"
        ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
    latest=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest") ||
        die "cannot reach github.com"
    VERSION=${latest##*/}
fi
case $VERSION in
    v[0-9]*) ;;
    *) die "not a release tag: $VERSION" ;;
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
[ -f "$tree/lib/apw/libopentui.so" ] || die "archive has no lib/apw/libopentui.so"

install -d "$PREFIX/bin" "$PREFIX/lib/apw"
install -m 0755 "$tree/bin/apw" "$PREFIX/bin/apw"
install -m 0755 "$tree/lib/apw/libopentui.so" "$PREFIX/lib/apw/libopentui.so"

if "$PREFIX/bin/apw" --version >/dev/null 2>&1; then
    echo "apw: installed $PREFIX/bin/apw ($("$PREFIX/bin/apw" --version))"
else
    echo "apw: installed $PREFIX/bin/apw, but it did not start" >&2
    echo "apw: check that glibc and libdbus-1 are present" >&2
fi

case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *)
        echo "apw: add $PREFIX/bin to PATH, then run: apw login"
        ;;
esac
