#!/bin/sh
# Install the Fencer CLI from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Fencer-Security/cli/main/scripts/install.sh | sh
#
# Optional environment:
#   FENCER_CLI_VERSION   Version to install (default: latest)
#   FENCER_CLI_REPO      GitHub owner/name that hosts releases (default: Fencer-Security/cli)
#   FENCER_CLI_DIR       Install directory (default: ~/.local/bin, or /usr/local/bin if writable)
#   FENCER_CLI_SKIP_VERIFY  Set to 1 to skip checksum verification (not recommended)
set -eu

REPO="${FENCER_CLI_REPO:-Fencer-Security/cli}"
VERSION="${FENCER_CLI_VERSION:-latest}"
SKIP_VERIFY="${FENCER_CLI_SKIP_VERIFY:-0}"

uname_os() {
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
    linux) printf '%s\n' linux ;;
    darwin) printf '%s\n' darwin ;;
    mingw* | msys* | cygwin*) printf '%s\n' windows ;;
    *)
        echo "unsupported OS: $os" >&2
        exit 1
        ;;
    esac
}

uname_arch() {
    arch="$(uname -m)"
    case "$arch" in
    x86_64 | amd64) printf '%s\n' amd64 ;;
    aarch64 | arm64) printf '%s\n' arm64 ;;
    *)
        echo "unsupported architecture: $arch" >&2
        exit 1
        ;;
    esac
}

github_api() {
    url="$1"
    auth=""
    if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
        auth="Authorization: Bearer ${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    fi
    if [ -n "$auth" ]; then
        curl -fsSL -H "$auth" -H "Accept: application/vnd.github+json" "$url"
    else
        curl -fsSL -H "Accept: application/vnd.github+json" "$url"
    fi
}

download() {
    url="$1"
    dest="$2"
    auth=""
    if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
        auth="Authorization: Bearer ${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    fi
    if [ -n "$auth" ]; then
        curl -fsSL -H "$auth" -o "$dest" "$url"
    else
        curl -fsSL -o "$dest" "$url"
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "need sha256sum or shasum to verify checksums" >&2
        exit 1
    fi
}

install_dir() {
    if [ -n "${FENCER_CLI_DIR:-}" ]; then
        printf '%s\n' "$FENCER_CLI_DIR"
        return
    fi
    if [ -w /usr/local/bin ]; then
        printf '%s\n' /usr/local/bin
        return
    fi
    printf '%s\n' "${HOME}/.local/bin"
}

OS="$(uname_os)"
ARCH="$(uname_arch)"
if [ "$OS" = "windows" ]; then
    echo "This POSIX script does not support native Windows shells (Git Bash/MSYS/Cygwin)." >&2
    echo "Install with PowerShell instead:" >&2
    echo "  irm https://raw.githubusercontent.com/Fencer-Security/cli/main/scripts/install.ps1 | iex" >&2
    echo "(Windows Subsystem for Linux reports as linux and works with this script.)" >&2
    exit 1
fi

if [ "$VERSION" = "latest" ]; then
    VERSION="$(github_api "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -n 1)"
    if [ -z "$VERSION" ]; then
        echo "failed to resolve the latest Fencer CLI release from ${REPO}" >&2
        exit 1
    fi
fi
VERSION="${VERSION#v}"

ARCHIVE="fencer_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

download "${BASE}/${ARCHIVE}" "${TMP}/${ARCHIVE}"
download "${BASE}/SHA256SUMS" "${TMP}/SHA256SUMS"

if [ "$SKIP_VERIFY" != "1" ]; then
    expected="$(awk -v f="$ARCHIVE" '$2 == f {print $1}' "${TMP}/SHA256SUMS")"
    if [ -z "$expected" ]; then
        echo "no SHA256SUMS entry for ${ARCHIVE}" >&2
        exit 1
    fi
    actual="$(sha256_file "${TMP}/${ARCHIVE}")"
    if [ "$expected" != "$actual" ]; then
        echo "checksum mismatch for ${ARCHIVE}" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
fi

tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"
BIN="${TMP}/fencer"
if [ ! -x "$BIN" ]; then
    echo "archive did not contain an executable fencer binary" >&2
    exit 1
fi

DEST="$(install_dir)"
mkdir -p "$DEST"
install -m 0755 "$BIN" "${DEST}/fencer"

echo "Installed fencer ${VERSION} to ${DEST}/fencer"
"${DEST}/fencer" version || true
case ":$PATH:" in
*":${DEST}:"*) ;;
*) echo "Add ${DEST} to PATH to use the fencer command." ;;
esac
