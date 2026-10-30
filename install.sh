#!/usr/bin/env sh
# Universal one-line installer for Custos (`custos`)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/george-amir/Custos/main/install.sh | sh

set -eu

REPO="george-amir/Custos"
BIN_NAME="custos"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
      *) echo "Unsupported Linux architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *) echo "Unsupported macOS architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS (use PowerShell or Cargo on Windows)" >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -eq 0 ]; then
  INSTALL_DIR="/usr/local/bin"
elif [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

ARCHIVE_URL="https://github.com/${REPO}/releases/latest/download/${BIN_NAME}-${TARGET}.tar.gz"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Installing Custos (${BIN_NAME}) for ${TARGET}..."

if curl -fsSL "$ARCHIVE_URL" -o "$TMP_DIR/${BIN_NAME}.tar.gz" 2>/dev/null; then
  tar -xzf "$TMP_DIR/${BIN_NAME}.tar.gz" -C "$TMP_DIR"
  install -m 0755 "$TMP_DIR/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  echo "==> Installed prebuilt binary to ${INSTALL_DIR}/${BIN_NAME}"
elif command -v cargo >/dev/null 2>&1; then
  echo "==> Prebuilt release archive not found yet; building with Cargo..."
  cargo install --git "https://github.com/${REPO}.git" --locked
  echo "==> Installed ${BIN_NAME} via Cargo"
else
  echo "Error: Could not download release archive from ${ARCHIVE_URL} and 'cargo' is not installed." >&2
  exit 1
fi

echo ""
echo "Custos is ready! Quick start:"
echo "  1. Generate config & auto-detect OS firewall/logs : custos init"
echo "  2. Start the Custos daemon                        : custos run"
