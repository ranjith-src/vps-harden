#!/usr/bin/env bash
# install.sh — Download and install vps-harden
# Usage: curl -fsSL https://raw.githubusercontent.com/ranjith-src/vps-harden/main/install.sh | bash
set -euo pipefail

REPO="ranjith-src/vps-harden"
BINARY_NAME="vps-harden"

# Determine install directory
if [[ $(id -u) -eq 0 ]]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo "Installing ${BINARY_NAME}..."

# Try to get latest release tag from GitHub API
LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | sed 's/.*"\(.*\)".*/\1/' || true)

DOWNLOADED=false

if [[ -n "$LATEST_TAG" ]]; then
    echo "Latest release: ${LATEST_TAG}"
    RELEASE_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/vps-harden.sh"
    if curl -fsSL "$RELEASE_URL" -o "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null; then
        DOWNLOADED=true
    fi
fi

if [[ "$DOWNLOADED" != "true" ]]; then
    echo "Downloading from main branch..."
    if ! curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/vps-harden.sh" -o "${INSTALL_DIR}/${BINARY_NAME}"; then
        echo "Error: Failed to download ${BINARY_NAME}" >&2
        exit 1
    fi
fi

chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

echo ""
echo "Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
echo ""

# Check if install dir is in PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo "NOTE: ${INSTALL_DIR} is not in your PATH."
    echo "Add it with:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
fi

echo "Usage:"
echo "  sudo ${BINARY_NAME}                # interactive setup wizard"
echo "  sudo ${BINARY_NAME} --help         # all options"
