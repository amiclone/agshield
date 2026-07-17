#!/bin/bash
# Installation script for AntiGravity Shield (Linux)
# Installs the standalone executable and the agent package to system locations.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

INSTALL_BIN="/usr/local/bin/agshield"
INSTALL_DIR="/usr/local/share/agshield"
AGENT_DIR="$INSTALL_DIR/agent_package"

echo "=========================================="
echo "Installing AntiGravity Shield"
echo "=========================================="

# Check if we have sudo/root
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo bash $0"
    exit 1
fi

# Create installation directories
echo "[1/5] Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$AGENT_DIR"

# Copy agent scripts
echo "[2/5] Installing agent package..."
cp -r "$PROJECT_DIR/../agent_package/"* "$AGENT_DIR/"

# Copy executable
echo "[3/5] Installing executable..."
cp "$PROJECT_DIR/dist/agshield" "$INSTALL_BIN"
chmod +x "$INSTALL_BIN"

# Also install as 'antigravity' alias
cp "$PROJECT_DIR/dist/agshield" "/usr/local/bin/antigravity"
chmod +x "/usr/local/bin/antigravity"

# Create default config if not exists
echo "[4/5] Creating default config..."
mkdir -p /etc/agravity 2>/dev/null || mkdir -p /etc/antigravity
if [ ! -f /etc/antigravity/config.yaml ]; then
    cp "$PROJECT_DIR/config/default.yaml" /etc/antigravity/config.yaml
fi

# Verify
echo "[5/5] Verifying installation..."
if command -v agshield &> /dev/null; then
    echo ""
    echo "=========================================="
    echo "✅ INSTALLATION SUCCESSFUL"
    echo "=========================================="
    echo "Executable: $INSTALL_BIN"
    echo "Agent package: $AGENT_DIR"
    echo "Config: /etc/antigravity/config.yaml"
    echo ""
    echo "Usage:"
    echo "  agshield start --watch /home --watch /tmp"
    echo "  agshield status"
    echo "  agshield stop"
    echo "=========================================="
else
    echo "❌ INSTALLATION FAILED"
    exit 1
fi
