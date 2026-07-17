#!/bin/bash
# Build script for AntiGravity Shield (Linux)
# Creates a standalone executable that can run on any Linux system
# without requiring Python or dependencies to be installed.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

cd "$PROJECT_DIR"

echo "=========================================="
echo "Building AntiGravity Shield (Linux)"
echo "=========================================="

# Check Python and pip
echo "[1/5] Checking dependencies..."
python3 --version
pip3 --version

# Install build dependencies
echo "[2/5] Installing build dependencies..."
pip3 install pyinstaller --break-system-packages 2>&1 | grep -E "(Successfully|already)" || true

# Install the package
echo "[3/5] Installing agshield package..."
pip3 install -e . --break-system-packages 2>&1 | grep -E "(Successfully|already)" || true

# Build with PyInstaller
echo "[4/5] Building executable..."
pyinstaller build_scripts/agshield_linux.spec \
    --clean \
    --noconfirm \
    --distpath dist \
    --workpath build

# Verify
echo "[5/5] Verifying build..."
if [ -f "dist/agshield" ]; then
    echo ""
    echo "=========================================="
    echo "✅ BUILD SUCCESSFUL"
    echo "=========================================="
    echo "Executable: $PROJECT_DIR/dist/agshield"
    echo "Size: $(du -h dist/agshield | cut -f1)"
    echo ""
    echo "Test it:"
    echo "  ./dist/agshield --version"
    echo "  ./dist/agshield --help"
    echo "=========================================="
else
    echo ""
    echo "=========================================="
    echo "❌ BUILD FAILED"
    echo "=========================================="
    exit 1
fi
