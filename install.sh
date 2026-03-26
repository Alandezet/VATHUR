#!/data/data/com.termux/files/usr/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║  VATHUR — one-command installer for Termux               ║
# ║  Usage: curl -fsSL https://raw.githubusercontent.com/    ║
# ║         YOUR_USER/vathur/main/install.sh | bash          ║
# ╚══════════════════════════════════════════════════════════╝

set -e

REPO="https://raw.githubusercontent.com/Alandezet/VATHUR/main"
INSTALL_DIR="$HOME/vathur"

echo ""
echo "  ██╗   ██╗ █████╗ ████████╗██╗  ██╗██╗   ██╗██████╗ "
echo "  ██║   ██║██╔══██╗╚══██╔══╝██║  ██║██║   ██║██╔══██╗"
echo "  ██║   ██║███████║   ██║   ███████║██║   ██║██████╔╝"
echo "  ╚██╗ ██╔╝██╔══██║   ██║   ██╔══██║██║   ██║██╔══██╗"
echo "   ╚████╔╝ ██║  ██║   ██║   ██║  ██║╚██████╔╝██║  ██║"
echo "    ╚═══╝  ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝"
echo ""
echo "  encrypted · ephemeral · sovereign"
echo ""

# ── 1. Update & install deps ────────────────────────────────
echo "[1/4] Installing system packages..."
pkg update -y -q
pkg install -y -q python python-pip

# ── 2. Install Python deps ──────────────────────────────────
echo "[2/4] Installing Python packages..."
pip install -q flask cryptography requests

# ── 3. Download app files ───────────────────────────────────
echo "[3/3] Downloading Vathur..."
mkdir -p "$INSTALL_DIR/templates"

curl -fsSL "$REPO/app.py"                   -o "$INSTALL_DIR/app.py"
curl -fsSL "$REPO/templates/index.html"     -o "$INSTALL_DIR/templates/index.html"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo "  ✓ Vathur installed at $INSTALL_DIR"
echo ""
echo "  To start:"
echo "    cd ~/vathur && python app.py"
echo ""
echo "  Then open: http://localhost:5000"
echo ""
