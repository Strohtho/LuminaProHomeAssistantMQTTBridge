#!/usr/bin/env bash
# ==============================================================================
# Leviton Lumina Pro to Home Assistant MQTT Bridge - Automated Debian Installer
# ==============================================================================
set -euo pipefail

INSTALL_DIR="/opt/lumina-bridge"
SERVICE_NAME="lumina-bridge.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo " Leviton Lumina Pro MQTT Bridge - Debian/Proxmox Installer"
echo "=========================================================="

# 1. Root / Sudo check
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[-] ERROR: This script must be run as root (or with sudo)." >&2
    echo "    Usage: sudo ./install.sh" >&2
    exit 1
fi

# 2. Package Manager Verification & Dependency Installation
echo "[*] Checking and installing system dependencies via apt..."
if ! command -v apt-get >/dev/null 2>&1; then
    echo "[-] ERROR: apt-get not found. This installer is designed for Debian/Ubuntu." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip git curl

echo "[+] System dependencies installed."

# 3. Create dedicated system user
echo "[*] Ensuring system user 'lumina' exists..."
if ! id -u lumina >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" -M lumina
    echo "[+] Created service user: lumina"
else
    echo "[+] User 'lumina' already exists."
fi

# 4. Setup Target Installation Directory
echo "[*] Setting up installation in $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    echo "[*] Copying project files from $SCRIPT_DIR to $INSTALL_DIR..."
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR"/ || true
    # Also copy hidden files like .git if present to allow git updates
    if [ -d "$SCRIPT_DIR/.git" ]; then
        cp -r "$SCRIPT_DIR/.git" "$INSTALL_DIR"/ || true
    fi
fi

cd "$INSTALL_DIR"

# 5. Setup Python Virtual Environment
echo "[*] Creating Python virtual environment in $INSTALL_DIR/venv..."
python3 -m venv "$INSTALL_DIR/venv"

echo "[*] Installing Python packages from requirements.txt..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
echo "[+] Python virtual environment ready."

# 6. Initialize config.json
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    if [ -f "$INSTALL_DIR/config.example.json" ]; then
        echo "[*] Creating config.json from config.example.json..."
        cp "$INSTALL_DIR/config.example.json" "$INSTALL_DIR/config.json"
    fi
fi

# 7. Secure File Permissions
echo "[*] Setting secure file permissions..."
chown -R lumina:lumina "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/lumina_bridge.py"
chmod +x "$INSTALL_DIR/install.sh" || true
chmod +x "$INSTALL_DIR/update.sh" || true
if [ -f "$INSTALL_DIR/config.json" ]; then
    chmod 600 "$INSTALL_DIR/config.json"
fi

# 8. Install and Enable Systemd Service
echo "[*] Installing systemd service..."
cp "$INSTALL_DIR/lumina-bridge.service" /etc/systemd/system/"$SERVICE_NAME"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo "[+] Service '$SERVICE_NAME' enabled on boot."

# 9. Check configuration and start
KEY_CHECK=""
if [ -f "$INSTALL_DIR/config.json" ]; then
    KEY_CHECK=$(grep -E '"key":\s*"11111111111111111111111111111111"|"key":\s*"00112233445566778899AABBCCDDEEFF"' "$INSTALL_DIR/config.json" || true)
fi

echo ""
echo "=========================================================="
echo " Installation Complete!"
echo "=========================================================="
echo "Installation Directory: $INSTALL_DIR"
echo "Service Name:           $SERVICE_NAME"
echo ""

if [ -n "$KEY_CHECK" ]; then
    echo "⚠️  NOTE: $INSTALL_DIR/config.json still contains a placeholder key!"
    echo "   Before starting the service, edit your configuration:"
    echo "   sudo nano $INSTALL_DIR/config.json"
    echo ""
    echo "   Set your Lumina Pro IP, 16-byte hex encryption key, and MQTT broker IP."
    echo "   Then start the service with:"
    echo "   sudo systemctl start $SERVICE_NAME"
else
    echo "[*] Starting $SERVICE_NAME..."
    systemctl restart "$SERVICE_NAME"
    sleep 2
    systemctl status "$SERVICE_NAME" --no-pager || true
fi

echo ""
echo "Useful Commands:"
echo "  View live logs:   sudo journalctl -u $SERVICE_NAME -f"
echo "  Restart service:  sudo systemctl restart $SERVICE_NAME"
echo "  Check status:     sudo systemctl status $SERVICE_NAME"
echo "  Easy updates:     cd $INSTALL_DIR && sudo ./update.sh"
echo "=========================================================="
