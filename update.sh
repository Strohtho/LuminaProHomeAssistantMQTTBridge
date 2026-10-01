#!/usr/bin/env bash
# ==============================================================================
# Leviton Lumina Pro to Home Assistant MQTT Bridge - Automated Updater
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="lumina-bridge.service"

echo "=========================================================="
echo " Updating Leviton Lumina Pro MQTT Bridge"
echo "=========================================================="

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[-] ERROR: This script must be run as root (or with sudo)." >&2
    echo "    Usage: sudo ./update.sh" >&2
    exit 1
fi

cd "$SCRIPT_DIR"

# Configure git safe.directory to avoid dubious ownership warnings
git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true

# 1. Git pull while protecting local config.json
if [ -d ".git" ]; then
    echo "[*] Pulling latest updates from GitHub..."
    # Preserve local config modifications
    CONFIG_BACKUP=""
    if [ -f "config.json" ]; then
        CONFIG_BACKUP=$(mktemp)
        cp config.json "$CONFIG_BACKUP"
    fi

    # Stash any local working tree changes if needed
    git stash --quiet 2>/dev/null || true
    git pull origin main

    # Restore local config if it existed
    if [ -n "$CONFIG_BACKUP" ] && [ -f "$CONFIG_BACKUP" ]; then
        cp "$CONFIG_BACKUP" config.json
        rm -f "$CONFIG_BACKUP"
    fi
    echo "[+] Repository updated."
else
    echo "[*] Not a git clone directory; skipping git pull."
fi

# 2. Update Python virtual environment dependencies
if [ -d "$SCRIPT_DIR/venv" ]; then
    echo "[*] Updating Python packages in virtual environment..."
    "$SCRIPT_DIR/venv/bin/pip" install --upgrade pip --quiet
    "$SCRIPT_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" --quiet
    echo "[+] Python dependencies up to date."
else
    echo "[!] Virtual environment not found; creating one..."
    python3 -m venv "$SCRIPT_DIR/venv"
    "$SCRIPT_DIR/venv/bin/pip" install --upgrade pip
    "$SCRIPT_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
fi

# 3. Update systemd service file if changed
if [ -f "$SCRIPT_DIR/$SERVICE_NAME" ]; then
    cp "$SCRIPT_DIR/$SERVICE_NAME" /etc/systemd/system/"$SERVICE_NAME"
    systemctl daemon-reload
fi

# 4. Fix permissions
chown -R lumina:lumina "$SCRIPT_DIR"
chmod 755 "$SCRIPT_DIR"
chmod +x "$SCRIPT_DIR/lumina_bridge.py"
chmod +x "$SCRIPT_DIR/install.sh" || true
chmod +x "$SCRIPT_DIR/update.sh" || true
if [ -f "$SCRIPT_DIR/config.json" ]; then
    chmod 600 "$SCRIPT_DIR/config.json"
fi

# 5. Restart service
echo "[*] Restarting $SERVICE_NAME..."
systemctl restart "$SERVICE_NAME"
sleep 2

echo ""
systemctl status "$SERVICE_NAME" --no-pager || true

echo ""
echo "=========================================================="
echo " Update Complete!"
echo " Check live logs with: sudo journalctl -u $SERVICE_NAME -f"
echo "=========================================================="
