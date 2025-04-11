#!/bin/bash
set -e

SERVICE_NAME="dnsbox"
INSTALL_DIR="$HOME/.dnsbox"
BIN_NAME="dnsboxd"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

# Detect sudo or root
if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "🧹 Removing DNSBox..."

# Stop and disable the systemd service
if systemctl list-units --type=service | grep -q "$SERVICE_NAME"; then
  echo "🛑 Stopping systemd service..."
  $SUDO systemctl stop $SERVICE_NAME || true
  $SUDO systemctl disable $SERVICE_NAME || true
  $SUDO rm -f "$SERVICE_FILE"
  $SUDO systemctl daemon-reload
  echo "✅ Systemd service removed."
else
  echo "ℹ️ Service not found — skipping."
fi

# Remove binary and working directory
if [[ -d "$INSTALL_DIR" ]]; then
  echo "🗑️ Removing installation directory: $INSTALL_DIR..."
  rm -rf "$INSTALL_DIR"
  echo "✅ Directory deleted: $INSTALL_DIR"
else
  echo "ℹ️ Installation directory not found — skipping."
fi

# Delete journald logs for this specific service
echo "🧼 Cleaning up journald logs for $SERVICE_NAME..."
$SUDO journalctl --quiet --rotate
$SUDO journalctl --quiet --flush
$SUDO journalctl --quiet --vacuum-time=1s

# Wipe persistent journal logs that contain the service name
LOG_PATH="/var/log/journal"
if [[ -d "$LOG_PATH" ]]; then
  $SUDO find "$LOG_PATH" -type f -exec grep -l "$SERVICE_NAME" {} + | while read -r file; do
    echo "🧨 Truncating log file: $file"
    $SUDO truncate -s 0 "$file"
  done
fi

# Clear journald runtime cache and restart daemon
echo "♻️ Restarting systemd-journald and clearing runtime cache..."
$SUDO systemctl restart systemd-journald
$SUDO rm -rf /run/log/journal/*
echo "✅ Journald restarted and cache cleared."

# Final message
echo -e "\033[1;32m✅ DNSBox has been fully uninstalled. All related logs and cache have been cleaned.\033[0m"
