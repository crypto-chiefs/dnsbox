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
  echo "✅ Service removed."
else
  echo "ℹ️ Service not found — skipping."
fi

# Remove binary and working directory
if [[ -d "$INSTALL_DIR" ]]; then
  echo "🗑️ Removing directory $INSTALL_DIR..."
  rm -rf "$INSTALL_DIR"
  echo "✅ Deleted: $INSTALL_DIR"
else
  echo "ℹ️ Directory $INSTALL_DIR not found — skipping."
fi

# Final message
echo -e "\033[1;32m✅ DNSBox has been completely uninstalled.\033[0m"
