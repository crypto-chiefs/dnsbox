#!/bin/bash
set -e

# Parse args
FORCE_RESOLV=0
IP=""
DOMAIN=""
NS_NAME=""
for arg in "$@"; do
  case $arg in
    --force-resolv) FORCE_RESOLV=1 ;;
    --ip=*) IP="${arg#*=}" ;;
    --domain=*) DOMAIN="${arg#*=}" ;;
    --ns=*) NS_NAME="${arg#*=}" ;;
  esac
done

if [[ -z "$IP" || -z "$DOMAIN" || -z "$NS_NAME" ]]; then
  echo -e "\033[0;31m❌ Missing --ip or --domain or --ns.\033[0m"
  echo ""
  echo "👉 Example usage:"
  echo -e "   \033[1;36mbash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3\033[0m"
  exit 1
fi

# Detect sudo or root
if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

CURRENT_USER=$(logname 2>/dev/null || echo $SUDO_USER || echo $USER)

# Check port 53
if lsof -i :53 &>/dev/null; then
  if [[ "$FORCE_RESOLV" -eq 1 ]]; then
    echo -e "\033[1;33m⚠️ Port 53 is in use. Attempting to fix via --force-resolv...\033[0m"

    if systemctl list-units --type=service | grep -q systemd-resolved.service; then
      echo "🛑 Disabling systemd-resolved..."
      $SUDO systemctl stop systemd-resolved || true
      $SUDO systemctl disable systemd-resolved || true
    else
      echo "ℹ️ systemd-resolved not found — skipping"
    fi

    $SUDO rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" | $SUDO tee /etc/resolv.conf
    echo -e "\033[1;32m✅ fallback DNS set to 8.8.8.8\033[0m"
  else
    echo -e "\033[0;31m❌ Port 53 is already in use. DNSBox requires port 53 for UDP and TCP.\033[0m"
    echo ""
    lsof -i :53 | awk 'NR==1 || /LISTEN/'
    echo ""
    echo "👉 Re-run with \033[1;36m--force-resolv\033[0m to automatically disable systemd-resolved"
    echo "🚫 Aborting installation."
    exit 1
  fi
fi

# Setup
REPO="crypto-chiefs/dnsbox"
SERVICE_NAME="dnsbox"
ARCHIVE_PREFIX="dnsbox"
BIN_NAME="dnsboxd"
INSTALL_DIR="$HOME/.dnsbox"

UNAME=$(uname | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "❌ Unsupported architecture: $ARCH" && exit 1 ;;
esac

case "$UNAME" in
  linux|darwin) GOOS="$UNAME" ;;
  msys*|mingw*|cygwin*) GOOS="windows" ;;
  *) echo "❌ Unsupported OS: $UNAME" && exit 1 ;;
esac

ARCHIVE_NAME="$ARCHIVE_PREFIX-$GOOS-$ARCH.tar.gz"
RELEASE_URL="https://github.com/$REPO/releases/latest/download/$ARCHIVE_NAME"
UNIT_URL="https://raw.githubusercontent.com/$REPO/main/systemd/dnsbox.service"

echo "🌀 Installing $BIN_NAME for $GOOS/$ARCH from $RELEASE_URL"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
curl -L "$RELEASE_URL" | tar -xz
chmod +x "$BIN_NAME"

# Ensure cert storage dir exists with proper permissions
CERT_DIR="/var/lib/dnsbox/certs"

if [[ -d "$CERT_DIR" ]]; then
  echo "📁 Found existing cert directory: $CERT_DIR"
  # Check permissions
  PERMS=$(stat -c "%a" "$CERT_DIR")
  OWNER=$(stat -c "%U" "$CERT_DIR")
  if [[ "$PERMS" != "700" || "$OWNER" != "$CURRENT_USER" ]]; then
    echo "🔒 Fixing permissions for $CERT_DIR"
    $SUDO chown -R "$CURRENT_USER:$CURRENT_USER" "$CERT_DIR"
    $SUDO chmod -R 700 "$CERT_DIR"
  fi
else
  echo "📁 Creating cert directory: $CERT_DIR"
  $SUDO mkdir -p "$CERT_DIR"
  $SUDO chown -R "$CURRENT_USER:$CURRENT_USER" "$CERT_DIR"
  $SUDO chmod -R 700 "$CERT_DIR"
  echo "✅ Created and secured $CERT_DIR"
fi

if [[ "$GOOS" == "linux" ]]; then
  echo "⚙️ Setting up systemd..."

  SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
  TMP_UNIT="/tmp/$SERVICE_NAME.service"

  echo "📥 Downloading unit template..."
  curl -sL "$UNIT_URL" -o "$TMP_UNIT"

  echo "🔧 Replacing placeholders..."
  BIN_ABS_PATH="$INSTALL_DIR/$BIN_NAME"
  WORKDIR="$INSTALL_DIR"

  $SUDO sed -e "s|{{BIN_PATH}}|$BIN_ABS_PATH|g" \
            -e "s|{{WORKDIR}}|$WORKDIR|g" \
            -e "s|{{USER}}|$CURRENT_USER|g" \
            -e "s|{{IP}}|$IP|g" \
            -e "s|{{DOMAIN}}|$DOMAIN|g" \
            -e "s|{{NS_NAME}}|$NS_NAME|g" \
            "$TMP_UNIT" | $SUDO tee "$SERVICE_FILE" > /dev/null

  echo "✅ Unit installed: $SERVICE_FILE"

  $SUDO systemctl daemon-reexec
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable $SERVICE_NAME
  $SUDO systemctl restart $SERVICE_NAME

  echo "📦 DNSBox started: systemctl status $SERVICE_NAME"

else
  echo "🍎 Manual run: $INSTALL_DIR/$BIN_NAME"
fi
