#!/bin/bash
set -e

if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

CURRENT_USER=$(logname 2>/dev/null || echo $SUDO_USER || echo $USER)

if lsof -i :53 &>/dev/null; then
  echo -e "\033[0;31m❌ Port 53 is already in use. DNSBox requires port 53 for UDP and TCP.\033[0m"
  echo ""
  lsof -i :53 | awk 'NR==1 || /LISTEN/'
  echo ""
  echo "🚫 Aborting installation."
  exit 1
fi

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
