#!/usr/bin/env bash
set -euo pipefail
umask 077

VERSION=v0.5.0
INSTALL_DIR="${HOME:?HOME must be set}/.dnsbox"
USE_SYSTEMD=auto
IP=""
DOMAIN=""
NS_NAME=ns1
TLS_MODE=acme
ALLOWED_CIDRS=""
DATA_DIR=""
DNS_LISTEN=:53
HTTPS_LISTEN=:443
API_LISTEN=127.0.0.1:8080
UPSTREAM_PORT=80
ACME_EMAIL=""
ACME_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory
DEBUG=false

usage() {
  cat <<'EOF'
Usage: bash install.sh --ip=ADDRESS --domain=ZONE [options]
  --version=v0.5.0              Release to download (never mixes release files)
  --install-dir=PATH            Installation directory (default ~/.dnsbox)
  --ns=ns1                     Nameserver label
  --tls-mode=acme|local         Public ACME or private local CA
  --allowed-cidrs=LIST          Comma-separated allowed backend networks
  --data-dir=PATH               Persistent data (default INSTALL_DIR/data)
  --dns-listen=ADDRESS:PORT     DNS UDP and TCP listener (default :53)
  --https-listen=ADDRESS:PORT   HTTPS listener (default :443)
  --api-listen=ADDRESS:PORT     Management listener (default 127.0.0.1:8080)
  --upstream-port=PORT          Backend HTTP port (default 80)
  --acme-email=EMAIL            ACME account contact
  --acme-directory=URL          ACME directory, e.g. staging
  --systemd | --no-systemd      Force service or manual installation
  --debug                      Enable debug logging
  --help
Existing dnsbox.env is preserved. Edit it to change an existing installation.
The installer never changes the machine's DNS resolver or firewall.
EOF
}
die() { printf '%s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --ip=*) IP=${arg#*=} ;;
    --domain=*) DOMAIN=${arg#*=} ;;
    --ns=*) NS_NAME=${arg#*=} ;;
    --version=*) VERSION=${arg#*=} ;;
    --install-dir=*) INSTALL_DIR=${arg#*=} ;;
    --tls-mode=*) TLS_MODE=${arg#*=} ;;
    --allowed-cidrs=*) ALLOWED_CIDRS=${arg#*=} ;;
    --data-dir=*) DATA_DIR=${arg#*=} ;;
    --dns-listen=*) DNS_LISTEN=${arg#*=} ;;
    --https-listen=*) HTTPS_LISTEN=${arg#*=} ;;
    --api-listen=*) API_LISTEN=${arg#*=} ;;
    --upstream-port=*) UPSTREAM_PORT=${arg#*=} ;;
    --acme-email=*) ACME_EMAIL=${arg#*=} ;;
    --acme-directory=*) ACME_DIRECTORY=${arg#*=} ;;
    --systemd) USE_SYSTEMD=yes ;;
    --no-systemd) USE_SYSTEMD=no ;;
    --debug) DEBUG=true ;;
    --help|-h) usage; exit 0 ;;
    --force-resolv) die '--force-resolv was removed. Bind DNSBox to a free interface with --dns-listen instead.' ;;
    *) die "Unknown option: $arg" ;;
  esac
done

[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]] || die 'Invalid release version'
[[ "$INSTALL_DIR" = /* && "$INSTALL_DIR" != / ]] || die '--install-dir must be an absolute directory other than /'
DATA_DIR=${DATA_DIR:-"$INSTALL_DIR/data"}
[[ "$DATA_DIR" = /* && "$DATA_DIR" != / ]] || die '--data-dir must be an absolute directory other than /'

for cmd in curl tar awk mktemp; do command -v "$cmd" >/dev/null || die "Required command not found: $cmd"; done
if command -v sha256sum >/dev/null; then
  HASH=(sha256sum)
elif command -v shasum >/dev/null; then
  HASH=(shasum -a 256)
else
  die 'sha256sum or shasum is required to verify the download'
fi

case "$(uname -s)" in
  Linux) GOOS=linux ;;
  Darwin) GOOS=darwin ;;
  *) die 'This installer supports Linux and macOS. Download the Windows release manually.' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die 'Supported architectures: amd64, arm64' ;;
esac

if [[ "$USE_SYSTEMD" = auto ]]; then
  USE_SYSTEMD=no
  if [[ "$GOOS" = linux && -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
    USE_SYSTEMD=yes
  fi
fi
SUDO=()
if [[ "$USE_SYSTEMD" = yes ]]; then
  [[ "$GOOS" = linux && -d /run/systemd/system ]] || die 'systemd is not running; use --no-systemd'
  command -v systemctl >/dev/null || die 'systemctl is required'
  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null || die 'sudo is required to install a system service'
    SUDO=(sudo)
    sudo -v
  fi
  # systemd expands percent specifiers even inside quoted paths.
  [[ "$INSTALL_DIR" != *'%'* && "$INSTALL_DIR" != *'"'* && "$INSTALL_DIR" != *\\* ]] || die 'Unsupported character in systemd installation path'
fi

TASK_TMP=$(mktemp -d)
trap 'rm -rf -- "$TASK_TMP"' EXIT
ENV_FILE="$INSTALL_DIR/dnsbox.env"
if [[ -f "$ENV_FILE" ]]; then
  cp -- "$ENV_FILE" "$TASK_TMP/dnsbox.env"
  printf 'Preserving existing configuration: %s\n' "$ENV_FILE"
else
  [[ -n "$IP" && -n "$DOMAIN" ]] || die '--ip and --domain are required for a new installation'
  # Single-quoted values work in both a POSIX shell and systemd EnvironmentFile.
  write_env() {
    [[ "$2" != *"'"* && "$2" != *$'\n'* && "$2" != *$'\r'* ]] || die "Invalid character in $1"
    printf "%s='%s'\n" "$1" "$2" >> "$TASK_TMP/dnsbox.env"
  }
  write_env DNSBOX_IP "$IP"
  write_env DNSBOX_DOMAIN "$DOMAIN"
  write_env DNSBOX_NS_NAME "$NS_NAME"
  write_env DNSBOX_TLS_MODE "$TLS_MODE"
  write_env DNSBOX_ALLOWED_CIDRS "$ALLOWED_CIDRS"
  write_env DNSBOX_DATA_DIR "$DATA_DIR"
  write_env DNSBOX_DNS_LISTEN "$DNS_LISTEN"
  write_env DNSBOX_HTTPS_LISTEN "$HTTPS_LISTEN"
  write_env DNSBOX_API_LISTEN "$API_LISTEN"
  write_env DNSBOX_UPSTREAM_PORT "$UPSTREAM_PORT"
  write_env DNSBOX_ACME_EMAIL "$ACME_EMAIL"
  write_env DNSBOX_ACME_DIRECTORY "$ACME_DIRECTORY"
  write_env DNSBOX_DEBUG "$DEBUG"
fi

ARCHIVE="dnsbox-$GOOS-$GOARCH.tar.gz"
RELEASE_URL="https://github.com/crypto-chiefs/dnsbox/releases/download/$VERSION"
printf 'Downloading DNSBox %s for %s/%s\n' "$VERSION" "$GOOS" "$GOARCH"
curl --fail --show-error --silent --location --retry 3 --proto '=https' --tlsv1.2 "$RELEASE_URL/$ARCHIVE" -o "$TASK_TMP/$ARCHIVE"
curl --fail --show-error --silent --location --retry 3 --proto '=https' --tlsv1.2 "$RELEASE_URL/checksums.txt" -o "$TASK_TMP/checksums.txt"
EXPECTED=$(awk -v file="$ARCHIVE" '$2 == file {print $1}' "$TASK_TMP/checksums.txt")
[[ "$EXPECTED" =~ ^[a-fA-F0-9]{64}$ ]] || die 'Missing or ambiguous archive checksum'
ACTUAL=$("${HASH[@]}" "$TASK_TMP/$ARCHIVE" | awk '{print $1}')
[[ "$EXPECTED" = "$ACTUAL" ]] || die 'Archive checksum does not match; installation stopped'
# Extract only the binary; archive paths and bundled scripts cannot overwrite files.
tar -xzf "$TASK_TMP/$ARCHIVE" -C "$TASK_TMP" dnsboxd
[[ -f "$TASK_TMP/dnsboxd" && ! -L "$TASK_TMP/dnsboxd" ]] || die 'Archive did not contain a regular dnsboxd binary'
chmod 755 "$TASK_TMP/dnsboxd"
(
  set -a
  # Existing configuration is user-controlled, just like the launcher configuration.
  # shellcheck disable=SC1091
  . "$TASK_TMP/dnsbox.env"
  set +a
  "$TASK_TMP/dnsboxd" --check-config
)

mkdir -p -- "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"
cp -- "$TASK_TMP/dnsboxd" "$INSTALL_DIR/dnsboxd.new"
chmod 755 "$INSTALL_DIR/dnsboxd.new"
mv -f -- "$INSTALL_DIR/dnsboxd.new" "$INSTALL_DIR/dnsboxd"
if [[ ! -f "$ENV_FILE" ]]; then cp -- "$TASK_TMP/dnsbox.env" "$ENV_FILE"; fi
chmod 600 "$ENV_FILE"
cat > "$INSTALL_DIR/run-dnsbox" <<'EOF'
#!/bin/sh
set -eu
INSTALL_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
set -a
. "$INSTALL_DIR/dnsbox.env"
set +a
exec "$INSTALL_DIR/dnsboxd" "$@"
EOF
chmod 755 "$INSTALL_DIR/run-dnsbox"

if [[ "$USE_SYSTEMD" = yes ]]; then
  SERVICE_USER=$(id -un)
  [[ "$SERVICE_USER" =~ ^[a-zA-Z0-9_.-]+$ ]] || die 'Unsupported service user name'
  cat > "$TASK_TMP/dnsbox.service" <<EOF
[Unit]
Description=DNSBox DNS and HTTPS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
ExecStart="$INSTALL_DIR/run-dnsbox"
WorkingDirectory="$INSTALL_DIR"
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
  "${SUDO[@]}" install -m 644 "$TASK_TMP/dnsbox.service" /etc/systemd/system/dnsbox.service
  "${SUDO[@]}" systemctl daemon-reload
  "${SUDO[@]}" systemctl enable dnsbox.service
  "${SUDO[@]}" systemctl restart dnsbox.service
  "${SUDO[@]}" systemctl is-active --quiet dnsbox.service
  printf 'DNSBox service started. Logs: journalctl -u dnsbox.service\n'
else
  printf 'Installed. Start manually: %q/run-dnsbox\n' "$INSTALL_DIR"
  printf 'Ports below 1024 require appropriate privileges; alternatively configure high listener ports.\n'
fi
printf 'Configuration: %s\nData directory is configured by DNSBOX_DATA_DIR in this file.\n' "$ENV_FILE"
