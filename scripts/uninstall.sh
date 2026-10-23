#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME:?HOME must be set}/.dnsbox"
REMOVE_SERVICE=auto
for arg in "$@"; do
  case "$arg" in
    --install-dir=*) INSTALL_DIR=${arg#*=} ;;
    --no-systemd) REMOVE_SERVICE=no ;;
    --help|-h)
      printf 'Usage: bash uninstall.sh [--install-dir=PATH] [--no-systemd]\nRemoves the binary and matching service. Preserves configuration, certificates, CA, and logs.\n'
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; exit 1 ;;
  esac
done
[[ "$INSTALL_DIR" = /* && "$INSTALL_DIR" != / ]] || { printf 'Invalid installation directory\n' >&2; exit 1; }

SERVICE_FILE=/etc/systemd/system/dnsbox.service
matches_service() {
  # Accept both the current launcher and the legacy installer's direct binary.
  grep -Fxq -e "ExecStart=\"$INSTALL_DIR/run-dnsbox\"" \
    -e "ExecStart=$INSTALL_DIR/dnsboxd" \
    -e "ExecStart=\"$INSTALL_DIR/dnsboxd\"" "$SERVICE_FILE"
}
if [[ "$REMOVE_SERVICE" != no && -f "$SERVICE_FILE" ]] && matches_service; then
  SUDO=()
  if [[ $EUID -ne 0 ]]; then SUDO=(sudo); fi
  "${SUDO[@]}" systemctl disable --now dnsbox.service
  "${SUDO[@]}" rm -f -- "$SERVICE_FILE"
  "${SUDO[@]}" systemctl daemon-reload
fi

# Remove only known executable files, never recurse through user data.
rm -f -- "$INSTALL_DIR/dnsboxd" "$INSTALL_DIR/dnsboxd.new" "$INSTALL_DIR/run-dnsbox"
printf 'DNSBox executables removed. Configuration, certificates, CA, and system logs were preserved.\n'
printf 'Preserved installation directory: %s\n' "$INSTALL_DIR"
