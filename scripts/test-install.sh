#!/usr/bin/env bash
# Installer regression tests use a local release fixture; no root/network needed.
set -euo pipefail
REPO_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/release" "$TEST_DIR/payload"
export DNSBOX_TEST_RELEASE="$TEST_DIR/release"
export DNSBOX_TEST_URLS="$TEST_DIR/urls"
cat > "$TEST_DIR/payload/dnsboxd" <<'EOF'
#!/usr/bin/env bash
set -eu
[[ "$1" = --check-config ]]
[[ -n "$DNSBOX_DOMAIN" && -n "$DNSBOX_IP" ]]
[[ "$DNSBOX_DEBUG" = true || "$DNSBOX_DEBUG" = false ]]
EOF
chmod +x "$TEST_DIR/payload/dnsboxd"
ARCH=$(uname -m)
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; esac
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCHIVE="dnsbox-$OS-$ARCH.tar.gz"
tar -czf "$TEST_DIR/release/$ARCHIVE" -C "$TEST_DIR/payload" dnsboxd
(cd "$TEST_DIR/release" && sha256sum "$ARCHIVE" > checksums.txt)
cat > "$TEST_DIR/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -eu
URL=""
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    https://*) URL=$1; shift ;;
    -o) OUT=$2; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' "$URL" >> "$DNSBOX_TEST_URLS"
[[ "$URL" = https://github.com/crypto-chiefs/dnsbox/releases/download/v0.5.0/* ]]
cp "$DNSBOX_TEST_RELEASE/${URL##*/}" "$OUT"
EOF
chmod +x "$TEST_DIR/bin/curl"
export PATH="$TEST_DIR/bin:$PATH"

expect_failure() {
  if "$@" >"$TEST_DIR/failure.log" 2>&1; then
    printf 'Expected failure: %s\n' "$*" >&2
    exit 1
  fi
}

bash -n "$REPO_DIR/scripts/install.sh" "$REPO_DIR/scripts/uninstall.sh"
bash "$REPO_DIR/scripts/install.sh" --help >/dev/null
expect_failure bash "$REPO_DIR/scripts/install.sh" --unknown
expect_failure bash "$REPO_DIR/scripts/install.sh" --force-resolv
expect_failure bash "$REPO_DIR/scripts/install.sh" --version='../../bad'
expect_failure bash "$REPO_DIR/scripts/install.sh" --no-systemd --install-dir="$TEST_DIR/missing"
expect_failure bash "$REPO_DIR/scripts/install.sh" --no-systemd --install-dir="$TEST_DIR/invalid" --ip=192.168.1.2 "--domain=foo'bar"

DEST="$TEST_DIR/install with spaces"
bash "$REPO_DIR/scripts/install.sh" --no-systemd --install-dir="$DEST" --domain=home.arpa --ip=192.168.1.2 --tls-mode=local --allowed-cidrs=192.168.1.0/24 --debug
[[ -x "$DEST/dnsboxd" && -x "$DEST/run-dnsbox" ]]
grep -q "DNSBOX_DEBUG='true'" "$DEST/dnsbox.env"
"$DEST/run-dnsbox" --check-config
mkdir -p "$DEST/data/ca" "$DEST/data/certs"
printf 'keep CA\n' > "$DEST/data/ca/root.pem"
printf 'keep cert\n' > "$DEST/data/certs/example.crt"
printf "DNSBOX_API_TOKEN='preserve-me'\n" >> "$DEST/dnsbox.env"
cp "$DEST/dnsbox.env" "$TEST_DIR/original.env"
bash "$REPO_DIR/scripts/install.sh" --no-systemd --install-dir="$DEST"
cmp "$DEST/dnsbox.env" "$TEST_DIR/original.env"

cp "$DEST/dnsboxd" "$TEST_DIR/original.binary"
printf 'corrupted download\n' >> "$TEST_DIR/release/$ARCHIVE"
expect_failure bash "$REPO_DIR/scripts/install.sh" --no-systemd --install-dir="$DEST"
cmp "$DEST/dnsboxd" "$TEST_DIR/original.binary"
grep -q 'checksum does not match' "$TEST_DIR/failure.log"

bash "$REPO_DIR/scripts/uninstall.sh" --no-systemd --install-dir="$DEST"
[[ ! -e "$DEST/dnsboxd" && ! -e "$DEST/run-dnsbox" ]]
cmp "$DEST/dnsbox.env" "$TEST_DIR/original.env"
[[ $(cat "$DEST/data/ca/root.pem") = 'keep CA' ]]
[[ $(cat "$DEST/data/certs/example.crt") = 'keep cert' ]]
bash "$REPO_DIR/scripts/uninstall.sh" --no-systemd --install-dir="$DEST"
expect_failure bash "$REPO_DIR/scripts/uninstall.sh" --install-dir=/
printf 'Installer regression tests passed\n'
