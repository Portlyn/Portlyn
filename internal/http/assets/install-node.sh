#!/bin/sh
# Portlyn node agent installer.
# Usage:
#   curl -fsSL https://<portlyn-host>/install.sh | sudo sh -s -- --token <ENROLLMENT_TOKEN>
set -eu

API_BASE="__API_BASE__"
DOWNLOAD_BASE="__DOWNLOAD_BASE__"
VERSION="__VERSION__"
TOKEN=""
NAME=""
INSTALL_DIR="/usr/local/bin"
BIN_NAME="portlyn-nodeagent"
STATE_DIR="/var/lib/portlyn-nodeagent"
SERVICE_NAME="portlyn-nodeagent"
REQUIRE_SIGNATURE="0"
SAN_REGEXP='^https://github\.com/portlyn/Portlyn/'
OIDC_ISSUER="https://token.actions.githubusercontent.com"

while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --token=*) TOKEN="${1#*=}"; shift ;;
    --api) API_BASE="$2"; shift 2 ;;
    --api=*) API_BASE="${1#*=}"; shift ;;
    --name) NAME="$2"; shift 2 ;;
    --name=*) NAME="${1#*=}"; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --download-base) DOWNLOAD_BASE="$2"; shift 2 ;;
    --download-base=*) DOWNLOAD_BASE="${1#*=}"; shift ;;
    --require-signature) REQUIRE_SIGNATURE="1"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

err() { echo "error: $*" >&2; exit 1; }

[ -n "$TOKEN" ] || err "missing --token. Generate one in Portlyn under Nodes -> Install Node."
[ -n "$API_BASE" ] || err "missing --api (Portlyn base URL)."
[ -n "$NAME" ] || NAME="$(hostname 2>/dev/null || echo portlyn-node)"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin) ;;
  *) err "unsupported OS: $os" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

ext=""
asset="${BIN_NAME}-${os}-${arch}${ext}"
if [ "$VERSION" = "latest" ]; then
  release_base="${DOWNLOAD_BASE}/latest/download"
else
  release_base="${DOWNLOAD_BASE}/download/${VERSION}"
fi
url="${release_base}/${asset}"
checksum_url="${release_base}/checksums.txt"

if command -v curl >/dev/null 2>&1; then
  DL="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
  DL="wget -qO"
else
  err "need curl or wget to download the agent."
fi

if command -v sha256sum >/dev/null 2>&1; then
  SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA="shasum -a 256"
else
  err "need sha256sum or shasum to verify the download."
fi

tmp="$(mktemp)"
sums="$(mktemp)"
sig="$(mktemp)"
cert="$(mktemp)"
trap 'rm -f "$tmp" "$sums" "$sig" "$cert"' EXIT
echo "Downloading ${asset} ..."
$DL "$tmp" "$url" || err "download failed: $url"

echo "Verifying checksum ..."
$DL "$sums" "$checksum_url" || err "could not fetch checksums.txt for integrity verification: $checksum_url"
expected="$(grep " ${asset}\$" "$sums" | awk '{print $1}' | head -n1)"
[ -n "$expected" ] || err "no checksum entry for ${asset} in checksums.txt"
actual="$($SHA "$tmp" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
  err "checksum mismatch for ${asset}: expected ${expected}, got ${actual}"
fi
echo "Checksum OK."

echo "Verifying signature ..."
if command -v cosign >/dev/null 2>&1; then
  $DL "$sig" "${release_base}/checksums.txt.sig" || err "could not fetch checksums.txt.sig for signature verification"
  $DL "$cert" "${release_base}/checksums.txt.pem" || err "could not fetch checksums.txt.pem for signature verification"
  cosign verify-blob \
    --certificate "$cert" \
    --signature "$sig" \
    --certificate-identity-regexp "$SAN_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$sums" >/dev/null 2>&1 || err "cosign signature verification failed for checksums.txt"
  echo "Signature OK."
elif [ "$REQUIRE_SIGNATURE" = "1" ]; then
  err "cosign not found but --require-signature was set. Install cosign (https://docs.sigstore.dev/cosign) and retry."
else
  echo "WARNING: cosign not found; verified checksum only. The download's authenticity is NOT verified." >&2
  echo "WARNING: install cosign for full Sigstore verification, or re-run with --require-signature." >&2
fi

chmod +x "$tmp"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else err "run as root or install sudo."; fi
fi

$SUDO mkdir -p "$INSTALL_DIR"
$SUDO mv "$tmp" "${INSTALL_DIR}/${BIN_NAME}"
echo "Installed ${INSTALL_DIR}/${BIN_NAME}"

if command -v systemctl >/dev/null 2>&1; then
  unit="/etc/systemd/system/${SERVICE_NAME}.service"
  echo "Installing systemd service ${SERVICE_NAME} ..."
  $SUDO sh -c "cat > '$unit'" <<EOF
[Unit]
Description=Portlyn node agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${INSTALL_DIR}/${BIN_NAME} --api "${API_BASE}" --token "${TOKEN}" --name "${NAME}" --state "${STATE_DIR}/state.json"
Restart=always
RestartSec=5
DynamicUser=yes
StateDirectory=portlyn-nodeagent

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now "${SERVICE_NAME}.service"
  echo "Service started. Check status with: systemctl status ${SERVICE_NAME}"
else
  $SUDO mkdir -p "$STATE_DIR"
  echo "systemd not found. Start the agent manually (or add it to your init system):"
  echo "  ${INSTALL_DIR}/${BIN_NAME} --api \"${API_BASE}\" --token \"${TOKEN}\" --name \"${NAME}\" --state \"${STATE_DIR}/state.json\""
fi
