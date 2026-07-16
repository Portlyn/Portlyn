#!/bin/sh
# Portlyn hub installer.
# Usage:
#   curl -fsSL https://get.portlyn.dev | sudo sh
#   curl -fsSL https://get.portlyn.dev | sudo PORTLYN_DOMAIN=portlyn.example.com \
#     PORTLYN_ADMIN_EMAIL=admin@example.com sh
set -eu

PATH="${PATH}:/usr/local/bin:/usr/bin:/bin"
export PATH

REPO="portlyn/Portlyn"
DOWNLOAD_BASE="https://github.com/${REPO}/releases"
VERSION="${PORTLYN_VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"
BIN_NAME="portlyn"
STATE_DIR="/var/lib/portlyn"
SERVICE_NAME="portlyn"
SERVICE_USER="portlyn"
REQUIRE_SIGNATURE="1"
ALLOW_UNSIGNED="${ALLOW_UNSIGNED:-0}"
SAN_REGEXP='^https://github\.com/[Pp]ortlyn/[Pp]ortlyn/'
OIDC_ISSUER="https://token.actions.githubusercontent.com"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --download-base) DOWNLOAD_BASE="$2"; shift 2 ;;
    --download-base=*) DOWNLOAD_BASE="${1#*=}"; shift ;;
    --allow-unsigned) ALLOW_UNSIGNED="1"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

err() { echo "error: $*" >&2; exit 1; }

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux) ;;
  *) err "the hub installer supports Linux only (got: $os)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

asset="${BIN_NAME}-${os}-${arch}"
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
  err "need curl or wget to download the hub."
fi

if command -v sha256sum >/dev/null 2>&1; then
  SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA="shasum -a 256"
else
  err "need sha256sum or shasum to verify the download."
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else err "run as root or install sudo."; fi
fi

tmp="$(mktemp)"
sums="$(mktemp)"
sig="$(mktemp)"
cert="$(mktemp)"
bundle="$(mktemp)"
trap 'rm -f "$tmp" "$sums" "$sig" "$cert" "$bundle"' EXIT

echo "Downloading ${asset} ..."
$DL "$tmp" "$url" || err "download failed: $url"

echo "Verifying checksum ..."
$DL "$sums" "$checksum_url" || err "could not fetch checksums.txt: $checksum_url"
expected="$(grep " ${asset}\$" "$sums" | awk '{print $1}' | head -n1)"
[ -n "$expected" ] || err "no checksum entry for ${asset} in checksums.txt"
actual="$($SHA "$tmp" | awk '{print $1}')"
[ "$expected" = "$actual" ] || err "checksum mismatch for ${asset}: expected ${expected}, got ${actual}"
echo "Checksum OK."

if [ "$ALLOW_UNSIGNED" = "1" ]; then
  REQUIRE_SIGNATURE="0"
fi

chmod +x "$tmp"

if command -v cosign >/dev/null 2>&1; then
  echo "Verifying signature (cosign) ..."
  $DL "$sig" "${release_base}/checksums.txt.sig" || err "could not fetch checksums.txt.sig"
  $DL "$cert" "${release_base}/checksums.txt.pem" || err "could not fetch checksums.txt.pem"
  cosign verify-blob \
    --certificate "$cert" \
    --signature "$sig" \
    --certificate-identity-regexp "$SAN_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$sums" >/dev/null 2>&1 || err "cosign signature verification failed for checksums.txt"
  echo "Signature OK."
elif [ "$REQUIRE_SIGNATURE" = "1" ]; then
  echo "cosign not found; verifying signature in-process with the downloaded binary ..."
  $DL "$bundle" "${release_base}/checksums.txt.bundle.json" || err "could not fetch checksums.txt.bundle.json for in-process verification"
  "$tmp" verify-release --checksums "$sums" --bundle "$bundle" --asset "$tmp" --asset-name "$asset" \
    || err "in-process signature verification failed for checksums.txt"
  echo "Signature OK (verified in-process via embedded Sigstore trust root)."
else
  echo "WARNING: --allow-unsigned set. Verified checksum only." >&2
  echo "WARNING: the download's authenticity is NOT verified." >&2
fi
$SUDO mkdir -p "$INSTALL_DIR"
$SUDO mv "$tmp" "${INSTALL_DIR}/${BIN_NAME}"
echo "Installed ${INSTALL_DIR}/${BIN_NAME}"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  echo "Creating system user ${SERVICE_USER} ..."
  $SUDO useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER" \
    || $SUDO adduser --system --home "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" \
    || err "could not create system user ${SERVICE_USER}"
fi

$SUDO mkdir -p "$STATE_DIR"
$SUDO chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
$SUDO chmod 0750 "$STATE_DIR"

if [ -n "${PORTLYN_DOMAIN:-}" ] && [ -n "${PORTLYN_ADMIN_EMAIL:-}" ]; then
  if [ -f "${STATE_DIR}/.env" ]; then
    echo "${STATE_DIR}/.env already exists; skipping init."
  else
    echo "Generating configuration with 'portlyn init --non-interactive' ..."
    $SUDO env \
      PORTLYN_DOMAIN="$PORTLYN_DOMAIN" \
      PORTLYN_ADMIN_EMAIL="$PORTLYN_ADMIN_EMAIL" \
      PORTLYN_ADMIN_PASSWORD="${PORTLYN_ADMIN_PASSWORD:-}" \
      PORTLYN_ACME_EMAIL="${PORTLYN_ACME_EMAIL:-}" \
      PORTLYN_DNS_PROVIDER="${PORTLYN_DNS_PROVIDER:-}" \
      PORTLYN_DNS_TOKEN="${PORTLYN_DNS_TOKEN:-}" \
      "${INSTALL_DIR}/${BIN_NAME}" init --non-interactive \
        --output "${STATE_DIR}/.env" --data-dir "$STATE_DIR"
    $SUDO chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
    $SUDO chmod 0600 "${STATE_DIR}/.env"
  fi
  INIT_DONE="1"
else
  INIT_DONE="0"
fi

if command -v systemctl >/dev/null 2>&1; then
  unit="/etc/systemd/system/${SERVICE_NAME}.service"
  echo "Installing systemd service ${SERVICE_NAME} ..."
  $SUDO sh -c "cat > '$unit'" <<EOF
[Unit]
Description=Portlyn hub
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${STATE_DIR}
EnvironmentFile=${STATE_DIR}/.env
ExecStart=${INSTALL_DIR}/${BIN_NAME}
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  if [ "$INIT_DONE" = "1" ]; then
    $SUDO systemctl enable --now "${SERVICE_NAME}.service"
    echo "Service started. Check status with: systemctl status ${SERVICE_NAME}"
  else
    $SUDO systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    echo
    echo "Next steps:"
    echo "  1. sudo -u ${SERVICE_USER} ${INSTALL_DIR}/${BIN_NAME} init --output ${STATE_DIR}/.env --data-dir ${STATE_DIR}"
    echo "  2. sudo systemctl start ${SERVICE_NAME}"
  fi
else
  echo "systemd not found. Start the hub manually:"
  echo "  cd ${STATE_DIR} && ${INSTALL_DIR}/${BIN_NAME} init && ${INSTALL_DIR}/${BIN_NAME}"
fi
