#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ENV_FILE="$ROOT_DIR/.env.docker"
EXAMPLE_FILE="$ROOT_DIR/.env.docker.example"
TMP_FILE="$ROOT_DIR/.env.docker.tmp"

detect_distro() {
  if [ -r /etc/os-release ]; then
    distro_id="$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')"
    if [ -n "$distro_id" ]; then
      printf '%s' "$distro_id"
      return
    fi
  fi

  printf 'unknown'
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
    return
  fi

  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
    return
  fi

  if [ -r /dev/urandom ] && command -v head >/dev/null 2>&1 && command -v od >/dev/null 2>&1 && command -v tr >/dev/null 2>&1; then
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
    return
  fi

  printf 'change-me-%s' "$(date +%s)"
}

trim() {
  printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

escape_sed_replacement() {
  printf '%s' "$1" | sed 's/[\/&]/\\&/g'
}

set_env_value() {
  key="$1"
  value="$2"
  escaped_value="$(escape_sed_replacement "$value")"

  if grep -q "^${key}=" "$ENV_FILE"; then
    sed "s/^${key}=.*/${key}=${escaped_value}/" "$ENV_FILE" > "$TMP_FILE"
    mv "$TMP_FILE" "$ENV_FILE"
  else
    printf '\n%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

get_env_value() {
  key="$1"
  if [ ! -f "$ENV_FILE" ]; then
    return 0
  fi

  line="$(grep "^${key}=" "$ENV_FILE" | tail -n 1 || true)"
  if [ -z "$line" ]; then
    return 0
  fi

  printf '%s' "${line#*=}"
}

prompt_value() {
  key="$1"
  label="$2"
  default_value="$3"

  current_value="$(get_env_value "$key")"
  if [ -n "$current_value" ]; then
    default_value="$current_value"
  fi

  if [ -n "$default_value" ]; then
    printf '%s [%s]: ' "$label" "$default_value" >&2
  else
    printf '%s: ' "$label" >&2
  fi

  read -r input_value || true
  input_value="$(trim "$input_value")"
  if [ -z "$input_value" ]; then
    input_value="$default_value"
  fi

  printf '%s' "$input_value"
}

prompt_secret() {
  key="$1"
  label="$2"
  generated_default="$3"

  current_value="$(get_env_value "$key")"
  if [ -n "$current_value" ]; then
    generated_default="$current_value"
  fi

  printf '%s' "$label" >&2
  if [ -n "$generated_default" ]; then
    printf ' [press enter to keep current/generated value]' >&2
  fi
  printf ': ' >&2

  stty_state="$(stty -g 2>/dev/null || true)"
  if [ -n "$stty_state" ]; then
    stty -echo 2>/dev/null || true
  fi
  read -r input_value || true
  if [ -n "$stty_state" ]; then
    stty "$stty_state" 2>/dev/null || true
  fi
  printf '\n' >&2

  input_value="$(trim "$input_value")"
  if [ -z "$input_value" ]; then
    input_value="$generated_default"
  fi

  printf '%s' "$input_value"
}

prompt_yes_no() {
  key="$1"
  label="$2"
  default_value="$3"

  current_value="$(get_env_value "$key")"
  if [ "$current_value" = "true" ] || [ "$current_value" = "false" ]; then
    default_value="$current_value"
  fi

  while true; do
    if [ "$default_value" = "true" ]; then
      printf '%s [Y/n]: ' "$label" >&2
    else
      printf '%s [y/N]: ' "$label" >&2
    fi

    read -r input_value || true
    input_value="$(trim "$input_value")"
    input_value="$(printf '%s' "$input_value" | tr '[:upper:]' '[:lower:]')"

    if [ -z "$input_value" ]; then
      printf '%s' "$default_value"
      return 0
    fi

    case "$input_value" in
      y|yes|true) printf 'true'; return 0 ;;
      n|no|false) printf 'false'; return 0 ;;
    esac

    echo "Please answer yes or no." >&2
  done
}

require_non_empty() {
  key="$1"
  value="$2"
  if [ -z "$value" ]; then
    echo "$key must not be empty." >&2
    exit 1
  fi
}

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required but was not found in PATH." >&2
  exit 1
fi

if [ ! -f "$EXAMPLE_FILE" ]; then
  echo "Missing $EXAMPLE_FILE" >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  cp "$EXAMPLE_FILE" "$ENV_FILE"
  echo "Created $ENV_FILE from .env.docker.example"
fi

echo "Portlyn deployment setup"
echo "This wizard prepares bootstrap admin access and then starts docker compose."
echo "You can move Portlyn to a public admin domain later in the UI."
distro="$(detect_distro)"
if [ "$distro" != "unknown" ]; then
  echo "Detected Linux distro: $distro"
fi
echo

frontend_base_url="$(prompt_value "FRONTEND_BASE_URL" "Initial admin URL" "http://localhost")"
if [ -z "$frontend_base_url" ]; then
  frontend_base_url="http://localhost"
fi

default_cors="http://localhost,http://127.0.0.1"
case "$frontend_base_url" in
  http://localhost|http://127.0.0.1|"")
    ;;
  *)
    default_cors="$default_cors,$frontend_base_url"
    ;;
esac
cors_allowed_origins="$(prompt_value "CORS_ALLOWED_ORIGINS" "Allowed CORS origins (comma separated)" "$default_cors")"
admin_email="$(prompt_value "ADMIN_EMAIL" "Admin email" "$(get_env_value "ADMIN_EMAIL")")"
admin_password="$(prompt_secret "ADMIN_PASSWORD" "Admin password" "")"
jwt_secret="$(prompt_secret "JWT_SECRET" "JWT secret" "$(random_secret)")"
jwt_signing_secret="$(prompt_secret "JWT_SIGNING_SECRET" "JWT signing secret" "$(random_secret)")"
session_bridge_secret="$(prompt_secret "SESSION_BRIDGE_SECRET" "Session bridge secret" "$(random_secret)")"
oidc_state_secret="$(prompt_secret "OIDC_STATE_SECRET" "OIDC state secret" "$(random_secret)")"
mfa_encryption_secret="$(prompt_secret "MFA_ENCRYPTION_SECRET" "MFA encryption secret" "$(random_secret)")"
csrf_secret="$(prompt_secret "CSRF_SECRET" "CSRF secret" "$(random_secret)")"
data_encryption_secret="$(prompt_secret "DATA_ENCRYPTION_SECRET" "Data encryption secret" "$(random_secret)")"
audit_hmac_secret="$(prompt_secret "AUDIT_HMAC_SECRET" "Audit log HMAC secret" "$(random_secret)")"
postgres_password="$(prompt_secret "POSTGRES_PASSWORD" "PostgreSQL password" "$(random_secret)")"
grafana_admin_password="$(prompt_secret "GRAFANA_ADMIN_PASSWORD" "Grafana admin password" "$(random_secret)")"
bootstrap_admin_enabled="$(prompt_yes_no "BOOTSTRAP_ADMIN_ENABLED" "Keep bootstrap admin access on localhost and direct IPs" "true")"
acme_enabled="$(prompt_yes_no "ACME_ENABLED" "Enable ACME / Let's Encrypt now" "false")"

redirect_http_to_https="false"
acme_email=""
if [ "$acme_enabled" = "true" ]; then
  acme_email="$(prompt_value "ACME_EMAIL" "ACME email" "$(get_env_value "ACME_EMAIL")")"
  redirect_http_to_https="$(prompt_yes_no "REDIRECT_HTTP_TO_HTTPS" "Redirect HTTP to HTTPS" "true")"
fi

require_non_empty "FRONTEND_BASE_URL" "$frontend_base_url"
require_non_empty "CORS_ALLOWED_ORIGINS" "$cors_allowed_origins"
require_non_empty "ADMIN_EMAIL" "$admin_email"
require_non_empty "ADMIN_PASSWORD" "$admin_password"
require_non_empty "JWT_SECRET" "$jwt_secret"
require_non_empty "JWT_SIGNING_SECRET" "$jwt_signing_secret"
require_non_empty "SESSION_BRIDGE_SECRET" "$session_bridge_secret"
require_non_empty "OIDC_STATE_SECRET" "$oidc_state_secret"
require_non_empty "MFA_ENCRYPTION_SECRET" "$mfa_encryption_secret"
require_non_empty "CSRF_SECRET" "$csrf_secret"
require_non_empty "DATA_ENCRYPTION_SECRET" "$data_encryption_secret"
require_non_empty "AUDIT_HMAC_SECRET" "$audit_hmac_secret"
require_non_empty "GRAFANA_ADMIN_PASSWORD" "$grafana_admin_password"
require_non_empty "POSTGRES_PASSWORD" "$postgres_password"
if [ "$acme_enabled" = "true" ]; then
  require_non_empty "ACME_EMAIL" "$acme_email"
fi

set_env_value "FRONTEND_BASE_URL" "$frontend_base_url"
set_env_value "CORS_ALLOWED_ORIGINS" "$cors_allowed_origins"
set_env_value "ADMIN_EMAIL" "$admin_email"
set_env_value "ADMIN_PASSWORD" "$admin_password"
set_env_value "JWT_SECRET" "$jwt_secret"
set_env_value "JWT_SIGNING_SECRET" "$jwt_signing_secret"
set_env_value "SESSION_BRIDGE_SECRET" "$session_bridge_secret"
set_env_value "OIDC_STATE_SECRET" "$oidc_state_secret"
set_env_value "MFA_ENCRYPTION_SECRET" "$mfa_encryption_secret"
set_env_value "CSRF_SECRET" "$csrf_secret"
set_env_value "DATA_ENCRYPTION_SECRET" "$data_encryption_secret"
set_env_value "AUDIT_HMAC_SECRET" "$audit_hmac_secret"
set_env_value "POSTGRES_PASSWORD" "$postgres_password"
set_env_value "GRAFANA_ADMIN_PASSWORD" "$grafana_admin_password"
set_env_value "BOOTSTRAP_ADMIN_ENABLED" "$bootstrap_admin_enabled"
set_env_value "ACME_ENABLED" "$acme_enabled"
set_env_value "REDIRECT_HTTP_TO_HTTPS" "$redirect_http_to_https"
set_env_value "ACME_EMAIL" "$acme_email"
set_env_value "ALLOW_INSECURE_DEV_MODE" "false"
set_env_value "OTP_RESPONSE_INCLUDES_CODE" "false"

echo
echo "Saved configuration to $ENV_FILE"
echo "Starting docker compose..."
docker compose --env-file "$ENV_FILE" up -d --build
echo
api_port="$(get_env_value "PORTLYN_API_PORT")"
if [ -z "$api_port" ]; then
  api_port="8080"
fi

echo "Portlyn is starting."
echo "Frontend: $(get_env_value "FRONTEND_BASE_URL")"
if [ "$bootstrap_admin_enabled" = "true" ]; then
  echo "Bootstrap admin access: http://localhost or http://<server-ip>"
fi
echo "API: http://localhost:$api_port"
