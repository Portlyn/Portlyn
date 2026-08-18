#!/bin/sh
# Boots a throwaway Portlyn hub for the Playwright suite:
#   ./scripts/e2e-hub.sh ./portlyn ./.tmp/e2e
# Admin MFA is not enforced (the suite enrols TOTP itself) and the auth rate
# limit is raised so repeated logins do not lock the run out.
set -eu

BINARY="${1:-./portlyn}"
RUN_DIR="${2:-./.tmp/e2e}"
ADMIN_EMAIL="${PORTLYN_TEST_ADMIN_EMAIL:-admin@example.test}"
ADMIN_PASSWORD="${PORTLYN_TEST_ADMIN_PASSWORD:-ChangeMeStrongerPasswordPlease!}"

BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR"
cd "$RUN_DIR"

"$BINARY" init --non-interactive \
  --domain localhost \
  --admin-email "$ADMIN_EMAIL" \
  --admin-password "$ADMIN_PASSWORD" \
  --acme=false \
  --output .env \
  --data-dir ./data

printf 'REQUIRE_MFA_FOR_ADMINS=false\nAUTH_RATE_LIMIT_ATTEMPTS=1000\n' >> .env

"$BINARY" > hub.log 2>&1 &
echo "$!" > hub.pid

i=0
while [ "$i" -lt 60 ]; do
  if curl -fsS -o /dev/null http://localhost:8000/login; then
    echo "hub is up on http://localhost:8000"
    exit 0
  fi
  i=$((i + 1))
  sleep 1
done

echo "hub did not become ready" >&2
exit 1
