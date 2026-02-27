#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -f "$ROOT_DIR/.env" ]; then
  # shellcheck disable=SC1091
  set -a
  . "$ROOT_DIR/.env"
  set +a
fi

usage() {
  cat <<'EOF'
Usage: scripts/run-keycloak-ngrok.sh [--domain <name>] [--proxy] [--no-proxy] [--ngrok-only]

Starts ngrok and Keycloak (via docker compose) with a public HTTPS URL.
Keycloak is configured with KC_HOSTNAME so it generates correct endpoint URLs.

Options:
  --domain <name>  Use a custom ngrok domain (registered in your ngrok account).
                   Overrides the auto-detected domain from the sandbox cert.
  --proxy          Force-enable oid4vc-dev reverse proxy (auto-enabled if
                   oid4vc-dev is in PATH). Dashboard: http://localhost:9091
  --no-proxy       Disable oid4vc-dev proxy even if installed.
  --ngrok-only     Start only ngrok (and proxy if enabled) and print env vars
                   (useful when you want to restart Keycloak yourself).

Sandbox certificate:
  If sandbox/sandbox-ngrok-combined.pem exists, the script automatically
  extracts the dNSName SAN and uses it as the ngrok --url domain.
  If the file is missing, ngrok starts with a random URL.

Defaults:
  - keycloak port: 8080

After Keycloak is running, start the demo app in another terminal with:
  KEYCLOAK_BASE_URL=<public-url> mvn -pl demo-app spring-boot:run

Or combine with the demo ngrok script for full public access:
  KEYCLOAK_BASE_URL=<public-url> scripts/run-demo-ngrok.sh

Examples:
  scripts/run-keycloak-ngrok.sh
  scripts/run-keycloak-ngrok.sh --domain mykeycloak.ngrok-free.app
  scripts/run-keycloak-ngrok.sh --ngrok-only
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

KC_PORT=8080
NGROK_ONLY=false
NGROK_DOMAIN=""
PROXY_PORT=9090
PROXY_DASHBOARD_PORT=9091
# Auto-enable proxy if oid4vc-dev is installed; --no-proxy to override
if command -v oid4vc-dev >/dev/null 2>&1; then
  USE_PROXY=true
else
  USE_PROXY=false
fi

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --domain)
      if [ $# -lt 2 ]; then
        echo "Missing value for --domain" >&2
        usage >&2
        exit 2
      fi
      NGROK_DOMAIN="$2"
      shift 2
      ;;
    --proxy)
      USE_PROXY=true
      shift
      ;;
    --no-proxy)
      USE_PROXY=false
      shift
      ;;
    --ngrok-only|--tunnel-only|--no-app)
      NGROK_ONLY=true
      shift
      ;;
    *)
      echo "Unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd ngrok
require_cmd curl
require_cmd jq
require_cmd docker

tmp_log="$(mktemp -t keycloak-ngrok.XXXXXX.log)"

cleanup() {
  if [ -n "${PROXY_PID:-}" ]; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${NGROK_PID:-}" ]; then
    kill "${NGROK_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "$tmp_log" >/dev/null 2>&1 || true
}

trap cleanup INT TERM EXIT

# When proxy is enabled, ngrok forwards to the proxy port; proxy forwards to Keycloak.
NGROK_TARGET_PORT="$KC_PORT"
if [ "$USE_PROXY" = "true" ]; then
  if ! command -v oid4vc-dev >/dev/null 2>&1; then
    echo "oid4vc-dev not found in PATH. Install it or use --no-proxy." >&2
    exit 1
  fi
  NGROK_TARGET_PORT="$PROXY_PORT"
fi

# Auto-detect ngrok domain from sandbox cert
NGROK_CERT_FILE="$ROOT_DIR/sandbox/sandbox-ngrok-combined.pem"
if [ -z "$NGROK_DOMAIN" ] && command -v openssl >/dev/null 2>&1 && [ -f "$NGROK_CERT_FILE" ]; then
  NGROK_DOMAIN="$(openssl x509 -in "$NGROK_CERT_FILE" -noout -ext subjectAltName 2>/dev/null \
    | grep -oE 'DNS:[^ ,]+' | head -n1 | sed 's/DNS://')" || true
  if [ -n "$NGROK_DOMAIN" ]; then
    echo "Auto-detected ngrok domain from cert: $NGROK_DOMAIN"
  fi
fi

# Start ngrok
NGROK_ARGS="http $NGROK_TARGET_PORT --log=stdout --log-format=json"
if [ -n "$NGROK_DOMAIN" ]; then
  NGROK_ARGS="$NGROK_ARGS --url=$NGROK_DOMAIN"
fi
ngrok $NGROK_ARGS >"$tmp_log" 2>&1 &
NGROK_PID="$!"

get_public_url() {
  curl -fsS "http://127.0.0.1:4040/api/tunnels" 2>/dev/null \
    | jq -r '.tunnels[] | select(.proto=="https") | .public_url' 2>/dev/null \
    | head -n 1
}

# Wait for ngrok to be ready
i=0
public_url=""
while [ "$i" -lt 120 ]; do
  public_url="$(get_public_url || true)"
  if [ -n "$public_url" ] && [ "$public_url" != "null" ]; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done

if [ -z "$public_url" ] || [ "$public_url" = "null" ]; then
  echo "Failed to obtain ngrok public URL. See: $tmp_log" >&2
  exit 1
fi

# Start oid4vc-dev proxy if enabled
if [ "$USE_PROXY" = "true" ]; then
  oid4vc-dev proxy --target "http://127.0.0.1:$KC_PORT" --port "$PROXY_PORT" --dashboard "$PROXY_DASHBOARD_PORT" &
  PROXY_PID="$!"
  echo "oid4vc-dev proxy started (pid $PROXY_PID), target: http://127.0.0.1:$KC_PORT"
fi

cat <<EOF
ngrok is running (pid $NGROK_PID)

Keycloak public URL:
  $public_url

Keycloak admin console:
  $public_url/admin

ngrok dashboard:
  http://127.0.0.1:4040
EOF

if [ "$USE_PROXY" = "true" ]; then
  cat <<EOF

oid4vc-dev proxy (pid $PROXY_PID):
  http://127.0.0.1:$PROXY_PORT -> http://127.0.0.1:$KC_PORT
  Dashboard: http://127.0.0.1:$PROXY_DASHBOARD_PORT
EOF
fi

cat <<EOF

Env vars:
  KC_HOSTNAME=$public_url
  KC_PROXY_HEADERS=xforwarded
  KEYCLOAK_BASE_URL=$public_url
EOF

if [ "$NGROK_ONLY" = "true" ]; then
  cat <<EOF

To start Keycloak with this hostname, run in another terminal:
  KC_HOSTNAME=$public_url KC_PROXY_HEADERS=xforwarded docker compose up keycloak

To start the demo app pointing at this Keycloak:
  KEYCLOAK_BASE_URL=$public_url mvn -pl demo-app spring-boot:run

Press Ctrl+C to stop ngrok.
EOF
  wait "$NGROK_PID"
  exit 0
fi

echo ""
echo "Starting Keycloak via docker compose..."

# Mount the ngrok sandbox cert into Keycloak so the oid4vp-sandbox IdP
# uses a certificate whose SAN matches the ngrok domain.
SANDBOX_CERT_MOUNT=""
if [ -f "$NGROK_CERT_FILE" ]; then
  SANDBOX_CERT_MOUNT="$NGROK_CERT_FILE:/sandbox/sandbox-combined.pem:ro"
  echo "Mounting ngrok cert as sandbox-combined.pem in Keycloak container"
elif [ -f "$ROOT_DIR/sandbox/sandbox-combined.pem" ]; then
  SANDBOX_CERT_MOUNT="$ROOT_DIR/sandbox/sandbox-combined.pem:/sandbox/sandbox-combined.pem:ro"
fi

cd "$ROOT_DIR"

# Build a docker compose override that mounts the sandbox cert
if [ -n "$SANDBOX_CERT_MOUNT" ]; then
  OVERRIDE_FILE="$(mktemp -t keycloak-ngrok-compose.XXXXXX.yml)"
  # shellcheck disable=SC2064
  trap "rm -f '$OVERRIDE_FILE'; cleanup" INT TERM EXIT
  cat > "$OVERRIDE_FILE" <<YAML
services:
  keycloak:
    volumes:
      - ${SANDBOX_CERT_MOUNT}
YAML
  KC_HOSTNAME="$public_url" KC_PROXY_HEADERS=xforwarded \
    docker compose -f docker-compose.yml -f "$OVERRIDE_FILE" up keycloak
else
  KC_HOSTNAME="$public_url" KC_PROXY_HEADERS=xforwarded docker compose up keycloak
fi
