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
Usage: scripts/run-demo-ngrok.sh [port] [--domain <name>] [--ngrok-only] [-- <maven args>]

Starts ngrok and the demo app (wallet + verifier) with a public HTTPS URL.
Useful for testing with mobile devices that need to reach your local server.

Options:
  --domain <name>  Use a custom ngrok domain (registered in your ngrok account).
  --ngrok-only     Start only ngrok and print env vars to copy/paste.

Defaults:
  - port: $PORT or 3000
  - maven: mvn -pl demo-app -Dspring-boot.run.fork=false spring-boot:run

Examples:
  scripts/run-demo-ngrok.sh
  scripts/run-demo-ngrok.sh 3000
  scripts/run-demo-ngrok.sh --domain myapp.ngrok-free.app
  scripts/run-demo-ngrok.sh 3000 --domain myapp.ngrok-free.app --ngrok-only
  scripts/run-demo-ngrok.sh 3000 -- -Dspring-boot.run.profiles=dev
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

maybe_init_sdkman() {
  if command -v mvn >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
    return 0
  fi
  if [ -f "$HOME/.sdkman/bin/sdkman-init.sh" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.sdkman/bin/sdkman-init.sh" >/dev/null 2>&1 || true
  fi
}

PORT="${PORT:-3000}"
PORT_SET=0
NGROK_ONLY=false
NGROK_DOMAIN=""

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
    --ngrok-only|--tunnel-only|--no-app)
      NGROK_ONLY=true
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      if [ "$PORT_SET" -eq 1 ]; then
        echo "Unexpected argument: $1" >&2
        usage >&2
        exit 2
      fi
      case "$1" in
        ''|*[!0-9]*)
          echo "Unexpected argument: $1" >&2
          usage >&2
          exit 2
          ;;
        *)
          PORT="$1"
          PORT_SET=1
          shift
          ;;
      esac
      ;;
  esac
done

case "$PORT" in
  ''|*[!0-9]*)
    echo "Invalid port: $PORT" >&2
    usage >&2
    exit 2
    ;;
esac

require_cmd ngrok
require_cmd curl
require_cmd jq

tmp_log="$(mktemp -t verifier-ngrok.XXXXXX.log)"

cleanup() {
  if [ -n "${APP_PID:-}" ]; then
    kill "${APP_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${NGROK_PID:-}" ]; then
    kill "${NGROK_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "$tmp_log" >/dev/null 2>&1 || true
}

trap cleanup INT TERM EXIT

NGROK_ARGS="http $PORT --log=stdout --log-format=json"
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

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$ROOT_DIR/target"
keys_file="$ROOT_DIR/target/verifier-keys-ngrok-$timestamp.json"

export PORT="$PORT"
export WALLET_PUBLIC_BASE_URL="$public_url"
export VERIFIER_KEYS_FILE="$keys_file"

cat <<EOF
ngrok is running (pid $NGROK_PID)

Public URL:
  $public_url

Verifier UI:
  $public_url/verifier

Conformance UI:
  $public_url/verifier/conformance

ngrok dashboard:
  http://127.0.0.1:4040

Env (applied to the app process):
  PORT=$PORT
  WALLET_PUBLIC_BASE_URL=$WALLET_PUBLIC_BASE_URL
  VERIFIER_KEYS_FILE=$VERIFIER_KEYS_FILE
EOF

if [ "$NGROK_ONLY" = "true" ]; then
  if [ $# -gt 0 ]; then
    echo "" >&2
    echo "Unexpected arguments after --ngrok-only. If you meant to pass maven args, remove --ngrok-only." >&2
    usage >&2
    exit 2
  fi

  cat <<EOF

Suggested env to copy/paste (for an IDE / another terminal):
  export PORT=$PORT
  export WALLET_PUBLIC_BASE_URL=$WALLET_PUBLIC_BASE_URL
  export VERIFIER_KEYS_FILE=$VERIFIER_KEYS_FILE

Press Ctrl+C to stop ngrok.
EOF
  wait "$NGROK_PID"
  exit 0
fi

maybe_init_sdkman
require_cmd mvn

cd "$ROOT_DIR"

mvn -pl demo-app -Dspring-boot.run.fork=false spring-boot:run "$@" &
APP_PID="$!"

wait "$APP_PID"
