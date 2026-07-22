#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
. ./bootstrap.sh

ensure_build_prereqs

PORT=${PORT:-2077}

make CC="$BUILD_CC" build/server
SERVER_BIN="$ROOT_DIR/build/server"

if [ "${1:-}" = "ngrok" ]; then
    NGROK_PORT=${2:-$PORT}

    if ! command -v ngrok &>/dev/null; then
        echo "ngrok is not installed. Get it from: https://ngrok.com/download"
        exit 1
    fi

    PORT=$NGROK_PORT "$SERVER_BIN" &
    SERVER_PID=$!
    sleep 2

    echo "Starting ngrok tunnel on port $NGROK_PORT..."
    ngrok tcp "$NGROK_PORT" >/dev/null &
    NGROK_PID=$!
    sleep 3

    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels \
        | grep -o '"public_url":"tcp://[^"]*' \
        | cut -d'"' -f4 \
        | head -n1)
    NGROK_ADDRESS=${NGROK_URL#tcp://}

    echo "================================================"
    echo "Server address : $NGROK_ADDRESS"
    echo "ngrok dashboard: http://localhost:4040"
    echo "================================================"

    trap "kill \$SERVER_PID \$NGROK_PID 2>/dev/null" EXIT INT TERM
    wait $SERVER_PID
else
    PORT=$PORT "$SERVER_BIN"
fi
