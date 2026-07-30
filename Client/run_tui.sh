#!/bin/bash
set -euo pipefail
DEFAULT_SERVER="129.154.42.68:2077"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
. ./bootstrap.sh

ensure_build_prereqs

TARGET=""
TEST_MODE=0

for arg in "$@"; do
    case "$arg" in
        -test)
            TEST_MODE=1
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$arg"
            else
                echo "Usage: ./run_tui.sh [host:port] [-test]" >&2
                exit 1
            fi
            ;;
    esac
done

make CC="$BUILD_CC" build/client_tui
CLIENT_BIN="$ROOT_DIR/build/client_tui"

if [ "$TEST_MODE" -eq 1 ]; then
    TEST_DIR=$(mktemp -d)
    mkdir -p "$TEST_DIR/.socketchat"
    echo "Running TUI in TEST mode (temp identity: $TEST_DIR)..."
    if [ -n "$TARGET" ]; then
        HOME="$TEST_DIR" "$CLIENT_BIN" "$TARGET"
    else
        HOME="$TEST_DIR" "$CLIENT_BIN"
    fi
    rm -rf "$TEST_DIR"
else
    if [ -n "$TARGET" ]; then
        echo "Connecting to $TARGET..."
        "$CLIENT_BIN" "$TARGET"
    else
        echo "Connecting to $DEFAULT_SERVER..."
        "$CLIENT_BIN" "$DEFAULT_SERVER"
    fi
fi
