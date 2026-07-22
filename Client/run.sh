#!/bin/bash
set -euo pipefail

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
                echo "Usage: ./run.sh [host:port] [-test]" >&2
                exit 1
            fi
            ;;
    esac
done

make CC="$BUILD_CC" build/client
CLIENT_BIN="$ROOT_DIR/build/client"

if [ "$TEST_MODE" -eq 1 ]; then
    # Create temp HOME dir for test mode (allows multiple clients)
    TEST_DIR=$(mktemp -d)
    mkdir -p "$TEST_DIR/.socketchat"
    echo "Running in TEST mode (temp identity: $TEST_DIR)..."
    if [ -n "$TARGET" ]; then
        HOME="$TEST_DIR" "$CLIENT_BIN" "$TARGET"
    else
        HOME="$TEST_DIR" "$CLIENT_BIN"
    fi

    # Cleanup after client exits
    rm -rf "$TEST_DIR"
else
    if [ -z "$TARGET" ]; then
        echo "Connecting to localhost:2077..."
        "$CLIENT_BIN"
    else
        echo "Connecting to $TARGET..."
        "$CLIENT_BIN" "$TARGET"
    fi
fi
