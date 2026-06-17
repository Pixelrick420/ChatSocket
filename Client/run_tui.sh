#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
. ../bootstrap.sh

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

echo "Building TUI client..."
"$BUILD_CC" client_tui.c \
    ../Utils/socketUtil.c \
    ../Utils/sha256.c \
    ../Utils/aes.c \
    ../Utils/contacts.c \
    ../Utils/identity.c \
    ../Utils/tls.c \
    ../Utils/ecdh.c \
    ../Utils/history.c \
    ../Utils/platform.c \
    ../Utils/protocol.c \
    -o client_tui \
    $(pkg-config --cflags --libs openssl) \
    -lpthread \
    -Wall -Wextra -O2

echo "Build successful!"

if [ "$TEST_MODE" -eq 1 ]; then
    TEST_DIR=$(mktemp -d)
    mkdir -p "$TEST_DIR/.socketchat"
    echo "Running TUI in TEST mode (temp identity: $TEST_DIR)..."
    if [ -n "$TARGET" ]; then
        HOME="$TEST_DIR" ./client_tui "$TARGET"
    else
        HOME="$TEST_DIR" ./client_tui
    fi
    rm -rf "$TEST_DIR"
else
    if [ -n "$TARGET" ]; then
        echo "Connecting to $TARGET..."
        ./client_tui "$TARGET"
    else
        echo "Running client (connecting to 127.0.0.1:2077)..."
        ./client_tui
    fi
fi
