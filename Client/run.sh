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
                echo "Usage: ./run.sh [host:port] [-test]" >&2
                exit 1
            fi
            ;;
    esac
done

echo "Compiling client..."
"$BUILD_CC" client.c \
    ../Utils/socketUtil.c \
    ../Utils/sha256.c \
    ../Utils/aes.c \
    ../Utils/identity.c \
    ../Utils/ecdh.c \
    ../Utils/history.c \
    ../Utils/tls.c \
    ../Utils/platform.c \
    ../Utils/protocol.c \
    -o client \
    $(pkg-config --cflags --libs openssl) \
    -lpthread \
    -Wall -Wextra -O2

echo "Compiled successfully."

if [ "$TEST_MODE" -eq 1 ]; then
    # Create temp HOME dir for test mode (allows multiple clients)
    TEST_DIR=$(mktemp -d)
    mkdir -p "$TEST_DIR/.socketchat"
    echo "Running in TEST mode (temp identity: $TEST_DIR)..."
    if [ -n "$TARGET" ]; then
        HOME="$TEST_DIR" ./client "$TARGET"
    else
        HOME="$TEST_DIR" ./client
    fi

    # Cleanup after client exits
    rm -rf "$TEST_DIR"
else
    if [ -z "$TARGET" ]; then
        echo "Connecting to localhost:2077..."
        ./client
    else
        echo "Connecting to $TARGET..."
        ./client "$TARGET"
    fi
fi
