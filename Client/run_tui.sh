#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
. ../bootstrap.sh

ensure_build_prereqs

TARGET=${1:-}

echo "Building TUI client..."
"$BUILD_CC" client_tui.c \
    ../Utils/socketUtil.c \
    ../Utils/sha256.c \
    ../Utils/aes.c \
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

if [ $? -eq 0 ]; then
    echo "Build successful!"
    if [ -n "$TARGET" ]; then
        echo "Connecting to $TARGET..."
        ./client_tui "$TARGET"
    else
        echo "Running client (connecting to 127.0.0.1:2077)..."
        ./client_tui
    fi
else
    echo "Build failed!"
    exit 1
fi
