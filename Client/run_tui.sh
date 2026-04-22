#!/bin/bash
cd "$(dirname "$0")"

echo "Building TUI client..."
gcc client_tui.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c ../Utils/identity.c ../Utils/tls.c ../Utils/ecdh.c ../Utils/history.c -o client_tui -lpthread -lssl -lcrypto -lncurses

if [ $? -eq 0 ]; then
    echo "Build successful!"
    if [ -n "$1" ]; then
        echo "Connecting to $1..."
        ./client_tui "$1"
    else
        echo "Running client (connecting to 127.0.0.1:2077)..."
        ./client_tui
    fi
else
    echo "Build failed!"
    exit 1
fi