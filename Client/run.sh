#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Compiling client..."
gcc client.c \
    ../Utils/socketUtil.c \
    ../Utils/sha256.c \
    ../Utils/aes.c \
    ../Utils/identity.c \
    ../Utils/ecdh.c \
    ../Utils/history.c \
    ../Utils/tls.c \
    -o client \
    -lpthread -lssl -lcrypto \
    -Wall -Wextra -O2

echo "Compiled successfully."

# Check for -test flag as second argument
if [ "$2" = "-test" ]; then
    # Create temp HOME dir for test mode (allows multiple clients)
    TEST_DIR=$(mktemp -d)
    mkdir -p "$TEST_DIR/.socketchat"
    echo "Running in TEST mode (temp identity: $TEST_DIR)..."
    HOME="$TEST_DIR" ./client "$1"

    # Cleanup after client exits
    rm -rf "$TEST_DIR"
else
    if [ $# -eq 0 ]; then
        echo "Connecting to localhost:2077..."
        ./client
    else
        echo "Connecting to $1..."
        ./client "$1"
    fi
fi