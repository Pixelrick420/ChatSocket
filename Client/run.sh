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
    -o client \
    -lpthread -lssl -lcrypto \
    -Wall -Wextra -O2

echo "Compiled successfully."

if [ $# -eq 0 ]; then
    echo "Connecting to localhost:2077..."
    ./client
else
    echo "Connecting to $1..."
    ./client "$1"
fi
