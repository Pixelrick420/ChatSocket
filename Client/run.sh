#!/bin/bash

echo "Compiling client..."
gcc client.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c -o client -lpthread -lssl -lcrypto
if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Connecting to localhost:2077..."
    ./client
else
    echo "Connecting to $1..."
    ./client $1
fi