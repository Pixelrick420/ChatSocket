#!/bin/bash

gcc client.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c -o client -lpthread -lssl -lcrypto || exit 1

if [ $# -eq 0 ]; then
    ./client "127.0.0.1" "8080"
elif [ $# -eq 2 ]; then
    HOST="$1"
    PORT="$2"
    
    if [[ ! $HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        IP=$(getent hosts "$HOST" | awk '{ print $1 ; exit }')
        [ -z "$IP" ] && IP=$(dig +short "$HOST" | head -n 1)
        [ -z "$IP" ] && IP=$(nslookup "$HOST" 2>/dev/null | awk '/^Address: / { print $2 }' | head -n 1)
        HOST="${IP:-$HOST}"
    fi
    
    ./client "$HOST" "$PORT"
else
    echo "Usage: $0 <host> <port>"
    exit 1
fi