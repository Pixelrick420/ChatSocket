#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

DEFAULT_HOST="127.0.0.1"
DEFAULT_PORT="2077"

echo -e "${GREEN}SocketChat Client Builder${NC}"
echo "================================"
echo -e "${YELLOW}Compiling client...${NC}"
gcc client.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c -o client -lpthread -lssl -lcrypto

if [ $? -ne 0 ]; then
    echo -e "${RED}Compilation failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Compilation successful!${NC}"
echo ""

if [ $# -eq 0 ]; then
    echo -e "${YELLOW}No connection details provided. Using defaults.${NC}"
    echo -e "Usage: $0 <host/domain> <port>"
    echo -e "Example: $0 0.tcp.ngrok.io 12345"
    echo ""
    echo -e "Connecting to ${GREEN}${DEFAULT_HOST}:${DEFAULT_PORT}${NC}"
    ./client "$DEFAULT_HOST" "$DEFAULT_PORT"
elif [ $# -eq 1 ]; then
    echo -e "${RED}Error: Port number required when specifying host${NC}"
    echo -e "Usage: $0 <host/domain> <port>"
    echo -e "Example: $0 0.tcp.ngrok.io 12345"
    exit 1
elif [ $# -eq 2 ]; then
    HOST="$1"
    PORT="$2"
    echo -e "Connecting to ${GREEN}${HOST}:${PORT}${NC}"
    ./client "$HOST" "$PORT"
else
    echo -e "${RED}Error: Too many arguments${NC}"
    echo -e "Usage: $0 <host/domain> <port>"
    echo -e "Example: $0 0.tcp.ngrok.io 12345"
    exit 1
fi