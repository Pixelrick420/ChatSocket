#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
DEFAULT_HOST="127.0.0.1"
DEFAULT_PORT="8080"

echo -e "${GREEN}SocketChat Client Builder${NC}"
echo "================================"

# Compile the client
echo -e "${YELLOW}Compiling client...${NC}"
gcc client.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c -o client -lpthread -lssl -lcrypto

if [ $? -ne 0 ]; then
    echo -e "${RED}Compilation failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Compilation successful!${NC}"
echo ""

# Check if arguments are provided
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
    
    # Check if HOST is already an IP address (simple check)
    if [[ $HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Already an IP address
        IP="$HOST"
        echo -e "Connecting to ${GREEN}${IP}:${PORT}${NC}"
    else
        # It's a domain name, resolve it
        echo -e "${YELLOW}Resolving domain ${HOST}...${NC}"
        
        # Try getent first (most reliable)
        IP=$(getent hosts "$HOST" 2>/dev/null | awk '{ print $1 ; exit }')
        
        # Fallback to dig if getent fails
        if [ -z "$IP" ]; then
            IP=$(dig +short "$HOST" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+
else
    echo -e "${RED}Error: Too many arguments${NC}"
    echo -e "Usage: $0 <host/domain> <port>"
    echo -e "Example: $0 0.tcp.ngrok.io 12345"
    exit 1
fi
 | head -n 1)
        fi
        
        # Fallback to nslookup if dig fails
        if [ -z "$IP" ]; then
            IP=$(nslookup "$HOST" 2>/dev/null | awk '/^Address: / { print $2 }' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+
else
    echo -e "${RED}Error: Too many arguments${NC}"
    echo -e "Usage: $0 <host/domain> <port>"
    echo -e "Example: $0 0.tcp.ngrok.io 12345"
    exit 1
fi
 | head -n 1)
        fi
        
        # Fallback to ping as last resort
        if [ -z "$IP" ]; then
            IP=$(ping -c 1 -W 2 "$HOST" 2>/dev/null | grep -oP '\(\K[0-9.]+(?=\))' | head -n 1)
        fi
        
        if [ -z "$IP" ]; then
            echo -e "${RED}Error: Could not resolve domain ${HOST}${NC}"
            echo -e "Please check your internet connection and domain name."
            exit 1
        fi
        
        echo -e "${GREEN}Resolved to IP: ${IP}${NC}"
        echo -e "Connecting to ${GREEN}${IP}:${PORT}${NC}"
    fi
    
    ./client "$IP" "$PORT"
else
    echo -e "${RED}Error: Too many arguments${NC}"
    echo -e "Usage: $0 <host/domain> <port>"
    echo -e "Example: $0 0.tcp.ngrok.io 12345"
    exit 1
fi