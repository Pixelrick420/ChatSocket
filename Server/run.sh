#!/bin/bash
PORT=2077

echo "Compiling server..."
gcc server.c ../Utils/socketUtil.c ../Utils/sha256.c -o server
if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

if [ "$1" == "ngrok" ]; then
    PORT=${2:-2077}
    
    if ! command -v ngrok &> /dev/null; then
        echo "ngrok is not installed. Install from: https://ngrok.com/download"
        exit 1
    fi
    
    ./server &
    SERVER_PID=$!
    sleep 2
    
    echo "Starting ngrok..."
    ngrok tcp $PORT > /dev/null &
    NGROK_PID=$!
    sleep 3
    
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"tcp://[^"]*' | cut -d'"' -f4 | head -n1)
    NGROK_ADDRESS=$(echo $NGROK_URL | sed 's/tcp:\/\///')
    
    echo "================================================"
    echo "Server Address: $NGROK_ADDRESS"
    echo "ngrok Dashboard: http://localhost:4040"
    echo "================================================"
    
    trap "kill $SERVER_PID $NGROK_PID 2>/dev/null" EXIT INT TERM
    
    wait $SERVER_PID
else
    ./server
fi