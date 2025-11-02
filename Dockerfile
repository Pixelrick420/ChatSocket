FROM gcc:latest

WORKDIR /app

COPY Utils/ ./Utils/

COPY Server/ ./Server/

WORKDIR /app/Server

RUN gcc -o server server.c ../Utils/socketUtil.c ../Utils/sha256.c -lpthread

EXPOSE 2077

CMD ["./server"]
