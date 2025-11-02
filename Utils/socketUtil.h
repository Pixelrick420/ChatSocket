#ifndef SOCKETUTIL_H
#define SOCKETUTIL_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

#define MSG_SIZE 2048
#define PORT 2077

typedef struct sockaddr_in SocketAddress;
typedef struct AcceptedSocket
{
    int socketFD;
    SocketAddress *address;
    int error;
    bool success;
} Client;

void print(char *message);
int createTCPIPv4Socket();
SocketAddress *getSocketAddress(char *ipAddr, int port, bool isClient);
int connectToSocket(int socketFD, SocketAddress *address, int size);
int bindServerToSocket(int socketFD, SocketAddress *address, int size);
Client *createClient(int socketFD, SocketAddress *clientAddr);

#endif