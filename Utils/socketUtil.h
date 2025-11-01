#ifndef SOCKETUTIL_H
#define SOCKETUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>

typedef struct sockaddr_in SocketAddress;

int createTCPIPv4Socket();
SocketAddress *getSocketAddress(char *ipAddr, int port, bool isClient);
int connectToSocket(int socketFD, SocketAddress *address, int size);
int bindServerToSocket(int socketFD, SocketAddress *address, int size);
int listenToClient(int socketFD, int backlog, SocketAddress *clientAddr);

#endif