#include "socketUtil.h"

int createTCPIPv4Socket()
{
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        printf("Error creating socket\n");
        exit(EXIT_FAILURE);
    }
    return socketFD;
}

SocketAddress *getSocketAddress(char *ipAddr, int port)
{
    SocketAddress *address = (SocketAddress *)malloc(sizeof(SocketAddress));

    if (!address)
    {
        printf("Malloc failed\n");
        exit(EXIT_FAILURE);
    }

    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (inet_pton(AF_INET, ipAddr, &address->sin_addr.s_addr) <= 0)
    {
        printf("Invalid IP address\n");
        exit(EXIT_FAILURE);
    }

    return address;
}

int connectToSocket(int socketFD, SocketAddress *address, int size)
{
    if (connect(socketFD, (struct sockaddr *)address, size) != 0)
    {
        printf("Connection failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}