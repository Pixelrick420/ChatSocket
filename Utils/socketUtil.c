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

SocketAddress *getSocketAddress(char *ipAddr, int port, bool isClient)
{
    SocketAddress *address = (SocketAddress *)malloc(sizeof(SocketAddress));

    if (!address)
    {
        printf("Malloc failed\n");
        exit(EXIT_FAILURE);
    }

    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (isClient)
    {
        int result = inet_pton(AF_INET, ipAddr, &address->sin_addr.s_addr);
        if (result <= 0)
        {
            printf("Invalid IP address\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        address->sin_addr.s_addr = INADDR_ANY;
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

int bindServerToSocket(int socketFD, SocketAddress *address, int size)
{
    int result = bind(socketFD, (struct sockaddr *)address, size);
    if (result != 0)
    {
        printf("Socket bind failed\n");
        exit(EXIT_FAILURE);
    }
    return result;
}

int listenToClient(int socketFD, int backlog, SocketAddress *clientAddr)
{
    int listenRes = listen(socketFD, backlog);
    if (listenRes != 0)
    {
        printf("Error while listening\n");
        exit(EXIT_FAILURE);
    }

    int clientAddrSize = sizeof(*clientAddr);
    int clientSocketFD = accept(socketFD, (struct sockaddr *)clientAddr, &clientAddrSize);
    return clientSocketFD;
}
