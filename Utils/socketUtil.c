#include "socketUtil.h"

pthread_mutex_t printLock = PTHREAD_MUTEX_INITIALIZER;
void print(char *message)
{
    pthread_mutex_lock(&printLock);
    printf("%s", message);
    fflush(stdout);
    pthread_mutex_unlock(&printLock);
}

int createTCPIPv4Socket()
{
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        print("Error creating socket\n");
        exit(EXIT_FAILURE);
    }
    return socketFD;
}

SocketAddress *getSocketAddress(char *ipAddr, int port, bool isClient)
{
    SocketAddress *address = (SocketAddress *)malloc(sizeof(SocketAddress));

    if (!address)
    {
        print("Malloc failed\n");
        exit(EXIT_FAILURE);
    }

    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (isClient)
    {
        int result = inet_pton(AF_INET, ipAddr, &address->sin_addr.s_addr);
        if (result <= 0)
        {
            print("Invalid IP address\n");
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
        print("Connection failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int bindServerToSocket(int socketFD, SocketAddress *address, int size)
{
    int result = bind(socketFD, (struct sockaddr *)address, size);
    if (result != 0)
    {
        print("Socket bind failed\n");
        exit(EXIT_FAILURE);
    }
    return result;
}

Client *createClient(int socketFD, SocketAddress *clientAddr)
{
    Client *client = (Client *)malloc(sizeof(Client));

    int clientAddrSize = sizeof(*clientAddr);
    client->address = (clientAddr);
    client->socketFD = accept(socketFD, (struct sockaddr *)clientAddr, &clientAddrSize);
    client->success = (client->socketFD > 0);

    if (!client->success)
    {
        client->error = client->socketFD;
    }
    return client;
}
