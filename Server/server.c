#include "../Utils/socketUtil.h"

char *LOCALHOST = "127.0.0.1";
int BACKLOG = 10;

void *handleClient(void *arg)
{
    Client *client = (Client *)arg;

    char *buffer = (char *)malloc(sizeof(char) * MSG_SIZE);
    while (true)
    {
        size_t received = recv(client->socketFD, buffer, MSG_SIZE, 0);
        if (received > 0)
        {
            buffer[received] = 0;
            print(buffer);
        }
        else
        {
            break;
        }
    }

    free(buffer);
    close(client->socketFD);
    free(client);
    return NULL;
}

int main()
{
    int serverSocketFD = createTCPIPv4Socket();
    SocketAddress *address = getSocketAddress(LOCALHOST, PORT, false);
    bindServerToSocket(serverSocketFD, address, sizeof(*address));

    if (listen(serverSocketFD, BACKLOG) != 0)
    {
        print("Error while listening\n");
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        SocketAddress clientAddr;
        Client *client = createClient(serverSocketFD, &clientAddr);

        pthread_t id;
        pthread_create(&id, NULL, handleClient, client);
        pthread_detach(id);
    }

    shutdown(serverSocketFD, SHUT_RDWR);
    free(address);
    return 0;
}