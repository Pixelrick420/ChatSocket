#include "../Utils/socketUtil.h"

char *LOCALHOST = "0.0.0.0";
int BACKLOG = 10;
int MAX_CLIENTS = 32;

typedef struct
{
    int socketFD;
    pthread_mutex_t mutex;
    Client **clients;
    size_t clientCount;
} ServerContext;

ServerContext *globalContext = NULL;

ServerContext *createContext(int socketFD)
{
    ServerContext *context = (ServerContext *)malloc(sizeof(ServerContext));
    context->clients = (Client **)malloc(sizeof(Client *) * MAX_CLIENTS);
    context->socketFD = socketFD;
    context->clientCount = 0;
    pthread_mutex_init(&context->mutex, NULL);
    return context;
}

void cleanupServer(ServerContext *context)
{
    pthread_mutex_destroy(&context->mutex);
    free(context->clients);
    free(context);
}

int addClient(ServerContext *context, Client *client)
{
    pthread_mutex_lock(&context->mutex);
    if (context->clientCount >= MAX_CLIENTS)
    {
        pthread_mutex_unlock(&context->mutex);
        return -1;
    }
    context->clients[context->clientCount++] = client;
    pthread_mutex_unlock(&context->mutex);
    return 0;
}

void removeClient(ServerContext *context, int socketFD)
{
    pthread_mutex_lock(&context->mutex);
    for (size_t i = 0; i < context->clientCount; i++)
    {
        if (context->clients[i]->socketFD == socketFD)
        {
            context->clients[i] = context->clients[context->clientCount - 1];
            context->clientCount--;
            break;
        }
    }
    pthread_mutex_unlock(&context->mutex);
}

void broadcastMessage(ServerContext *context, int senderFD, const char *msg, size_t len)
{
    pthread_mutex_lock(&context->mutex);
    for (size_t i = 0; i < context->clientCount; i++)
    {
        int fd = context->clients[i]->socketFD;
        if (fd != senderFD)
        {
            send(fd, msg, len, 0);
        }
    }
    pthread_mutex_unlock(&context->mutex);
}

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
            broadcastMessage(globalContext, client->socketFD, buffer, received);
        }
        else
        {
            break;
        }
    }

    free(buffer);
    removeClient(globalContext, client->socketFD);
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

    globalContext = createContext(serverSocketFD);

    while (true)
    {
        SocketAddress clientAddr;
        Client *client = createClient(serverSocketFD, &clientAddr);

        addClient(globalContext, client);
        pthread_t id;
        pthread_create(&id, NULL, handleClient, client);
        pthread_detach(id);
    }

    shutdown(serverSocketFD, SHUT_RDWR);
    free(address);
    return 0;
}