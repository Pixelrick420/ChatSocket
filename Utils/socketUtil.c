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
    snprintf(client->name, 10, "Sock%d", rand());

    client->currentRoom = -1;

    if (!client->success)
    {
        client->error = client->socketFD;
    }
    return client;
}

void recieveMessages(int socketFD)
{
    char *buffer = (char *)malloc(sizeof(char) * MSG_SIZE);
    while (true)
    {
        size_t received = recv(socketFD, buffer, MSG_SIZE, 0);
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
}

ServerContext *createContext(int socketFD, int size)
{
    ServerContext *context = (ServerContext *)malloc(sizeof(ServerContext));
    context->size = size;
    context->clients = (Client **)malloc(sizeof(Client *) * context->size);
    context->socketFD = socketFD;
    context->clientCount = 0;
    context->rooms = (Room **)malloc(sizeof(Room *) * 50);
    context->roomCount = 0;
    context->maxRooms = 50;
    pthread_mutex_init(&context->mutex, NULL);
    return context;
}
void cleanupServer(ServerContext *context)
{
    pthread_mutex_destroy(&context->mutex);
    for (int i = 0; i < context->roomCount; i++)
    {
        free(context->rooms[i]->members);
        free(context->rooms[i]);
    }
    free(context->rooms);
    free(context->clients);
    free(context);
}

int addClient(ServerContext *context, Client *client)
{
    pthread_mutex_lock(&context->mutex);
    if (context->clientCount >= context->size)
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

Room *createRoom(const char *name, const char *password)
{
    Room *room = (Room *)malloc(sizeof(Room));
    strcpy(room->name, name);
    room->hasPassword = (password != NULL && strlen(password) > 0);
    if (room->hasPassword)
    {
        strcpy(room->password, password);
    }
    room->members = (int *)malloc(sizeof(int) * 32);
    room->memberCount = 0;
    room->maxMembers = 32;
    room->lastActivity = time(NULL);
    return room;
}

int findRoom(ServerContext *context, const char *name)
{
    for (int i = 0; i < context->roomCount; i++)
    {
        if (strcmp(context->rooms[i]->name, name) == 0)
        {
            return i;
        }
    }
    return -1;
}

void cleanupInactiveRooms(ServerContext *context)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&context->mutex);
    for (int i = 0; i < context->roomCount; i++)
    {
        if (difftime(now, context->rooms[i]->lastActivity) > 3600)
        {
            free(context->rooms[i]->members);
            free(context->rooms[i]);
            context->rooms[i] = context->rooms[context->roomCount - 1];
            context->roomCount--;
            i--;
        }
    }
    pthread_mutex_unlock(&context->mutex);
}

void broadcastToRoom(ServerContext *context, int roomIdx, int senderFD, const char *msg, size_t len)
{
    pthread_mutex_lock(&context->mutex);
    Room *room = context->rooms[roomIdx];
    room->lastActivity = time(NULL);
    for (int i = 0; i < room->memberCount; i++)
    {
        int fd = room->members[i];
        if (fd != senderFD)
        {
            send(fd, msg, len, 0);
        }
    }
    pthread_mutex_unlock(&context->mutex);
}
