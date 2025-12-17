#include "socketUtil.h"

static pthread_mutex_t printLock = PTHREAD_MUTEX_INITIALIZER;

// print with mutex lock
void print(char* message)
{
    pthread_mutex_lock(&printLock);
    printf("%s", message);
    fflush(stdout);
    pthread_mutex_unlock(&printLock);
}

// socket management functions

int createTCPSocket(void)
{
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        print("Error creating socket\n");
        exit(EXIT_FAILURE);
    }
    return socketFD;
}

SocketAddress* createSocketAddress(char* ipAddr, int port, bool isClient)
{
    SocketAddress* address = malloc(sizeof(SocketAddress));
    if (!address)
    {
        print("Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    memset(address, 0, sizeof(SocketAddress));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);

    if (isClient)
    {
        if (inet_pton(AF_INET, ipAddr, &address->sin_addr.s_addr) <= 0)
        {
            print("Invalid IP address\n");
            free(address);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        address->sin_addr.s_addr = INADDR_ANY;
    }

    return address;
}

int connectSocket(int socketFD, SocketAddress* address)
{
    if (connect(socketFD, (struct sockaddr*) address, sizeof(*address)) != 0)
    {
        print("Connection failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int bindSocket(int socketFD, SocketAddress* address)
{
    if (bind(socketFD, (struct sockaddr*) address, sizeof(*address)) != 0)
    {
        perror("Socket bind failed");
        exit(EXIT_FAILURE);
    }
    return 0;
}

Client* acceptClient(int serverSocketFD)
{
    Client* client = malloc(sizeof(Client));
    if (!client)
    {
        print("Memory allocation failed\n");
        return NULL;
    }

    SocketAddress* clientAddr = malloc(sizeof(SocketAddress));
    if (!clientAddr)
    {
        free(client);
        return NULL;
    }

    socklen_t addrSize = sizeof(*clientAddr);
    client->socketFD = accept(serverSocketFD, (struct sockaddr*) clientAddr, &addrSize);
    client->address = clientAddr;
    client->success = (client->socketFD > 0);
    client->currentRoom = -1;
    client->error = client->success ? 0 : client->socketFD;

    snprintf(client->name, MAX_NAME_LEN, "User%d", rand() % 10000);

    return client;
}

// server management
ServerContext* createServerContext(int socketFD, int maxClients, int maxRooms)
{
    ServerContext* context = malloc(sizeof(ServerContext));
    if (!context)
    {
        print("Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    context->socketFD = socketFD;
    context->maxClients = maxClients;
    context->maxRooms = maxRooms;
    context->clientCount = 0;
    context->roomCount = 0;

    context->clients = calloc(maxClients, sizeof(Client*));
    context->rooms = calloc(maxRooms, sizeof(Room*));

    if (!context->clients || !context->rooms)
    {
        print("Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_init(&context->mutex, NULL);
    return context;
}

void destroyServerContext(ServerContext* context)
{
    if (!context)
        return;

    pthread_mutex_destroy(&context->mutex);

    for (int i = 0; i < context->roomCount; i++)
    {
        destroyRoom(context->rooms[i]);
    }

    free(context->rooms);
    free(context->clients);
    free(context);
}

// client management
bool addClient(ServerContext* context, Client* client)
{
    pthread_mutex_lock(&context->mutex);

    if (context->clientCount >= context->maxClients)
    {
        pthread_mutex_unlock(&context->mutex);
        return false;
    }

    context->clients[context->clientCount++] = client;
    pthread_mutex_unlock(&context->mutex);
    return true;
}

void removeClient(ServerContext* context, int socketFD)
{
    pthread_mutex_lock(&context->mutex);

    for (size_t i = 0; i < context->clientCount; i++)
    {
        if (context->clients[i]->socketFD == socketFD)
        {
            context->clients[i] = context->clients[--context->clientCount];
            break;
        }
    }

    pthread_mutex_unlock(&context->mutex);
}

// room management
Room* createRoom(const char* name, const char* password)
{
    Room* room = malloc(sizeof(Room));
    if (!room)
        return NULL;

    strncpy(room->name, name, MAX_NAME_LEN - 1);
    room->name[MAX_NAME_LEN - 1] = '\0';

    room->hasPassword = (password != NULL && strlen(password) > 0);
    if (room->hasPassword)
    {
        strncpy(room->password, password, MAX_PASSWORD_LEN - 1);
        room->password[MAX_PASSWORD_LEN - 1] = '\0';
    }
    else
    {
        room->password[0] = '\0';
    }

    room->members = calloc(MAX_ROOM_MEMBERS, sizeof(int));
    if (!room->members)
    {
        free(room);
        return NULL;
    }

    room->memberCount = 0;
    room->maxMembers = MAX_ROOM_MEMBERS;
    room->lastActivity = time(NULL);

    return room;
}

void destroyRoom(Room* room)
{
    if (!room)
        return;
    free(room->members);
    free(room);
}

int findRoomIndex(ServerContext* context, const char* name)
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

bool addMemberToRoom(Room* room, int socketFD)
{
    if (room->memberCount >= room->maxMembers)
    {
        return false;
    }
    room->members[room->memberCount++] = socketFD;
    return true;
}

bool removeMemberFromRoom(Room* room, int socketFD)
{
    for (int i = 0; i < room->memberCount; i++)
    {
        if (room->members[i] == socketFD)
        {
            room->members[i] = room->members[--room->memberCount];
            return true;
        }
    }
    return false;
}

void updateRoomActivity(Room* room)
{
    room->lastActivity = time(NULL);
}

void cleanupInactiveRooms(ServerContext* context)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&context->mutex);

    for (int i = 0; i < context->roomCount; i++)
    {
        if (difftime(now, context->rooms[i]->lastActivity) > ROOM_TIMEOUT)
        {
            destroyRoom(context->rooms[i]);
            context->rooms[i] = context->rooms[--context->roomCount];
            i--;
        }
    }

    pthread_mutex_unlock(&context->mutex);
}

// broadcast function for server
void broadcastToRoom(ServerContext* context, int roomIdx, int senderFD, const char* msg)
{
    pthread_mutex_lock(&context->mutex);

    Room* room = context->rooms[roomIdx];
    updateRoomActivity(room);

    size_t msgLen = strlen(msg);
    for (int i = 0; i < room->memberCount; i++)
    {
        int fd = room->members[i];
        if (fd != senderFD)
        {
            send(fd, msg, msgLen, 0);
        }
    }

    pthread_mutex_unlock(&context->mutex);
}
