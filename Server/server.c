#include "../Utils/socketUtil.h"

char *LOCALHOST = "0.0.0.0";
int BACKLOG = 10;
int MAX_CLIENTS = 32;
ServerContext *globalContext = NULL;

void handleHelp(Client *client)
{
    char response[MSG_SIZE];
    snprintf(response, MSG_SIZE,
             "Commands:\n"
             "/help - Show this help\n"
             "/create <room> -p <password> - Create room\n"
             "/enter <room> - Enter room\n"
             "/leave - Leave current room\n"
             "/exit - Exit\n"
             "/name <name> - Set your name\n");
    send(client->socketFD, response, strlen(response), 0);
}

void handleName(Client *client, char *buffer)
{
    char response[MSG_SIZE];
    sscanf(buffer + 6, "%63s", client->name);
    snprintf(response, MSG_SIZE, "Name set to: %s\n", client->name);
    send(client->socketFD, response, strlen(response), 0);
}

void handleCreate(Client *client, char *buffer)
{
    char roomName[64] = {0};
    char password[64] = {0};
    char response[MSG_SIZE];
    char *pFlag = strstr(buffer + 8, " -p ");

    if (pFlag)
    {
        sscanf(buffer + 8, "%63s", roomName);
        sscanf(pFlag + 4, "%63s", password);
    }
    else
    {
        sscanf(buffer + 8, "%63s", roomName);
    }

    pthread_mutex_lock(&globalContext->mutex);
    if (findRoom(globalContext, roomName) != -1)
    {
        snprintf(response, MSG_SIZE, "Room '%s' already exists\n", roomName);
    }
    else
    {
        Room *room = createRoom(roomName, pFlag ? password : NULL);
        globalContext->rooms[globalContext->roomCount++] = room;
        snprintf(response, MSG_SIZE, "Room '%s' created\n", roomName);
    }
    pthread_mutex_unlock(&globalContext->mutex);
    send(client->socketFD, response, strlen(response), 0);
}

void handleEnter(Client *client, char *buffer)
{
    char roomName[64];
    char response[MSG_SIZE];
    sscanf(buffer + 7, "%63s", roomName);

    pthread_mutex_lock(&globalContext->mutex);
    int roomIdx = findRoom(globalContext, roomName);

    if (roomIdx == -1)
    {
        snprintf(response, MSG_SIZE, "Room '%s' does not exist\n", roomName);
        pthread_mutex_unlock(&globalContext->mutex);
        send(client->socketFD, response, strlen(response), 0);
        return;
    }

    Room *room = globalContext->rooms[roomIdx];

    if (room->hasPassword)
    {
        char *prompt = "Password: ";
        send(client->socketFD, prompt, strlen(prompt), 0);
        pthread_mutex_unlock(&globalContext->mutex);

        char inputPass[64];
        size_t passLen = recv(client->socketFD, inputPass, 63, 0);
        if (passLen > 0)
        {
            inputPass[passLen - 1] = 0;
            pthread_mutex_lock(&globalContext->mutex);

            if (strcmp(room->password, inputPass) == 0)
            {
                client->currentRoom = roomIdx;
                room->members[room->memberCount++] = client->socketFD;
                snprintf(response, MSG_SIZE, "Entered room '%s'\n", roomName);
            }
            else
            {
                snprintf(response, MSG_SIZE, "Incorrect password\n");
            }
            pthread_mutex_unlock(&globalContext->mutex);
            send(client->socketFD, response, strlen(response), 0);
        }
    }
    else
    {
        client->currentRoom = roomIdx;
        room->members[room->memberCount++] = client->socketFD;
        snprintf(response, MSG_SIZE, "Entered room '%s'\n", roomName);
        pthread_mutex_unlock(&globalContext->mutex);
        send(client->socketFD, response, strlen(response), 0);
    }
}

void handleLeave(Client *client)
{
    if (client->currentRoom == -1)
    {
        char *msg = "Not in a room\n";
        send(client->socketFD, msg, strlen(msg), 0);
        return;
    }

    pthread_mutex_lock(&globalContext->mutex);
    Room *room = globalContext->rooms[client->currentRoom];

    for (int i = 0; i < room->memberCount; i++)
    {
        if (room->members[i] == client->socketFD)
        {
            room->members[i] = room->members[room->memberCount - 1];
            room->memberCount--;
            break;
        }
    }

    client->currentRoom = -1;
    pthread_mutex_unlock(&globalContext->mutex);
    char *msg = "Left Room\n";
    send(client->socketFD, msg, strlen(msg), 0);
}

void handleMessage(Client *client, char *buffer)
{
    if (client->currentRoom == -1)
    {
        char *msg = "Not in a room. Use /enter <room>\n";
        send(client->socketFD, msg, strlen(msg), 0);
        return;
    }

    char response[MSG_SIZE];
    snprintf(response, MSG_SIZE, "%s: %s", client->name, buffer);
    broadcastToRoom(globalContext, client->currentRoom, client->socketFD, response, strlen(response));
}

CommandType parseCommand(char *buffer)
{
    if (buffer[0] != '/')
        return CMD_MESSAGE;

    if (strncmp(buffer, "/help", 5) == 0)
        return CMD_HELP;
    if (strncmp(buffer, "/name ", 6) == 0)
        return CMD_NAME;
    if (strncmp(buffer, "/create ", 8) == 0)
        return CMD_CREATE;
    if (strncmp(buffer, "/enter ", 7) == 0)
        return CMD_ENTER;
    if (strncmp(buffer, "/leave", 6) == 0)
        return CMD_LEAVE;
    if (strncmp(buffer, "/exit", 5) == 0)
        return CMD_EXIT;

    return CMD_UNKNOWN;
}

void cleanupClientRoom(Client *client)
{
    if (client->currentRoom == -1)
        return;

    pthread_mutex_lock(&globalContext->mutex);
    Room *room = globalContext->rooms[client->currentRoom];

    for (int i = 0; i < room->memberCount; i++)
    {
        if (room->members[i] == client->socketFD)
        {
            room->members[i] = room->members[room->memberCount - 1];
            room->memberCount--;
            break;
        }
    }
    pthread_mutex_unlock(&globalContext->mutex);
}

void *handleClient(void *arg)
{
    Client *client = (Client *)arg;
    char *buffer = (char *)malloc(sizeof(char) * MSG_SIZE);
    bool running = true;

    while (running)
    {
        size_t received = recv(client->socketFD, buffer, MSG_SIZE, 0);
        if (received <= 0)
            break;

        buffer[received] = 0;

        CommandType cmd = parseCommand(buffer);

        switch (cmd)
        {
        case CMD_HELP:
            handleHelp(client);
            break;

        case CMD_NAME:
            handleName(client, buffer);
            break;

        case CMD_CREATE:
            handleCreate(client, buffer);
            break;

        case CMD_ENTER:
            handleEnter(client, buffer);
            break;

        case CMD_LEAVE:
            handleLeave(client);
            break;

        case CMD_EXIT:
            running = false;
            break;

        case CMD_MESSAGE:
            handleMessage(client, buffer);
            break;

        case CMD_UNKNOWN:
            char *msg = "Unknown command. Type /help for help\n";
            send(client->socketFD, msg, strlen(msg), 0);
            break;
        }
    }

    cleanupClientRoom(client);
    free(buffer);
    removeClient(globalContext, client->socketFD);
    close(client->socketFD);
    free(client);
    return NULL;
}

void *cleanupThread(void *arg)
{
    while (true)
    {
        sleep(600);
        cleanupInactiveRooms(globalContext);
    }
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

    globalContext = createContext(serverSocketFD, MAX_CLIENTS);

    pthread_t cleanupTid;
    pthread_create(&cleanupTid, NULL, cleanupThread, NULL);
    pthread_detach(cleanupTid);

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