#include "../Utils/sha256.h"
#include "../Utils/socketUtil.h"

#define LOCALHOST "0.0.0.0"
#define BACKLOG 10
#define MAX_CLIENTS 32
#define MAX_ROOMS 50

static ServerContext* g_context = NULL;

static void sendResponse(int socketFD, const char* message)
{
    send(socketFD, message, strlen(message), 0);
}

static void formatResponse(char* buffer, size_t size, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, size, format, args);
    va_end(args);
}

static Client* findClient(int socketFD)
{
    for (size_t i = 0; i < g_context->clientCount; i++)
    {
        if (g_context->clients[i]->socketFD == socketFD)
        {
            return g_context->clients[i];
        }
    }
    return NULL;
}

static void leaveCurrentRoom(Client* client)
{
    if (client->currentRoom == -1)
        return;

    pthread_mutex_lock(&g_context->mutex);
    Room* room = g_context->rooms[client->currentRoom];
    removeMemberFromRoom(room, client->socketFD);
    client->currentRoom = -1;
    pthread_mutex_unlock(&g_context->mutex);
}

static CommandType parseCommand(const char* buffer)
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

static void trimNewlines(char* str)
{
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r'))
    {
        str[--len] = '\0';
    }
}

bool isWhiteSpace(char* str)
{
    trimNewlines(str);
    int n = strlen(str);
    for (int i = 0; i < n; i++)
    {
        if (!isspace((unsigned char) str[i]))
        {
            return false;
        }
    }
    return true;
}

static void cmdHelp(Client* client)
{
    char response[MSG_SIZE];
    formatResponse(response, MSG_SIZE,
                   "RESCommands:\n"
                   "/help - Show this help\n"
                   "/create <room> -p <password> - Create room\n"
                   "/enter <room> - Enter room\n"
                   "/leave - Leave current room\n"
                   "/exit - Exit\n"
                   "/name <name> - Set your name\n");
    sendResponse(client->socketFD, response);
}

static void cmdSetName(Client* client, const char* buffer)
{
    char newName[MAX_NAME_LEN] = {0};
    char response[MSG_SIZE] = {0};

    bool cpySuccess = sscanf(buffer + 6, "%63s", newName);
    if (cpySuccess && !isWhiteSpace(newName))
    {
        strncpy(client->name, newName, MAX_NAME_LEN - 1);
        client->name[MAX_NAME_LEN - 1] = '\0';

        formatResponse(response, MSG_SIZE, "RESName Set to: %s\n", client->name);
        sendResponse(client->socketFD, response);
    }
    else
    {
        formatResponse(response, MSG_SIZE, "RESName Cannot be Empty\n");
        sendResponse(client->socketFD, response);
    }
}

static void cmdCreateRoom(Client* client, char* buffer)
{
    char roomName[MAX_NAME_LEN] = {0};
    char password[MAX_NAME_LEN] = {0};
    char response[MSG_SIZE];

    password[0] = '\0';

    trimNewlines(buffer);
    sscanf(buffer + 8, "%63s", roomName);
    char* passwordFlag = strstr(buffer + 8, " -p ");

    pthread_mutex_lock(&g_context->mutex);
    if (isWhiteSpace(roomName))
    {
        formatResponse(response, MSG_SIZE, "RESRoom Name Cannot be Empty\n");
        pthread_mutex_unlock(&g_context->mutex);
        sendResponse(client->socketFD, response);
        return;
    }

    if (passwordFlag)
    {
        sscanf(passwordFlag + 4, "%63s", password);
    }

    if (findRoomIndex(g_context, roomName) != -1)
    {
        formatResponse(response, MSG_SIZE, "RESRoom '%s' Already Exists\n", roomName);
        pthread_mutex_unlock(&g_context->mutex);
        sendResponse(client->socketFD, response);
        return;
    }

    Room* room;
    if (!isWhiteSpace(password) && strlen(password) > 0)
    {
        char* hashedPass = createHashedPass(roomName, password);
        if (!hashedPass)
        {
            formatResponse(response, MSG_SIZE, "ERRFailed to Create Room (hash error)\n");
            pthread_mutex_unlock(&g_context->mutex);
            sendResponse(client->socketFD, response);
            return;
        }
        room = createRoom(roomName, hashedPass);
        free(hashedPass);
    }
    else
    {
        room = createRoom(roomName, NULL);
    }

    if (g_context->roomCount < g_context->maxRooms)
    {
        g_context->rooms[g_context->roomCount++] = room;
        formatResponse(response, MSG_SIZE, "RESRoom '%s' Created\n", roomName);
    }
    else
    {
        destroyRoom(room);
        formatResponse(response, MSG_SIZE, "RESCannot Create Room: Server Full\n");
    }

    pthread_mutex_unlock(&g_context->mutex);
    sendResponse(client->socketFD, response);
}

static void cmdEnterRoom(Client* client, const char* buffer)
{
    char roomName[MAX_NAME_LEN];
    char response[MSG_SIZE];
    char message[MSG_SIZE];

    if (sscanf(buffer + 7, "%63s", roomName) != 1)
    {
        sendResponse(client->socketFD, "RESInvalid Room Name\n");
        return;
    }

    pthread_mutex_lock(&g_context->mutex);
    int roomIdx = findRoomIndex(g_context, roomName);

    if (roomIdx == -1)
    {
        formatResponse(response, MSG_SIZE, "RESRoom '%s' Does Not Exist\n", roomName);
        pthread_mutex_unlock(&g_context->mutex);
        sendResponse(client->socketFD, response);
        return;
    }

    Room* room = g_context->rooms[roomIdx];

    if (room->hasPassword)
    {
        sendResponse(client->socketFD, "PASPassword: ");
        pthread_mutex_unlock(&g_context->mutex);

        char inputPass[MAX_NAME_LEN];
        ssize_t passLen = recv(client->socketFD, inputPass, MAX_NAME_LEN - 1, 0);

        if (passLen <= 0)
            return;

        inputPass[passLen] = '\0';
        trimNewlines(inputPass);

        pthread_mutex_lock(&g_context->mutex);

        if (!verifyHashedPass(room->password, roomName, inputPass))
        {
            formatResponse(response, MSG_SIZE, "RESIncorrect Password\n");
            pthread_mutex_unlock(&g_context->mutex);
            sendResponse(client->socketFD, response);
            return;
        }
    }

    client->currentRoom = roomIdx;
    addMemberToRoom(room, client->socketFD);
    formatResponse(response, MSG_SIZE, "RESEntered Room '%s'\n", roomName);
    formatResponse(message, MSG_SIZE, "RES%s: Entered the Room\n", client->name);
    pthread_mutex_unlock(&g_context->mutex);
    sendResponse(client->socketFD, response);
    broadcastToRoom(g_context, client->currentRoom, client->socketFD, message);
}

static void cmdLeaveRoom(Client* client)
{
    if (client->currentRoom == -1)
    {
        sendResponse(client->socketFD, "RESNot in a Room\n");
        return;
    }

    char message[MSG_SIZE];
    formatResponse(message, MSG_SIZE, "RES%s : Left the Room\n", client->name);
    broadcastToRoom(g_context, client->currentRoom, client->socketFD, message);
    leaveCurrentRoom(client);
    sendResponse(client->socketFD, "RESLeft Room\n");
}

static void cmdSendMessage(Client* client, const char* buffer)
{
    if (client->currentRoom == -1)
    {
        sendResponse(client->socketFD, "RESNot in a Room. Use /enter <room>\n");
        return;
    }

    char message[MSG_SIZE];
    formatResponse(message, MSG_SIZE, "%s%s: %s", "MSG", client->name, buffer);
    broadcastToRoom(g_context, client->currentRoom, client->socketFD, message);
}

static void* handleClient(void* arg)
{
    Client* client = (Client*) arg;
    char buffer[MSG_SIZE];
    bool running = true;

    while (running)
    {
        ssize_t received = recv(client->socketFD, buffer, MSG_SIZE - 1, 0);

        if (received <= 0)
            break;

        buffer[received] = '\0';
        CommandType cmd = parseCommand(buffer);

        switch (cmd)
        {
        case CMD_HELP:
            cmdHelp(client);
            break;
        case CMD_NAME:
            cmdSetName(client, buffer);
            break;
        case CMD_CREATE:
            cmdCreateRoom(client, buffer);
            break;
        case CMD_ENTER:
            cmdEnterRoom(client, buffer);
            break;
        case CMD_LEAVE:
            cmdLeaveRoom(client);
            break;
        case CMD_EXIT:
            running = false;
            break;
        case CMD_MESSAGE:
            cmdSendMessage(client, buffer);
            break;
        case CMD_UNKNOWN:
            sendResponse(client->socketFD, "RESUnknown command. Type /help for Help\n");
            break;
        }
    }

    leaveCurrentRoom(client);
    removeClient(g_context, client->socketFD);
    close(client->socketFD);
    free(client->address);
    free(client);

    return NULL;
}

static void* cleanupThread(void* arg)
{
    while (true)
    {
        sleep(600);
        cleanupInactiveRooms(g_context);
    }
    return NULL;
}

int main(void)
{
    char* portEnv = getenv("PORT");
    int serverPort = portEnv ? atoi(portEnv) : PORT;

    int serverSocketFD = createTCPSocket();

    int opt = 1;
    if (setsockopt(serverSocketFD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
    }

    SocketAddress* address = createSocketAddress(LOCALHOST, serverPort, false);
    bindSocket(serverSocketFD, address);

    printf("Server starting on port %d...\n", serverPort);
    if (listen(serverSocketFD, BACKLOG) != 0)
    {
        print("Error while listening\n");
        exit(EXIT_FAILURE);
    }

    g_context = createServerContext(serverSocketFD, MAX_CLIENTS, MAX_ROOMS);

    pthread_t cleanupTid;
    pthread_create(&cleanupTid, NULL, cleanupThread, NULL);
    pthread_detach(cleanupTid);

    while (true)
    {
        Client* client = acceptClient(serverSocketFD);

        if (!client || !client->success)
        {
            if (client)
                free(client);
            continue;
        }

        if (!addClient(g_context, client))
        {
            sendResponse(client->socketFD, "Server is full\n");
            close(client->socketFD);
            free(client->address);
            free(client);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, handleClient, client) != 0)
        {
            removeClient(g_context, client->socketFD);
            close(client->socketFD);
            free(client->address);
            free(client);
        }
        else
        {
            pthread_detach(tid);
        }
    }

    shutdown(serverSocketFD, SHUT_RDWR);
    free(address);
    destroyServerContext(g_context);

    return 0;
}
