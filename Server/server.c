#include "../Utils/sha256.h"
#include "../Utils/socketUtil.h"

#define LOCALHOST "0.0.0.0"
#define BACKLOG 10
#define MAX_CLIENTS 32
#define MAX_ROOMS 50

static ServerContext *g_context = NULL;

static void sendResponse(int socketFD, const char *message) {
  send(socketFD, message, strlen(message), 0);
}

static void trimNewlines(char *str) {
  size_t len = strlen(str);
  while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r'))
    str[--len] = '\0';
}

static bool isBlankString(const char *str) {
  for (size_t i = 0; str[i] != '\0'; i++)
    if (!isspace((unsigned char)str[i]))
      return false;
  return true;
}

static CommandType parseCommand(const char *buffer) {
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

static void leaveCurrentRoom(Client *client) {
  if (client->currentRoom == -1)
    return;

  pthread_mutex_lock(&g_context->mutex);
  removeMemberFromRoom(g_context->rooms[client->currentRoom], client->socketFD);
  client->currentRoom = -1;
  pthread_mutex_unlock(&g_context->mutex);
}

static void cmdHelp(Client *client) {
  sendResponse(client->socketFD,
               "RESAvailable Commands:\n"
               "  /help                              – Show this help\n"
               "  /name <name>                       – Set your display name\n"
               "  /create <room>                     – Create a public room\n"
               "  /create <room> -p <password>       – Create a "
               "password-protected room\n"
               "  /enter <room>                      – Enter a room\n"
               "  /leave                             – Leave the current room\n"
               "  /exit                              – Disconnect\n");
}

static void cmdSetName(Client *client, const char *buffer) {
  char newName[MAX_NAME_LEN] = {0};
  char response[MSG_SIZE] = {0};

  if (sscanf(buffer + 6, "%63s", newName) != 1 || isBlankString(newName)) {
    sendResponse(client->socketFD, "RESName cannot be empty\n");
    return;
  }

  strncpy(client->name, newName, MAX_NAME_LEN - 1);
  client->name[MAX_NAME_LEN - 1] = '\0';
  snprintf(response, sizeof(response), "RESName set to: %s\n", client->name);
  sendResponse(client->socketFD, response);
}

static void cmdCreateRoom(Client *client, char *buffer) {
  char roomName[MAX_NAME_LEN] = {0};
  char password[MAX_NAME_LEN] = {0};
  char response[MSG_SIZE];

  trimNewlines(buffer);

  if (sscanf(buffer + 8, "%63s", roomName) != 1 || isBlankString(roomName)) {
    sendResponse(client->socketFD, "RESRoom name cannot be empty\n");
    return;
  }

  char *passwordFlag = strstr(buffer + 8, " -p ");
  if (passwordFlag)
    sscanf(passwordFlag + 4, "%63s", password);

  pthread_mutex_lock(&g_context->mutex);

  if (findRoomIndex(g_context, roomName) != -1) {
    pthread_mutex_unlock(&g_context->mutex);
    snprintf(response, sizeof(response), "RESRoom '%s' already exists\n",
             roomName);
    sendResponse(client->socketFD, response);
    return;
  }

  Room *room;
  if (!isBlankString(password) && strlen(password) > 0) {

    char *hashedPass = createHashedPass(roomName, password);
    if (!hashedPass) {
      pthread_mutex_unlock(&g_context->mutex);
      sendResponse(client->socketFD, "ERRFailed to create room (hash error)\n");
      return;
    }
    room = createRoom(roomName, hashedPass);
    free(hashedPass);
  } else {
    room = createRoom(roomName, NULL);
  }

  if (!room) {
    pthread_mutex_unlock(&g_context->mutex);
    sendResponse(client->socketFD, "ERRFailed to create room (memory error)\n");
    return;
  }

  if (g_context->roomCount < g_context->maxRooms) {
    g_context->rooms[g_context->roomCount++] = room;
    snprintf(response, sizeof(response), "RESRoom '%s' created\n", roomName);
  } else {
    destroyRoom(room);
    snprintf(response, sizeof(response),
             "RESCannot create room: server full\n");
  }

  pthread_mutex_unlock(&g_context->mutex);
  sendResponse(client->socketFD, response);
}

static void cmdEnterRoom(Client *client, const char *buffer) {
  char roomName[MAX_NAME_LEN];
  char response[MSG_SIZE];

  if (sscanf(buffer + 7, "%63s", roomName) != 1) {
    sendResponse(client->socketFD, "RESInvalid room name\n");
    return;
  }

  pthread_mutex_lock(&g_context->mutex);
  int roomIdx = findRoomIndex(g_context, roomName);

  if (roomIdx == -1) {
    pthread_mutex_unlock(&g_context->mutex);
    snprintf(response, sizeof(response), "RESRoom '%s' does not exist\n",
             roomName);
    sendResponse(client->socketFD, response);
    return;
  }

  bool needsPassword = g_context->rooms[roomIdx]->hasPassword;
  pthread_mutex_unlock(&g_context->mutex);

  if (needsPassword) {
    sendResponse(client->socketFD, "PASPassword: ");

    char inputPass[MAX_NAME_LEN];
    ssize_t passLen = recv(client->socketFD, inputPass, MAX_NAME_LEN - 1, 0);
    if (passLen <= 0)
      return;

    inputPass[passLen] = '\0';
    trimNewlines(inputPass);
    pthread_mutex_lock(&g_context->mutex);
    roomIdx = findRoomIndex(g_context, roomName);
    if (roomIdx == -1) {
      pthread_mutex_unlock(&g_context->mutex);
      snprintf(response, sizeof(response), "RESRoom '%s' no longer exists\n",
               roomName);
      sendResponse(client->socketFD, response);
      return;
    }

    if (!verifyHashedPass(g_context->rooms[roomIdx]->password, roomName,
                          inputPass)) {
      pthread_mutex_unlock(&g_context->mutex);
      sendResponse(client->socketFD, "RESIncorrect password\n");
      return;
    }
    pthread_mutex_unlock(&g_context->mutex);
  }

  pthread_mutex_lock(&g_context->mutex);

  roomIdx = findRoomIndex(g_context, roomName);
  if (roomIdx == -1) {
    pthread_mutex_unlock(&g_context->mutex);
    snprintf(response, sizeof(response), "RESRoom '%s' no longer exists\n",
             roomName);
    sendResponse(client->socketFD, response);
    return;
  }

  if (client->currentRoom != -1)
    removeMemberFromRoom(g_context->rooms[client->currentRoom],
                         client->socketFD);

  client->currentRoom = roomIdx;
  addMemberToRoom(g_context->rooms[roomIdx], client->socketFD);
  pthread_mutex_unlock(&g_context->mutex);

  snprintf(response, sizeof(response), "RESEntered room '%s'\n", roomName);
  sendResponse(client->socketFD, response);

  char announcement[MSG_SIZE];
  snprintf(announcement, sizeof(announcement), "RES%s joined the room\n",
           client->name);
  broadcastToRoom(g_context, roomIdx, client->socketFD, announcement);
}

static void cmdLeaveRoom(Client *client) {
  if (client->currentRoom == -1) {
    sendResponse(client->socketFD, "RESNot in a room\n");
    return;
  }

  char announcement[MSG_SIZE];
  snprintf(announcement, sizeof(announcement), "RES%s left the room\n",
           client->name);
  broadcastToRoom(g_context, client->currentRoom, client->socketFD,
                  announcement);

  leaveCurrentRoom(client);
  sendResponse(client->socketFD, "RESLeft room\n");
}

static void cmdSendMessage(Client *client, const char *buffer) {
  if (client->currentRoom == -1) {
    sendResponse(client->socketFD,
                 "RESNot in a room — use /enter <room> first\n");
    return;
  }

  char text[MSG_SIZE];
  strncpy(text, buffer, MSG_SIZE - 1);
  text[MSG_SIZE - 1] = '\0';
  trimNewlines(text);

  char message[MSG_SIZE];
  snprintf(message, sizeof(message), "MSG%s: %s\n", client->name, text);
  broadcastToRoom(g_context, client->currentRoom, client->socketFD, message);
}

static void *handleClient(void *arg) {
  Client *client = (Client *)arg;
  char buffer[MSG_SIZE];

  while (true) {
    ssize_t received = recv(client->socketFD, buffer, MSG_SIZE - 1, 0);
    if (received <= 0)
      break;

    buffer[received] = '\0';

    switch (parseCommand(buffer)) {
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
      goto disconnect;
    case CMD_MESSAGE:
      cmdSendMessage(client, buffer);
      break;
    case CMD_UNKNOWN:
      sendResponse(client->socketFD,
                   "RESUnknown command — type /help for help\n");
      break;
    }
  }

disconnect:
  leaveCurrentRoom(client);
  removeClient(g_context, client->socketFD);
  close(client->socketFD);
  free(client->address);
  free(client);
  return NULL;
}

static void *cleanupThread(void *arg) {
  (void)arg;
  while (true) {
    sleep(600);
    cleanupInactiveRooms(g_context);
  }
  return NULL;
}

int main(void) {

  const char *portEnv = getenv("PORT");
  int serverPort = portEnv ? atoi(portEnv) : PORT;

  int serverSocketFD = createTCPSocket();
  if (serverSocketFD < 0) {
    fprintf(stderr, "Failed to create server socket\n");
    return 1;
  }

  int opt = 1;
  setsockopt(serverSocketFD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  SocketAddress *address = createSocketAddress(LOCALHOST, serverPort, false);
  if (!address) {
    fprintf(stderr, "Failed to create socket address\n");
    return 1;
  }

  bindSocket(serverSocketFD, address);
  free(address);

  if (listen(serverSocketFD, BACKLOG) != 0) {
    perror("listen");
    return 1;
  }

  printf("Server listening on port %d  (max %d clients, %d rooms)\n",
         serverPort, MAX_CLIENTS, MAX_ROOMS);

  g_context = createServerContext(serverSocketFD, MAX_CLIENTS, MAX_ROOMS);

  pthread_t cleanupTid;
  pthread_create(&cleanupTid, NULL, cleanupThread, NULL);
  pthread_detach(cleanupTid);

  while (true) {
    Client *client = acceptClient(serverSocketFD);
    if (!client || !client->success) {
      if (client) {
        free(client->address);
        free(client);
      }
      continue;
    }

    if (!addClient(g_context, client)) {
      sendResponse(client->socketFD, "ERRServer is full\n");
      close(client->socketFD);
      free(client->address);
      free(client);
      continue;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, handleClient, client) != 0) {
      perror("pthread_create");
      removeClient(g_context, client->socketFD);
      close(client->socketFD);
      free(client->address);
      free(client);
    } else {
      pthread_detach(tid);
    }
  }

  shutdown(serverSocketFD, SHUT_RDWR);
  destroyServerContext(g_context);
  return 0;
}
