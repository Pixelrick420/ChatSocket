#include "../Utils/identity.h"
#include "../Utils/sha256.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#define LOCALHOST "0.0.0.0"
#define BACKLOG 10
#define MAX_CLIENTS 32
#define MAX_ROOMS 50

typedef struct {
  int socketFD;
  SSL *ssl;
} SslEntry;

static SslEntry g_sslMap[MAX_CLIENTS];
static int g_sslCount = 0;
static SSL_CTX *g_sslCtx = NULL;

static void sslMapAdd(int fd, SSL *ssl) {
  if (g_sslCount < MAX_CLIENTS) {
    g_sslMap[g_sslCount].socketFD = fd;
    g_sslMap[g_sslCount].ssl = ssl;
    g_sslCount++;
  }
}

static SSL *sslMapGet(int fd) {
  for (int i = 0; i < g_sslCount; i++)
    if (g_sslMap[i].socketFD == fd)
      return g_sslMap[i].ssl;
  return NULL;
}

static void sslMapRemove(int fd) {
  for (int i = 0; i < g_sslCount; i++) {
    if (g_sslMap[i].socketFD == fd) {
      tlsFree(g_sslMap[i].ssl);
      g_sslMap[i] = g_sslMap[--g_sslCount];
      return;
    }
  }
}

#define TOKEN_HEX_LEN 64

typedef struct {
  char token[TOKEN_HEX_LEN + 1];
  int socketFD;
} TokenEntry;

static TokenEntry g_tokenMap[MAX_CLIENTS];
static int g_tokenCount = 0;

static int tokenMapSet(const char *token, int newFD) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (strcmp(g_tokenMap[i].token, token) == 0) {
      return -1;
    }
  }
  if (g_tokenCount < MAX_CLIENTS) {
    snprintf(g_tokenMap[g_tokenCount].token,
             sizeof(g_tokenMap[g_tokenCount].token), "%s", token);
    g_tokenMap[g_tokenCount].socketFD = newFD;
    g_tokenCount++;
  }
  return 0;
}

static int tokenMapLookup(const char *token) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (strcmp(g_tokenMap[i].token, token) == 0)
      return g_tokenMap[i].socketFD;
  }
  return -1;
}

static void tokenMapRemoveByFD(int fd) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (g_tokenMap[i].socketFD == fd) {
      g_tokenMap[i] = g_tokenMap[--g_tokenCount];
      return;
    }
  }
}

static bool tokenMapLookupByFD(int fd, char out[TOKEN_HEX_LEN + 1]) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (g_tokenMap[i].socketFD == fd) {
      memcpy(out, g_tokenMap[i].token, TOKEN_HEX_LEN + 1);
      return true;
    }
  }
  return false;
}

static ServerContext *g_context = NULL;

static void sendResponse(int socketFD, const char *message) {
  pthread_mutex_lock(&g_context->mutex);
  SSL *ssl = sslMapGet(socketFD);
  pthread_mutex_unlock(&g_context->mutex);

  if (ssl)
    tlsSend(ssl, message, strlen(message));
}

static void tlsBroadcastToRoom(int roomIdx, int senderFD, const char *msg) {
  int fds[MAX_ROOM_MEMBERS];
  int count = 0;

  pthread_mutex_lock(&g_context->mutex);
  Room *room = g_context->rooms[roomIdx];
  updateRoomActivity(room);
  for (int i = 0; i < room->memberCount; i++)
    if (room->members[i] != senderFD)
      fds[count++] = room->members[i];
  pthread_mutex_unlock(&g_context->mutex);

  size_t msgLen = strlen(msg);
  for (int i = 0; i < count; i++) {
    pthread_mutex_lock(&g_context->mutex);
    SSL *ssl = sslMapGet(fds[i]);
    pthread_mutex_unlock(&g_context->mutex);

    if (ssl)
      tlsSend(ssl, msg, msgLen);
  }
}

static ssize_t recvClient(int socketFD, char *buf, size_t maxLen) {
  pthread_mutex_lock(&g_context->mutex);
  SSL *ssl = sslMapGet(socketFD);
  pthread_mutex_unlock(&g_context->mutex);

  if (ssl)
    return tlsRecv(ssl, buf, maxLen);
  return recv(socketFD, buf, maxLen - 1, 0);
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

typedef enum {
  CMD_MESSAGE,
  CMD_HELP,
  CMD_NAME,
  CMD_CREATE,
  CMD_ENTER,
  CMD_LEAVE,
  CMD_EXIT,
  CMD_AUTH,
  CMD_DM,
  CMD_DM_REQ,
  CMD_ROOMS,
  CMD_UNKNOWN
} CommandType;

static CommandType parseCommand(const char *buffer) {
  if (strncmp(buffer, "AUTH:", 5) == 0)
    return CMD_AUTH;
  if (strncmp(buffer, "DM:", 3) == 0)
    return CMD_DM;
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
  if (strncmp(buffer, "/rooms", 6) == 0)
    return CMD_ROOMS;
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
  sendResponse(
      client->socketFD,
      "RESAvailable Commands:\n"
      "  /help                              – Show this help\n"
      "  /token                             – Show your identity token\n"
      "  /name <name>                       – Set your display name\n"
      "  /rooms                             – List available rooms\n"
      "  /create <room>                     – Create a public room\n"
      "  /create <room> -p <password>       – Create a password-protected "
      "room\n"
      "  /enter <room>                      – Enter a room\n"
      "  /leave                             – Leave the current room\n"
      "  /list                              – List your DM conversations\n"
      "  /dm <token>                        – Start a private DM session\n"
      "  /exit                              – Disconnect\n");
}

static void cmdSetName(Client *client, const char *buffer) {
  char newName[MAX_NAME_LEN] = {0};
  char response[MSG_SIZE] = {0};

  if (sscanf(buffer + 6, "%63s", newName) != 1 || isBlankString(newName)) {
    sendResponse(client->socketFD, "RESName cannot be empty\n");
    return;
  }

  char oldName[MAX_NAME_LEN];
  snprintf(oldName, sizeof(oldName), "%s", client->name);

  snprintf(client->name, MAX_NAME_LEN, "%s", newName);

  snprintf(response, sizeof(response), "RESName set to: %s\n", client->name);
  sendResponse(client->socketFD, response);

  if (client->currentRoom != -1) {
    char announcement[MSG_SIZE];
    snprintf(announcement, sizeof(announcement), "RES%s is now known as %s\n",
             oldName, client->name);
    tlsBroadcastToRoom(client->currentRoom, client->socketFD, announcement);
  }
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

    char inputPass[MSG_SIZE];
    ssize_t passLen = recvClient(client->socketFD, inputPass, MSG_SIZE - 1);
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

    bool ok = verifyHashedPassPrehashed(g_context->rooms[roomIdx]->password,
                                        roomName, inputPass);
    if (!ok) {
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
  tlsBroadcastToRoom(roomIdx, client->socketFD, announcement);
}

static void cmdLeaveRoom(Client *client) {
  if (client->currentRoom == -1) {
    sendResponse(client->socketFD, "RESNot in a room\n");
    return;
  }

  char announcement[MSG_SIZE];
  snprintf(announcement, sizeof(announcement), "RES%s left the room\n",
           client->name);
  tlsBroadcastToRoom(client->currentRoom, client->socketFD, announcement);

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
  snprintf(text, sizeof(text), "%s", buffer);
  trimNewlines(text);

  char message[MSG_SIZE];
  snprintf(message, sizeof(message), "MSG%s: %s\n", client->name, text);
  tlsBroadcastToRoom(client->currentRoom, client->socketFD, message);
}

static bool cmdAuth(Client *client, const char *buffer,
                    const unsigned char nonce[CHALLENGE_BYTES]) {

  const char *p = buffer + 5;

  if (strlen(p) < (size_t)(TOKEN_HEX_LEN + 1 + SIG_HEX_LEN)) {
    sendResponse(client->socketFD, "ERRMalformed AUTH frame\n");
    return false;
  }

  char token[TOKEN_STR_SIZE];
  snprintf(token, sizeof(token), "%.*s", TOKEN_HEX_LEN, p);

  for (int i = 0; i < TOKEN_HEX_LEN; i++) {
    char c = token[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      sendResponse(client->socketFD, "ERRToken contains invalid characters\n");
      return false;
    }
  }

  if (p[TOKEN_HEX_LEN] != ':') {
    sendResponse(client->socketFD, "ERRMalformed AUTH frame\n");
    return false;
  }

  const char *sigHex = p + TOKEN_HEX_LEN + 1;
  unsigned char sig[SIG_BYTES];
  for (int i = 0; i < SIG_BYTES; i++) {
    int hi, lo;
    char hc = sigHex[i * 2], lc = sigHex[i * 2 + 1];
    if (hc >= '0' && hc <= '9')
      hi = hc - '0';
    else if (hc >= 'a' && hc <= 'f')
      hi = hc - 'a' + 10;
    else if (hc >= 'A' && hc <= 'F')
      hi = hc - 'A' + 10;
    else {
      sendResponse(client->socketFD, "ERRBad signature encoding\n");
      return false;
    }
    if (lc >= '0' && lc <= '9')
      lo = lc - '0';
    else if (lc >= 'a' && lc <= 'f')
      lo = lc - 'a' + 10;
    else if (lc >= 'A' && lc <= 'F')
      lo = lc - 'A' + 10;
    else {
      sendResponse(client->socketFD, "ERRBad signature encoding\n");
      return false;
    }
    sig[i] = (unsigned char)((hi << 4) | lo);
  }

  if (!identityVerify(token, nonce, CHALLENGE_BYTES, sig)) {
    sendResponse(client->socketFD,
                 "ERRAuthentication failed: invalid signature\n");
    return false;
  }

  pthread_mutex_lock(&g_context->mutex);
  int rc = tokenMapSet(token, client->socketFD);
  pthread_mutex_unlock(&g_context->mutex);

  if (rc != 0) {
    sendResponse(client->socketFD,
                 "ERRAlready connected: this identity has an active session\n");
    return false;
  }

  sendResponse(client->socketFD, "RESAuthenticated\n");
  return true;
}

static void cmdRouteDirectMessage(Client *client, const char *buffer) {

  const char *p = buffer + 3;
  if (strlen(p) < TOKEN_HEX_LEN + 1) {
    sendResponse(client->socketFD, "ERRMalformed DM command\n");
    return;
  }

  char targetToken[TOKEN_HEX_LEN + 1];
  memcpy(targetToken, p, TOKEN_HEX_LEN);
  targetToken[TOKEN_HEX_LEN] = '\0';

  char senderToken[TOKEN_HEX_LEN + 1] = {0};
  pthread_mutex_lock(&g_context->mutex);
  bool hasSenderToken = tokenMapLookupByFD(client->socketFD, senderToken);
  int targetFD = tokenMapLookup(targetToken);
  pthread_mutex_unlock(&g_context->mutex);

  if (!hasSenderToken) {
    sendResponse(client->socketFD,
                 "ERRMust register token before sending DMs\n");
    return;
  }

  if (strcmp(senderToken, targetToken) == 0) {
    sendResponse(client->socketFD, "RESCannot DM yourself\n");
    return;
  }

  if (targetFD < 0) {
    sendResponse(client->socketFD, "RESReceiver not connected\n");
    return;
  }

  const char *payload = p + TOKEN_HEX_LEN + 1;

  char forwarded[MSG_SIZE * 2];
  int fwdLen =
      snprintf(forwarded, sizeof(forwarded), "DM:%s:%s", senderToken, payload);

  if (fwdLen > 0 && forwarded[fwdLen - 1] != '\n') {
    if (fwdLen < (int)sizeof(forwarded) - 1) {
      forwarded[fwdLen++] = '\n';
      forwarded[fwdLen] = '\0';
    }
  }

  pthread_mutex_lock(&g_context->mutex);
  SSL *targetSsl = sslMapGet(targetFD);
  pthread_mutex_unlock(&g_context->mutex);

  if (targetSsl)
    tlsSend(targetSsl, forwarded, (size_t)fwdLen);
}

static void cmdListRooms(Client *client) {
  pthread_mutex_lock(&g_context->mutex);

  if (g_context->roomCount == 0) {
    pthread_mutex_unlock(&g_context->mutex);
    sendResponse(client->socketFD, "RESNo rooms available\n");
    return;
  }

  char response[MSG_SIZE];
  int offset = 0;
  offset += snprintf(response + offset, sizeof(response) - offset,
                     "RESAvailable rooms:\n");

  for (int i = 0;
       i < g_context->roomCount && offset < (int)sizeof(response) - 60; i++) {
    Room *r = g_context->rooms[i];
    offset +=
        snprintf(response + offset, sizeof(response) - offset, "  %-20s %s\n",
                 r->name, r->hasPassword ? "[password protected]" : "[open]");
  }

  pthread_mutex_unlock(&g_context->mutex);
  sendResponse(client->socketFD, response);
}

static void *handleClient(void *arg) {
  Client *client = (Client *)arg;
  char buffer[MSG_SIZE];

  unsigned char nonce[CHALLENGE_BYTES];
  if (RAND_bytes(nonce, CHALLENGE_BYTES) != 1) {
    sendResponse(client->socketFD,
                 "ERRServer error: could not generate nonce\n");
    goto disconnect;
  }

  {
    static const char hexChars[] = "0123456789abcdef";
    char challengeMsg[10 + CHALLENGE_HEX_LEN + 2];
    challengeMsg[0] = '\0';
    char *out = challengeMsg;
    out += snprintf(out, sizeof(challengeMsg), "CHALLENGE:");
    for (int i = 0; i < CHALLENGE_BYTES; i++) {
      *out++ = hexChars[nonce[i] >> 4];
      *out++ = hexChars[nonce[i] & 0x0f];
    }
    *out++ = '\n';
    *out = '\0';
    sendResponse(client->socketFD, challengeMsg);
  }

  {
    ssize_t received = recvClient(client->socketFD, buffer, MSG_SIZE - 1);
    if (received <= 0)
      goto disconnect;
    buffer[received] = '\0';

    if (parseCommand(buffer) != CMD_AUTH || !cmdAuth(client, buffer, nonce)) {
      goto disconnect;
    }
  }

  while (true) {
    ssize_t received = recvClient(client->socketFD, buffer, MSG_SIZE - 1);
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
    case CMD_AUTH:
      sendResponse(client->socketFD, "ERRAlready authenticated\n");
      break;
    case CMD_DM:
    case CMD_DM_REQ:
      cmdRouteDirectMessage(client, buffer);
      break;
    case CMD_ROOMS:
      cmdListRooms(client);
      break;
    case CMD_UNKNOWN:
      sendResponse(client->socketFD,
                   "RESUnknown command — type /help for help\n");
      break;
    }
  }

disconnect:
  leaveCurrentRoom(client);
  pthread_mutex_lock(&g_context->mutex);
  tokenMapRemoveByFD(client->socketFD);
  sslMapRemove(client->socketFD);
  pthread_mutex_unlock(&g_context->mutex);
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

  g_sslCtx = tlsServerCtxCreate();
  if (!g_sslCtx) {
    fprintf(stderr, "Failed to create TLS context\n");
    return 1;
  }

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

  printf("Server listening on port %d  (TLS, max %d clients, %d rooms)\n",
         serverPort, MAX_CLIENTS, MAX_ROOMS);

  g_context = createServerContext(serverSocketFD, MAX_CLIENTS, MAX_ROOMS);

  pthread_t cleanupTid;
  if (pthread_create(&cleanupTid, NULL, cleanupThread, NULL) != 0) {
    perror("pthread_create (cleanup thread)");
    return 1;
  }
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
      send(client->socketFD, "ERRServer is full\n", 18, 0);
      close(client->socketFD);
      free(client->address);
      free(client);
      continue;
    }

    SSL *ssl = tlsServerAccept(g_sslCtx, client->socketFD);
    if (!ssl) {
      removeClient(g_context, client->socketFD);
      close(client->socketFD);
      free(client->address);
      free(client);
      continue;
    }

    pthread_mutex_lock(&g_context->mutex);
    sslMapAdd(client->socketFD, ssl);
    pthread_mutex_unlock(&g_context->mutex);

    pthread_t tid;
    if (pthread_create(&tid, NULL, handleClient, client) != 0) {
      perror("pthread_create");
      pthread_mutex_lock(&g_context->mutex);
      sslMapRemove(client->socketFD);
      pthread_mutex_unlock(&g_context->mutex);
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
  SSL_CTX_free(g_sslCtx);
  return 0;
}
