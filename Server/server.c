#include "../Utils/aes.h"
#include "../Utils/identity.h"
#include "../Utils/protocol.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#define LOCALHOST "0.0.0.0"
#define BACKLOG 10
#define MAX_CLIENTS 32
#define MAX_ROOMS 50

typedef struct {
  SocketHandle socketFD;
  SSL *ssl;
} SslEntry;

typedef struct {
  char token[TOKEN_HEX_LEN + 1];
  SocketHandle socketFD;
} TokenEntry;

static SslEntry g_sslMap[MAX_CLIENTS];
static int g_sslCount = 0;
static SSL_CTX *g_sslCtx = NULL;

static TokenEntry g_tokenMap[MAX_CLIENTS];
static int g_tokenCount = 0;

static ServerContext *g_context = NULL;

static void sslMapAdd(SocketHandle fd, SSL *ssl) {
  if (g_sslCount < MAX_CLIENTS) {
    g_sslMap[g_sslCount].socketFD = fd;
    g_sslMap[g_sslCount].ssl = ssl;
    g_sslCount++;
  }
}

static SSL *sslMapGet(SocketHandle fd) {
  for (int i = 0; i < g_sslCount; i++) {
    if (g_sslMap[i].socketFD == fd)
      return g_sslMap[i].ssl;
  }
  return NULL;
}

static void sslMapRemove(SocketHandle fd) {
  for (int i = 0; i < g_sslCount; i++) {
    if (g_sslMap[i].socketFD == fd) {
      tlsFree(g_sslMap[i].ssl);
      g_sslMap[i] = g_sslMap[--g_sslCount];
      return;
    }
  }
}

static int tokenMapSet(const char *token, SocketHandle newFD) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (strcmp(g_tokenMap[i].token, token) == 0)
      return -1;
  }

  if (g_tokenCount < MAX_CLIENTS) {
    snprintf(g_tokenMap[g_tokenCount].token,
             sizeof(g_tokenMap[g_tokenCount].token), "%s", token);
    g_tokenMap[g_tokenCount].socketFD = newFD;
    g_tokenCount++;
  }

  return 0;
}

static SocketHandle tokenMapLookup(const char *token) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (strcmp(g_tokenMap[i].token, token) == 0)
      return g_tokenMap[i].socketFD;
  }
  return INVALID_SOCKET_HANDLE;
}

static void tokenMapRemoveByFD(SocketHandle fd) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (g_tokenMap[i].socketFD == fd) {
      g_tokenMap[i] = g_tokenMap[--g_tokenCount];
      return;
    }
  }
}

static bool tokenMapLookupByFD(SocketHandle fd, char out[TOKEN_HEX_LEN + 1]) {
  for (int i = 0; i < g_tokenCount; i++) {
    if (g_tokenMap[i].socketFD == fd) {
      memcpy(out, g_tokenMap[i].token, TOKEN_HEX_LEN + 1);
      return true;
    }
  }
  return false;
}

static bool sendFrame(SocketHandle socketFD, const char *message) {
  pthread_mutex_lock(&g_context->mutex);
  SSL *ssl = sslMapGet(socketFD);
  pthread_mutex_unlock(&g_context->mutex);

  if (ssl)
    return tlsSend(ssl, message, strlen(message));
  return send(socketFD, message, strlen(message), 0) >= 0;
}

static void sendError(SocketHandle socketFD, const char *message) {
  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "ERR|%s\n", message);
  sendFrame(socketFD, frame);
}

static void sendOk(SocketHandle socketFD, const char *message) {
  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "OK|%s\n", message);
  sendFrame(socketFD, frame);
}

static ssize_t recvClient(SocketHandle socketFD, char *buf, size_t maxLen) {
  pthread_mutex_lock(&g_context->mutex);
  SSL *ssl = sslMapGet(socketFD);
  pthread_mutex_unlock(&g_context->mutex);

  if (ssl)
    return tlsRecv(ssl, buf, maxLen);

  if (maxLen == 0)
    return -1;

  size_t offset = 0;
  while (offset < maxLen - 1) {
    char ch;
    ssize_t received = recv(socketFD, &ch, 1, 0);
    if (received <= 0)
      break;
    buf[offset++] = ch;
    if (ch == '\n')
      break;
  }
  buf[offset] = '\0';
  return offset == 0 ? 0 : (ssize_t)offset;
}

static void broadcastToRoomTls(int roomIdx, SocketHandle senderFD,
                               const char *msg) {
  SocketHandle fds[MAX_ROOM_MEMBERS];
  int count = 0;

  pthread_mutex_lock(&g_context->mutex);
  Room *room = g_context->rooms[roomIdx];
  updateRoomActivity(room);
  for (int i = 0; i < room->memberCount; i++) {
    if (room->members[i] != senderFD)
      fds[count++] = room->members[i];
  }
  pthread_mutex_unlock(&g_context->mutex);

  for (int i = 0; i < count; i++)
    sendFrame(fds[i], msg);
}

static void leaveCurrentRoom(Client *client) {
  if (client->currentRoom == -1)
    return;

  pthread_mutex_lock(&g_context->mutex);
  if (client->currentRoom >= 0 && client->currentRoom < g_context->roomCount)
    removeMemberFromRoom(g_context->rooms[client->currentRoom], client->socketFD);
  client->currentRoom = -1;
  client->waitingForRoomProof = false;
  client->pendingRoomName[0] = '\0';
  pthread_mutex_unlock(&g_context->mutex);
}

static bool parseRoomProtection(const char *stored, char saltHex[ROOM_SALT_HEX_SIZE],
                                char verifierHex[SHA256_HEX_SIZE]) {
  const char *sep = strchr(stored, ':');
  if (!sep)
    return false;

  size_t saltLen = (size_t)(sep - stored);
  if (saltLen != ROOM_SALT_HEX_SIZE - 1)
    return false;

  memcpy(saltHex, stored, saltLen);
  saltHex[saltLen] = '\0';
  snprintf(verifierHex, SHA256_HEX_SIZE, "%s", sep + 1);
  return strlen(verifierHex) == SHA256_HEX_SIZE - 1;
}

static bool joinRoom(Client *client, int roomIdx) {
  if (roomIdx < 0 || roomIdx >= g_context->roomCount)
    return false;

  if (client->currentRoom != -1)
    removeMemberFromRoom(g_context->rooms[client->currentRoom], client->socketFD);

  client->currentRoom = roomIdx;
  client->waitingForRoomProof = false;
  client->pendingRoomName[0] = '\0';
  return addMemberToRoom(g_context->rooms[roomIdx], client->socketFD);
}

static void handleSetName(Client *client, const char *name) {
  if (!protocolIsSafeIdentifier(name)) {
    sendError(client->socketFD, "Invalid name");
    return;
  }

  char oldName[MAX_NAME_LEN];
  snprintf(oldName, sizeof(oldName), "%s", client->name);
  snprintf(client->name, sizeof(client->name), "%s", name);
  sendOk(client->socketFD, "NAME_SET");

  if (client->currentRoom != -1) {
    char notice[MSG_SIZE];
    snprintf(notice, sizeof(notice), "INFO|NAME_CHANGED|%s|%s\n", oldName,
             client->name);
    broadcastToRoomTls(client->currentRoom, client->socketFD, notice);
  }
}

static void handleRoomCreate(Client *client, char **parts, size_t partCount) {
  if (partCount < 3 || !protocolIsSafeIdentifier(parts[1])) {
    sendError(client->socketFD, "Invalid room name");
    return;
  }

  Room *room = NULL;
  char protection[MAX_PASSWORD_LEN] = {0};

  if (strcmp(parts[2], "OPEN") == 0) {
    room = createRoom(parts[1], NULL);
  } else if (strcmp(parts[2], "PROTECTED") == 0 && partCount >= 5 &&
             strlen(parts[3]) == ROOM_SALT_HEX_SIZE - 1 &&
             strlen(parts[4]) == SHA256_HEX_SIZE - 1) {
    snprintf(protection, sizeof(protection), "%s:%s", parts[3], parts[4]);
    room = createRoom(parts[1], protection);
  } else {
    sendError(client->socketFD, "Malformed ROOM_CREATE");
    return;
  }

  if (!room) {
    sendError(client->socketFD, "Failed to create room");
    return;
  }

  pthread_mutex_lock(&g_context->mutex);
  if (findRoomIndex(g_context, parts[1]) != -1) {
    pthread_mutex_unlock(&g_context->mutex);
    destroyRoom(room);
    sendError(client->socketFD, "Room already exists");
    return;
  }

  if (g_context->roomCount >= g_context->maxRooms) {
    pthread_mutex_unlock(&g_context->mutex);
    destroyRoom(room);
    sendError(client->socketFD, "Server room limit reached");
    return;
  }

  g_context->rooms[g_context->roomCount++] = room;
  pthread_mutex_unlock(&g_context->mutex);

  sendOk(client->socketFD, "ROOM_CREATED");
}

static void handleRoomList(Client *client) {
  pthread_mutex_lock(&g_context->mutex);
  sendFrame(client->socketFD, "INFO|ROOMS_BEGIN\n");
  for (int i = 0; i < g_context->roomCount; i++) {
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "INFO|ROOM|%s|%s\n", g_context->rooms[i]->name,
             g_context->rooms[i]->hasPassword ? "PROTECTED" : "OPEN");
    sendFrame(client->socketFD, frame);
  }
  pthread_mutex_unlock(&g_context->mutex);
  sendFrame(client->socketFD, "INFO|ROOMS_END\n");
}

static void handleRoomEnter(Client *client, const char *roomName) {
  if (!protocolIsSafeIdentifier(roomName)) {
    sendError(client->socketFD, "Invalid room name");
    return;
  }

  pthread_mutex_lock(&g_context->mutex);
  int roomIdx = findRoomIndex(g_context, roomName);
  if (roomIdx == -1) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room does not exist");
    return;
  }

  Room *room = g_context->rooms[roomIdx];
  if (!room->hasPassword) {
    if (!joinRoom(client, roomIdx)) {
      pthread_mutex_unlock(&g_context->mutex);
      sendError(client->socketFD, "Room is full");
      return;
    }
    pthread_mutex_unlock(&g_context->mutex);

    sendFrame(client->socketFD, "OK|ROOM_ENTERED|OPEN\n");
    char joined[MSG_SIZE];
    snprintf(joined, sizeof(joined), "INFO|ROOM_JOINED|%s\n", client->name);
    broadcastToRoomTls(roomIdx, client->socketFD, joined);
    return;
  }

  char saltHex[ROOM_SALT_HEX_SIZE];
  char verifierHex[SHA256_HEX_SIZE];
  if (!parseRoomProtection(room->password, saltHex, verifierHex)) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room protection data is corrupt");
    return;
  }

  client->waitingForRoomProof = true;
  snprintf(client->pendingRoomName, sizeof(client->pendingRoomName), "%s",
           roomName);
  pthread_mutex_unlock(&g_context->mutex);

  char challenge[MSG_SIZE];
  snprintf(challenge, sizeof(challenge), "ROOM_CHALLENGE|%s|%s\n", roomName,
           saltHex);
  sendFrame(client->socketFD, challenge);
}

static void handleRoomProof(Client *client, const char *roomName,
                            const char *verifierHex) {
  if (!client->waitingForRoomProof ||
      strcmp(client->pendingRoomName, roomName) != 0) {
    sendError(client->socketFD, "Unexpected ROOM_PROOF");
    return;
  }

  pthread_mutex_lock(&g_context->mutex);
  int roomIdx = findRoomIndex(g_context, roomName);
  if (roomIdx == -1) {
    client->waitingForRoomProof = false;
    client->pendingRoomName[0] = '\0';
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room no longer exists");
    return;
  }

  char saltHex[ROOM_SALT_HEX_SIZE];
  char expectedVerifier[SHA256_HEX_SIZE];
  if (!parseRoomProtection(g_context->rooms[roomIdx]->password, saltHex,
                           expectedVerifier)) {
    client->waitingForRoomProof = false;
    client->pendingRoomName[0] = '\0';
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room protection data is corrupt");
    return;
  }

  if (strcmp(expectedVerifier, verifierHex) != 0) {
    client->waitingForRoomProof = false;
    client->pendingRoomName[0] = '\0';
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Incorrect room secret");
    return;
  }

  if (!joinRoom(client, roomIdx)) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room is full");
    return;
  }
  pthread_mutex_unlock(&g_context->mutex);

  sendFrame(client->socketFD, "OK|ROOM_ENTERED|PROTECTED\n");
  char joined[MSG_SIZE];
  snprintf(joined, sizeof(joined), "INFO|ROOM_JOINED|%s\n", client->name);
  broadcastToRoomTls(roomIdx, client->socketFD, joined);
}

static void handleRoomLeave(Client *client) {
  if (client->currentRoom == -1) {
    sendError(client->socketFD, "Not in a room");
    return;
  }

  int oldRoom = client->currentRoom;
  char left[MSG_SIZE];
  snprintf(left, sizeof(left), "INFO|ROOM_LEFT|%s\n", client->name);
  broadcastToRoomTls(oldRoom, client->socketFD, left);

  leaveCurrentRoom(client);
  sendOk(client->socketFD, "ROOM_LEFT");
}

static void handleRoomSend(Client *client, const char *payload) {
  if (client->currentRoom == -1) {
    sendError(client->socketFD, "Not in a room");
    return;
  }

  if (!payload || !payload[0]) {
    sendError(client->socketFD, "Empty room message");
    return;
  }

  char frame[MSG_SIZE * 2];
  snprintf(frame, sizeof(frame), "ROOM_MSG|%s|%s\n", client->name, payload);
  broadcastToRoomTls(client->currentRoom, client->socketFD, frame);
}

static void forwardDmFrame(Client *client, const char *targetToken,
                           const char *frameType, const char *fieldA,
                           const char *fieldB) {
  char senderToken[TOKEN_HEX_LEN + 1] = {0};

  pthread_mutex_lock(&g_context->mutex);
  bool hasSenderToken = tokenMapLookupByFD(client->socketFD, senderToken);
  SocketHandle targetFD = tokenMapLookup(targetToken);
  pthread_mutex_unlock(&g_context->mutex);

  if (!hasSenderToken) {
    sendError(client->socketFD, "Authentication missing");
    return;
  }

  if (targetFD == INVALID_SOCKET_HANDLE) {
    sendError(client->socketFD, "Peer is not connected");
    return;
  }

  if (strcmp(senderToken, targetToken) == 0) {
    sendError(client->socketFD, "Cannot DM yourself");
    return;
  }

  char frame[MSG_SIZE * 2];
  snprintf(frame, sizeof(frame), "%s|%s|%s|%s\n", frameType, senderToken,
           fieldA ? fieldA : "", fieldB ? fieldB : "");
  sendFrame(targetFD, frame);
}

static bool handleAuth(Client *client, char **parts, size_t partCount,
                       const unsigned char nonce[CHALLENGE_BYTES]) {
  if (partCount != 3 || strlen(parts[1]) != TOKEN_HEX_LEN ||
      strlen(parts[2]) != SIG_HEX_LEN) {
    sendError(client->socketFD, "Malformed AUTH");
    return false;
  }

  unsigned char sig[SIG_BYTES];
  if (!hexToBytes(parts[2], sig, sizeof(sig))) {
    sendError(client->socketFD, "Invalid signature encoding");
    return false;
  }

  if (!identityVerify(parts[1], nonce, CHALLENGE_BYTES, sig)) {
    sendError(client->socketFD, "Authentication failed");
    return false;
  }

  pthread_mutex_lock(&g_context->mutex);
  int rc = tokenMapSet(parts[1], client->socketFD);
  pthread_mutex_unlock(&g_context->mutex);
  if (rc != 0) {
    sendError(client->socketFD, "Identity already connected");
    return false;
  }

  sendOk(client->socketFD, "AUTH");
  return true;
}

static bool handleFrame(Client *client, char *buffer) {
  char *parts[PROTOCOL_MAX_PARTS] = {0};
  size_t partCount = protocolSplitFields(buffer, parts, PROTOCOL_MAX_PARTS);
  if (partCount == 0)
    return true;

  if (strcmp(parts[0], "SET_NAME") == 0 && partCount >= 2) {
    handleSetName(client, parts[1]);
    return true;
  }
  if (strcmp(parts[0], "ROOM_CREATE") == 0) {
    handleRoomCreate(client, parts, partCount);
    return true;
  }
  if (strcmp(parts[0], "ROOM_LIST") == 0) {
    handleRoomList(client);
    return true;
  }
  if (strcmp(parts[0], "ROOM_ENTER") == 0 && partCount >= 2) {
    handleRoomEnter(client, parts[1]);
    return true;
  }
  if (strcmp(parts[0], "ROOM_PROOF") == 0 && partCount >= 3) {
    handleRoomProof(client, parts[1], parts[2]);
    return true;
  }
  if (strcmp(parts[0], "ROOM_LEAVE") == 0) {
    handleRoomLeave(client);
    return true;
  }
  if (strcmp(parts[0], "ROOM_SEND") == 0 && partCount >= 2) {
    handleRoomSend(client, parts[1]);
    return true;
  }
  if (strcmp(parts[0], "DM_INIT") == 0 && partCount >= 4) {
    forwardDmFrame(client, parts[1], "DM_INIT", parts[2], parts[3]);
    return true;
  }
  if (strcmp(parts[0], "DM_ACK") == 0 && partCount >= 4) {
    forwardDmFrame(client, parts[1], "DM_ACK", parts[2], parts[3]);
    return true;
  }
  if (strcmp(parts[0], "DM_SEND") == 0 && partCount >= 3) {
    forwardDmFrame(client, parts[1], "DM_MSG", parts[2], NULL);
    return true;
  }
  if (strcmp(parts[0], "QUIT") == 0) {
    sendOk(client->socketFD, "BYE");
    return false;
  }

  sendError(client->socketFD, "Unknown frame");
  return true;
}

static void *handleClient(void *arg) {
  Client *client = (Client *)arg;
  char buffer[MSG_SIZE];

  unsigned char nonce[CHALLENGE_BYTES];
  if (RAND_bytes(nonce, CHALLENGE_BYTES) != 1) {
    sendError(client->socketFD, "Server could not generate challenge");
    goto disconnect;
  }

  char nonceHex[CHALLENGE_HEX_SIZE];
  bytesToHex(nonce, sizeof(nonce), nonceHex);
  char challenge[MSG_SIZE];
  snprintf(challenge, sizeof(challenge), "CHALLENGE|%s\n", nonceHex);
  sendFrame(client->socketFD, challenge);

  {
    ssize_t received = recvClient(client->socketFD, buffer, sizeof(buffer));
    if (received <= 0)
      goto disconnect;

    char *parts[PROTOCOL_MAX_PARTS] = {0};
    size_t partCount = protocolSplitFields(buffer, parts, PROTOCOL_MAX_PARTS);
    if (partCount == 0 || strcmp(parts[0], "AUTH") != 0 ||
        !handleAuth(client, parts, partCount, nonce)) {
      goto disconnect;
    }
  }

  while (true) {
    ssize_t received = recvClient(client->socketFD, buffer, sizeof(buffer));
    if (received <= 0)
      break;

    if (strcmp(buffer, "QUIT\n") == 0 || strcmp(buffer, "QUIT") == 0)
      break;

    if (!handleFrame(client, buffer))
      break;
  }

disconnect:
  if (client->currentRoom != -1) {
    char left[MSG_SIZE];
    snprintf(left, sizeof(left), "INFO|ROOM_LEFT|%s\n", client->name);
    broadcastToRoomTls(client->currentRoom, client->socketFD, left);
  }
  leaveCurrentRoom(client);
  pthread_mutex_lock(&g_context->mutex);
  tokenMapRemoveByFD(client->socketFD);
  sslMapRemove(client->socketFD);
  pthread_mutex_unlock(&g_context->mutex);
  removeClient(g_context, client->socketFD);
  platformCloseSocket(client->socketFD);
  free(client->address);
  free(client);
  return NULL;
}

static void *cleanupThread(void *arg) {
  (void)arg;
  while (true) {
    platformSleepMs(600000);
    cleanupInactiveRooms(g_context);
  }
  return NULL;
}

int main(void) {
  if (!platformInit()) {
    fprintf(stderr, "Failed to initialize platform networking\n");
    return 1;
  }

  const char *portEnv = getenv("PORT");
  int serverPort = portEnv ? atoi(portEnv) : PORT;

  g_sslCtx = tlsServerCtxCreate();
  if (!g_sslCtx) {
    fprintf(stderr, "Failed to create TLS context\n");
    return 1;
  }

  SocketHandle serverSocketFD = createTCPSocket();
  if (serverSocketFD == INVALID_SOCKET_HANDLE) {
    fprintf(stderr, "Failed to create server socket\n");
    return 1;
  }

  int opt = 1;
  setsockopt(serverSocketFD, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
             sizeof(opt));

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

  printf("Server listening on port %d (TLS, protocol v2)\n", serverPort);

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
      send(client->socketFD, "ERR|Server is full\n", 19, 0);
      platformCloseSocket(client->socketFD);
      free(client->address);
      free(client);
      continue;
    }

    SSL *ssl = tlsServerAccept(g_sslCtx, client->socketFD);
    if (!ssl) {
      removeClient(g_context, client->socketFD);
      platformCloseSocket(client->socketFD);
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
      platformCloseSocket(client->socketFD);
      free(client->address);
      free(client);
    } else {
      pthread_detach(tid);
    }
  }

  destroyServerContext(g_context);
  SSL_CTX_free(g_sslCtx);
  platformCloseSocket(serverSocketFD);
  platformCleanup();
  return 0;
}
