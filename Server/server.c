#include "../Utils/aes.h"
#include "../Utils/identity.h"
#include "../Utils/protocol.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#include <openssl/crypto.h>
#include <strings.h>

#define LOCALHOST "0.0.0.0"
#define BACKLOG 10
#define MAX_CLIENTS 32
#define MAX_ROOMS 50
#define DM_SESSION_ID_HEX_LEN 32

typedef struct {
  SocketHandle socketFD;
  SSL *ssl;
  pthread_mutex_t sendMutex;
  pthread_cond_t idle;
  size_t refs;
  bool closing;
} SslEntry;

typedef struct {
  char token[TOKEN_HEX_LEN + 1];
  SocketHandle socketFD;
} TokenEntry;

static SslEntry *g_sslMap[MAX_CLIENTS];
static int g_sslCount = 0;
static SSL_CTX *g_sslCtx = NULL;
static pthread_mutex_t g_sslMutex = PTHREAD_MUTEX_INITIALIZER;

static TokenEntry g_tokenMap[MAX_CLIENTS];
static int g_tokenCount = 0;

static ServerContext *g_context = NULL;

static bool sslMapAdd(SocketHandle fd, SSL *ssl) {
  SslEntry *entry = calloc(1, sizeof(*entry));
  if (!entry)
    return false;

  entry->socketFD = fd;
  entry->ssl = ssl;
  pthread_mutex_init(&entry->sendMutex, NULL);
  pthread_cond_init(&entry->idle, NULL);

  pthread_mutex_lock(&g_sslMutex);
  if (g_sslCount >= MAX_CLIENTS) {
    pthread_mutex_unlock(&g_sslMutex);
    pthread_cond_destroy(&entry->idle);
    pthread_mutex_destroy(&entry->sendMutex);
    free(entry);
    return false;
  }
  g_sslMap[g_sslCount++] = entry;
  pthread_mutex_unlock(&g_sslMutex);
  return true;
}

static SslEntry *sslMapAcquire(SocketHandle fd) {
  SslEntry *result = NULL;
  pthread_mutex_lock(&g_sslMutex);
  for (int i = 0; i < g_sslCount; i++) {
    if (g_sslMap[i]->socketFD == fd && !g_sslMap[i]->closing) {
      result = g_sslMap[i];
      result->refs++;
      break;
    }
  }
  pthread_mutex_unlock(&g_sslMutex);
  return result;
}

static void sslMapRelease(SslEntry *entry) {
  if (!entry)
    return;

  pthread_mutex_lock(&g_sslMutex);
  if (entry->refs > 0)
    entry->refs--;
  if (entry->closing && entry->refs == 0)
    pthread_cond_signal(&entry->idle);
  pthread_mutex_unlock(&g_sslMutex);
}

static void sslMapRemove(SocketHandle fd) {
  SslEntry *entry = NULL;

  pthread_mutex_lock(&g_sslMutex);
  for (int i = 0; i < g_sslCount; i++) {
    if (g_sslMap[i]->socketFD == fd) {
      entry = g_sslMap[i];
      entry->closing = true;
      while (entry->refs > 0)
        pthread_cond_wait(&entry->idle, &g_sslMutex);
      g_sslMap[i] = g_sslMap[--g_sslCount];
      g_sslMap[g_sslCount] = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&g_sslMutex);

  if (!entry)
    return;
  tlsFree(entry->ssl);
  pthread_cond_destroy(&entry->idle);
  pthread_mutex_destroy(&entry->sendMutex);
  free(entry);
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

static void setSocketTimeoutsMs(SocketHandle socketFD, int receiveTimeoutMs,
                                int sendTimeoutMs) {
#ifdef _WIN32
  DWORD receiveTimeout =
      receiveTimeoutMs > 0 ? (DWORD)receiveTimeoutMs : 0;
  DWORD sendTimeout = sendTimeoutMs > 0 ? (DWORD)sendTimeoutMs : 0;
  setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, (const char *)&receiveTimeout,
             sizeof(receiveTimeout));
  setsockopt(socketFD, SOL_SOCKET, SO_SNDTIMEO, (const char *)&sendTimeout,
             sizeof(sendTimeout));
#else
  struct timeval receiveTimeout = {
      .tv_sec = receiveTimeoutMs > 0 ? receiveTimeoutMs / 1000 : 0,
      .tv_usec = receiveTimeoutMs > 0 ? (receiveTimeoutMs % 1000) * 1000 : 0,
  };
  struct timeval sendTimeout = {
      .tv_sec = sendTimeoutMs > 0 ? sendTimeoutMs / 1000 : 0,
      .tv_usec = sendTimeoutMs > 0 ? (sendTimeoutMs % 1000) * 1000 : 0,
  };
  setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &receiveTimeout,
             sizeof(receiveTimeout));
  setsockopt(socketFD, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout,
             sizeof(sendTimeout));
#endif
}

static bool sendFrame(SocketHandle socketFD, const char *message) {
  SslEntry *entry = sslMapAcquire(socketFD);
  if (!entry)
    return false;

  pthread_mutex_lock(&entry->sendMutex);
  bool ok = tlsSend(entry->ssl, message, strlen(message));
  pthread_mutex_unlock(&entry->sendMutex);
  sslMapRelease(entry);
  return ok;
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

static bool validEncryptedPayload(const char *payload) {
  if (!payload || !payload[0] || strlen(payload) > PROTOCOL_MAX_PAYLOAD)
    return false;

  unsigned char decoded[MAX_MESSAGE_TEXT + AES_GCM_OVERHEAD];
  int decodedLen = decodeBase64(payload, decoded, sizeof(decoded));
  return decodedLen >= AES_GCM_OVERHEAD &&
         decodedLen <= MAX_MESSAGE_TEXT + AES_GCM_OVERHEAD;
}

static ssize_t recvClient(SocketHandle socketFD, char *buf, size_t maxLen) {
  SslEntry *entry = sslMapAcquire(socketFD);
  if (!entry)
    return -1;
  ssize_t result = tlsRecv(entry->ssl, buf, maxLen);
  sslMapRelease(entry);
  return result;
}

static void broadcastToRoomTls(Room *room, SocketHandle senderFD,
                               const char *msg) {
  SocketHandle fds[MAX_ROOM_MEMBERS];
  int count = 0;

  pthread_mutex_lock(&g_context->mutex);
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
  pthread_mutex_lock(&g_context->mutex);
  if (client->currentRoom == -1) {
    pthread_mutex_unlock(&g_context->mutex);
    return;
  }
  if (client->currentRoom >= 0 && client->currentRoom < g_context->roomCount)
    removeMemberFromRoom(g_context->rooms[client->currentRoom], client->socketFD);
  client->currentRoom = -1;
  client->waitingForRoomProof = false;
  client->pendingRoomName[0] = '\0';
  pthread_mutex_unlock(&g_context->mutex);
}

static bool parseRoomProtection(const char *stored, char kdfId[32],
                                char saltHex[ROOM_SALT_HEX_SIZE],
                                char verifierHex[SHA256_HEX_SIZE]) {
  const char *firstSep = strchr(stored, ':');
  const char *secondSep = firstSep ? strchr(firstSep + 1, ':') : NULL;
  if (!firstSep || !secondSep)
    return false;

  size_t kdfLen = (size_t)(firstSep - stored);
  size_t saltLen = (size_t)(secondSep - firstSep - 1);
  if (kdfLen == 0 || kdfLen >= 32)
    return false;
  if (saltLen != ROOM_SALT_HEX_SIZE - 1)
    return false;

  memcpy(kdfId, stored, kdfLen);
  kdfId[kdfLen] = '\0';
  memcpy(saltHex, firstSep + 1, saltLen);
  saltHex[saltLen] = '\0';
  snprintf(verifierHex, SHA256_HEX_SIZE, "%s", secondSep + 1);
  return strcmp(kdfId, ROOM_KDF_ID) == 0 &&
         protocolIsHex(saltHex, ROOM_SALT_HEX_SIZE - 1) &&
         protocolIsHex(verifierHex, SHA256_HEX_SIZE - 1);
}

static bool joinRoom(Client *client, int roomIdx) {
  if (roomIdx < 0 || roomIdx >= g_context->roomCount)
    return false;

  if (client->currentRoom == roomIdx) {
    client->waitingForRoomProof = false;
    client->pendingRoomName[0] = '\0';
    return true;
  }

  Room *target = g_context->rooms[roomIdx];
  if (target->memberCount >= target->maxMembers)
    return false;

  if (!addMemberToRoom(target, client->socketFD))
    return false;

  if (client->currentRoom != -1)
    removeMemberFromRoom(g_context->rooms[client->currentRoom], client->socketFD);

  client->currentRoom = roomIdx;
  client->waitingForRoomProof = false;
  client->pendingRoomName[0] = '\0';
  return true;
}

static void handleSetName(Client *client, const char *name) {
  if (!protocolIsSafeIdentifier(name)) {
    sendError(client->socketFD, "Invalid name");
    return;
  }

  char oldName[MAX_NAME_LEN];
  pthread_mutex_lock(&g_context->mutex);
  for (size_t i = 0; i < g_context->clientCount; i++) {
    Client *other = g_context->clients[i];
    if (other != client && strcasecmp(other->name, name) == 0) {
      pthread_mutex_unlock(&g_context->mutex);
      sendError(client->socketFD, "NAME_IN_USE");
      return;
    }
  }
  snprintf(oldName, sizeof(oldName), "%s", client->name);
  snprintf(client->name, sizeof(client->name), "%s", name);
  Room *room = client->currentRoom >= 0 &&
                       client->currentRoom < g_context->roomCount
                   ? g_context->rooms[client->currentRoom]
                   : NULL;
  pthread_mutex_unlock(&g_context->mutex);
  char nameAck[MSG_SIZE];
  snprintf(nameAck, sizeof(nameAck), "OK|NAME_SET|%s\n", client->name);
  sendFrame(client->socketFD, nameAck);

  if (room) {
    char notice[MSG_SIZE];
    snprintf(notice, sizeof(notice), "INFO|NAME_CHANGED|%s|%s\n", oldName,
             client->name);
    broadcastToRoomTls(room, client->socketFD, notice);
  }
}

static void handleRoomCreate(Client *client, char **parts, size_t partCount) {
  if (partCount < 3 || !protocolIsSafeIdentifier(parts[1])) {
    sendError(client->socketFD, "Invalid room name");
    return;
  }

  Room *room = NULL;
  char protection[MAX_PASSWORD_LEN] = {0};

  if (strcmp(parts[2], "OPEN") == 0 && partCount == 3) {
    room = createRoom(parts[1], NULL);
  } else if (strcmp(parts[2], "PROTECTED") == 0 && partCount == 6 &&
             strcmp(parts[3], ROOM_KDF_ID) == 0 &&
             protocolIsHex(parts[4], ROOM_SALT_HEX_SIZE - 1) &&
             protocolIsHex(parts[5], SHA256_HEX_SIZE - 1)) {
    snprintf(protection, sizeof(protection), "%s:%s:%s", parts[3], parts[4],
             parts[5]);
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
  char ownerToken[TOKEN_STR_SIZE];
  if (!tokenMapLookupByFD(client->socketFD, ownerToken)) {
    pthread_mutex_unlock(&g_context->mutex);
    destroyRoom(room);
    sendError(client->socketFD, "Authentication missing");
    return;
  }
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

  snprintf(room->ownerToken, sizeof(room->ownerToken), "%s", ownerToken);
  g_context->rooms[g_context->roomCount++] = room;
  pthread_mutex_unlock(&g_context->mutex);

  sendOk(client->socketFD, "ROOM_CREATED");
}

static void handleRoomList(Client *client) {
  char names[MAX_ROOMS][MAX_NAME_LEN];
  bool protectedRooms[MAX_ROOMS];
  int count = 0;

  pthread_mutex_lock(&g_context->mutex);
  count = g_context->roomCount;
  for (int i = 0; i < count; i++) {
    snprintf(names[i], sizeof(names[i]), "%s", g_context->rooms[i]->name);
    protectedRooms[i] = g_context->rooms[i]->hasPassword;
  }
  pthread_mutex_unlock(&g_context->mutex);

  sendFrame(client->socketFD, "INFO|ROOMS_BEGIN\n");
  for (int i = 0; i < count; i++) {
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "INFO|ROOM|%s|%s\n", names[i],
             protectedRooms[i] ? "PROTECTED" : "OPEN");
    sendFrame(client->socketFD, frame);
  }
  sendFrame(client->socketFD, "INFO|ROOMS_END\n");
}

static Room *currentRoomForMemberLocked(Client *client) {
  if (client->currentRoom < 0 || client->currentRoom >= g_context->roomCount)
    return NULL;

  Room *room = g_context->rooms[client->currentRoom];
  for (int i = 0; i < room->memberCount; i++) {
    if (room->members[i] == client->socketFD)
      return room;
  }
  return NULL;
}

static Client *clientByFdLocked(SocketHandle fd) {
  for (size_t i = 0; i < g_context->clientCount; i++) {
    if (g_context->clients[i]->socketFD == fd)
      return g_context->clients[i];
  }
  return NULL;
}

static void handleRoomMembers(Client *client) {
  char names[MAX_ROOM_MEMBERS][MAX_NAME_LEN];
  char tokens[MAX_ROOM_MEMBERS][TOKEN_STR_SIZE];
  bool owners[MAX_ROOM_MEMBERS] = {0};
  char roomName[MAX_NAME_LEN];
  int count = 0;

  pthread_mutex_lock(&g_context->mutex);
  Room *room = currentRoomForMemberLocked(client);
  if (!room) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Not in a room");
    return;
  }

  snprintf(roomName, sizeof(roomName), "%s", room->name);
  for (int i = 0; i < room->memberCount && count < MAX_ROOM_MEMBERS; i++) {
    Client *member = clientByFdLocked(room->members[i]);
    if (!member || !tokenMapLookupByFD(room->members[i], tokens[count]))
      continue;
    snprintf(names[count], sizeof(names[count]), "%s", member->name);
    owners[count] = strcmp(tokens[count], room->ownerToken) == 0;
    count++;
  }
  pthread_mutex_unlock(&g_context->mutex);

  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "INFO|MEMBERS_BEGIN|%s\n", roomName);
  sendFrame(client->socketFD, frame);
  for (int i = 0; i < count; i++) {
    snprintf(frame, sizeof(frame), "INFO|MEMBER|%s|%s|%s\n", names[i],
             tokens[i], owners[i] ? "OWNER" : "MEMBER");
    sendFrame(client->socketFD, frame);
  }
  sendFrame(client->socketFD, "INFO|MEMBERS_END\n");
}

static void sendRoomTopic(Client *client) {
  char topic[MAX_ROOM_TOPIC_LEN];

  pthread_mutex_lock(&g_context->mutex);
  Room *room = currentRoomForMemberLocked(client);
  if (!room) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Not in a room");
    return;
  }
  snprintf(topic, sizeof(topic), "%s", room->topic);
  pthread_mutex_unlock(&g_context->mutex);

  char encoded[MSG_SIZE];
  if (topic[0] && !protocolEncodeText(topic, encoded, sizeof(encoded))) {
    sendError(client->socketFD, "Failed to encode room topic");
    return;
  }
  if (!topic[0])
    snprintf(encoded, sizeof(encoded), "-");

  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "INFO|ROOM_TOPIC|%s|-\n", encoded);
  sendFrame(client->socketFD, frame);
}

static void handleRoomTopicSet(Client *client, const char *encoded) {
  char topic[MAX_ROOM_TOPIC_LEN] = {0};
  if (strcmp(encoded, "-") != 0 &&
      (!protocolDecodeText(encoded, topic, sizeof(topic)) ||
       !protocolIsSafeText(topic, MAX_ROOM_TOPIC_LEN - 1) || !topic[0])) {
    sendError(client->socketFD, "Invalid room topic");
    return;
  }

  pthread_mutex_lock(&g_context->mutex);
  Room *room = currentRoomForMemberLocked(client);
  char senderToken[TOKEN_STR_SIZE];
  if (!room || !tokenMapLookupByFD(client->socketFD, senderToken)) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Not in a room");
    return;
  }
  if (strcmp(senderToken, room->ownerToken) != 0) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Only room owner may change topic");
    return;
  }
  snprintf(room->topic, sizeof(room->topic), "%s", topic);
  pthread_mutex_unlock(&g_context->mutex);

  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "INFO|ROOM_TOPIC|%s|%s\n",
           topic[0] ? encoded : "-", client->name);
  sendFrame(client->socketFD, frame);
  broadcastToRoomTls(room, client->socketFD, frame);
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
    broadcastToRoomTls(room, client->socketFD, joined);
    return;
  }

  char kdfId[32];
  char saltHex[ROOM_SALT_HEX_SIZE];
  char verifierHex[SHA256_HEX_SIZE];
  if (!parseRoomProtection(room->password, kdfId, saltHex, verifierHex)) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room protection data is corrupt");
    return;
  }

  client->waitingForRoomProof = true;
  snprintf(client->pendingRoomName, sizeof(client->pendingRoomName), "%s",
           roomName);
  pthread_mutex_unlock(&g_context->mutex);

  char challenge[MSG_SIZE];
  snprintf(challenge, sizeof(challenge), "ROOM_CHALLENGE|%s|%s|%s\n",
           roomName, kdfId, saltHex);
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

  char kdfId[32];
  char saltHex[ROOM_SALT_HEX_SIZE];
  char expectedVerifier[SHA256_HEX_SIZE];
  if (!parseRoomProtection(g_context->rooms[roomIdx]->password, kdfId, saltHex,
                           expectedVerifier)) {
    client->waitingForRoomProof = false;
    client->pendingRoomName[0] = '\0';
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room protection data is corrupt");
    return;
  }

  if (!protocolIsHex(verifierHex, SHA256_HEX_SIZE - 1) ||
      CRYPTO_memcmp(expectedVerifier, verifierHex, SHA256_HEX_SIZE - 1) != 0) {
    client->waitingForRoomProof = false;
    client->pendingRoomName[0] = '\0';
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Incorrect room secret");
    return;
  }

  Room *room = g_context->rooms[roomIdx];
  if (!joinRoom(client, roomIdx)) {
    pthread_mutex_unlock(&g_context->mutex);
    sendError(client->socketFD, "Room is full");
    return;
  }
  pthread_mutex_unlock(&g_context->mutex);

  sendFrame(client->socketFD, "OK|ROOM_ENTERED|PROTECTED\n");
  char joined[MSG_SIZE];
  snprintf(joined, sizeof(joined), "INFO|ROOM_JOINED|%s\n", client->name);
  broadcastToRoomTls(room, client->socketFD, joined);
}

static void handleRoomLeave(Client *client) {
  pthread_mutex_lock(&g_context->mutex);
  Room *oldRoom = client->currentRoom >= 0 &&
                          client->currentRoom < g_context->roomCount
                      ? g_context->rooms[client->currentRoom]
                      : NULL;
  pthread_mutex_unlock(&g_context->mutex);
  if (!oldRoom) {
    sendError(client->socketFD, "Not in a room");
    return;
  }
  char left[MSG_SIZE];
  snprintf(left, sizeof(left), "INFO|ROOM_LEFT|%s\n", client->name);
  if (oldRoom)
    broadcastToRoomTls(oldRoom, client->socketFD, left);

  leaveCurrentRoom(client);
  sendOk(client->socketFD, "ROOM_LEFT");
}

static void handleRoomSend(Client *client, const char *payload) {
  if (!payload || !payload[0] || strlen(payload) > PROTOCOL_MAX_PAYLOAD) {
    sendError(client->socketFD, "Invalid room message");
    return;
  }

  unsigned char decoded[MSG_SIZE];
  int decodedLen = decodeBase64(payload, decoded, sizeof(decoded));
  if (decodedLen <= 0) {
    sendError(client->socketFD, "Invalid room message encoding");
    return;
  }

  pthread_mutex_lock(&g_context->mutex);
  Room *room = client->currentRoom >= 0 &&
                       client->currentRoom < g_context->roomCount
                   ? g_context->rooms[client->currentRoom]
                   : NULL;
  bool isMember = false;
  if (room) {
    for (int i = 0; i < room->memberCount; i++) {
      if (room->members[i] == client->socketFD) {
        isMember = true;
        break;
      }
    }
  }
  bool protectedRoom = room && room->hasPassword;
  pthread_mutex_unlock(&g_context->mutex);

  if (!room || !isMember) {
    sendError(client->socketFD, "Not in a room");
    return;
  }

  if ((!protectedRoom && decodedLen > MAX_MESSAGE_TEXT) ||
      (protectedRoom &&
       (decodedLen < AES_GCM_OVERHEAD ||
        decodedLen > MAX_MESSAGE_TEXT + AES_GCM_OVERHEAD))) {
    sendError(client->socketFD, "Invalid encrypted room message");
    return;
  }

  char frame[MSG_SIZE * 2];
  snprintf(frame, sizeof(frame), "ROOM_MSG|%s|%s\n", client->name, payload);
  broadcastToRoomTls(room, client->socketFD, frame);
}

static void forwardDmFrame(Client *client, const char *targetToken,
                           const char *frameType, const char *fields) {
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
  snprintf(frame, sizeof(frame), "%s|%s|%s\n", frameType, senderToken, fields);
  sendFrame(targetFD, frame);
}

static bool validSequence(const char *value) {
  uint64_t sequence = 0;
  return protocolParseSequence(value, &sequence);
}

static bool handleAuth(Client *client, char **parts, size_t partCount,
                       const unsigned char nonce[CHALLENGE_BYTES]) {
  if (partCount != 4 || strcmp(parts[1], PROTOCOL_VERSION) != 0 ||
      strlen(parts[2]) != TOKEN_HEX_LEN || strlen(parts[3]) != SIG_HEX_LEN) {
    sendError(client->socketFD, "Malformed AUTH");
    return false;
  }

  unsigned char sig[SIG_BYTES];
  if (!hexToBytes(parts[3], sig, sizeof(sig))) {
    sendError(client->socketFD, "Invalid signature encoding");
    return false;
  }

  unsigned char transcript[64];
  size_t transcriptLen = 0;
  if (!protocolBuildAuthTranscript(nonce, CHALLENGE_BYTES, transcript,
                                   sizeof(transcript), &transcriptLen) ||
      !identityVerify(parts[2], transcript, transcriptLen, sig)) {
    sendError(client->socketFD, "Authentication failed");
    return false;
  }

  pthread_mutex_lock(&g_context->mutex);
  int rc = tokenMapSet(parts[2], client->socketFD);
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

  time_t now = time(NULL);
  if (client->rateWindow != now) {
    client->rateWindow = now;
    client->framesInWindow = 0;
    client->dmInitsInWindow = 0;
  }
  if (++client->framesInWindow > 100) {
    sendError(client->socketFD, "Rate limit exceeded");
    return false;
  }
  if (strcmp(parts[0], "DM_INIT") == 0 && ++client->dmInitsInWindow > 5) {
    sendError(client->socketFD, "DM request rate limit exceeded");
    return false;
  }

  if (strcmp(parts[0], "SET_NAME") == 0 && partCount == 2) {
    handleSetName(client, parts[1]);
    return true;
  }
  if (strcmp(parts[0], "ROOM_CREATE") == 0) {
    handleRoomCreate(client, parts, partCount);
    return true;
  }
  if (strcmp(parts[0], "ROOM_LIST") == 0 && partCount == 1) {
    handleRoomList(client);
    return true;
  }
  if (strcmp(parts[0], "ROOM_MEMBERS") == 0 && partCount == 1) {
    handleRoomMembers(client);
    return true;
  }
  if (strcmp(parts[0], "ROOM_TOPIC_GET") == 0 && partCount == 1) {
    sendRoomTopic(client);
    return true;
  }
  if (strcmp(parts[0], "ROOM_TOPIC_SET") == 0 && partCount == 2) {
    handleRoomTopicSet(client, parts[1]);
    return true;
  }
  if (strcmp(parts[0], "ROOM_ENTER") == 0 && partCount == 2) {
    handleRoomEnter(client, parts[1]);
    return true;
  }
  if (strcmp(parts[0], "ROOM_PROOF") == 0 && partCount == 3) {
    handleRoomProof(client, parts[1], parts[2]);
    return true;
  }
  if (strcmp(parts[0], "ROOM_LEAVE") == 0 && partCount == 1) {
    handleRoomLeave(client);
    return true;
  }
  if (strcmp(parts[0], "ROOM_SEND") == 0 && partCount == 2) {
    handleRoomSend(client, parts[1]);
    return true;
  }
  if (strcmp(parts[0], "DM_INIT") == 0 && partCount == 5 &&
      protocolIsHex(parts[1], TOKEN_HEX_LEN) &&
      protocolIsHex(parts[2], DM_SESSION_ID_HEX_LEN) &&
      protocolIsHex(parts[3], 64) && protocolIsHex(parts[4], SIG_HEX_LEN)) {
    char fields[MSG_SIZE];
    snprintf(fields, sizeof(fields), "%s|%s|%s", parts[2], parts[3], parts[4]);
    forwardDmFrame(client, parts[1], "DM_INIT", fields);
    return true;
  }
  if (strcmp(parts[0], "DM_ACK") == 0 && partCount == 6 &&
      protocolIsHex(parts[1], TOKEN_HEX_LEN) &&
      protocolIsHex(parts[2], DM_SESSION_ID_HEX_LEN) &&
      protocolIsHex(parts[3], 64) && protocolIsHex(parts[4], 64) &&
      protocolIsHex(parts[5], SIG_HEX_LEN)) {
    char fields[MSG_SIZE];
    snprintf(fields, sizeof(fields), "%s|%s|%s|%s", parts[2], parts[3],
             parts[4], parts[5]);
    forwardDmFrame(client, parts[1], "DM_ACK", fields);
    return true;
  }
  if (strcmp(parts[0], "DM_REJECT") == 0 && partCount == 4 &&
      protocolIsHex(parts[1], TOKEN_HEX_LEN) &&
      protocolIsHex(parts[2], DM_SESSION_ID_HEX_LEN) &&
      strcmp(parts[3], "BUSY") == 0) {
    char fields[MSG_SIZE];
    snprintf(fields, sizeof(fields), "%s|BUSY", parts[2]);
    forwardDmFrame(client, parts[1], "DM_REJECT", fields);
    return true;
  }
  if (strcmp(parts[0], "DM_CLOSE") == 0 && partCount == 3 &&
      protocolIsHex(parts[1], TOKEN_HEX_LEN) &&
      protocolIsHex(parts[2], DM_SESSION_ID_HEX_LEN)) {
    forwardDmFrame(client, parts[1], "DM_CLOSE", parts[2]);
    return true;
  }
  if (strcmp(parts[0], "DM_SEND") == 0 && partCount == 5 &&
      protocolIsHex(parts[1], TOKEN_HEX_LEN) &&
      protocolIsHex(parts[2], DM_SESSION_ID_HEX_LEN) &&
      validSequence(parts[3]) && validEncryptedPayload(parts[4])) {
    char fields[MSG_SIZE * 2];
    snprintf(fields, sizeof(fields), "%s|%s|%s", parts[2], parts[3], parts[4]);
    forwardDmFrame(client, parts[1], "DM_MSG", fields);
    return true;
  }
  if (strcmp(parts[0], "QUIT") == 0 && partCount == 1) {
    sendOk(client->socketFD, "BYE");
    return false;
  }

  sendError(client->socketFD, "Unknown frame");
  return true;
}

static void *handleClient(void *arg) {
  Client *client = (Client *)arg;
  char buffer[MSG_SIZE];

  setSocketTimeoutsMs(client->socketFD, 5000, 5000);
  SSL *ssl = tlsServerAccept(g_sslCtx, client->socketFD);
  if (!ssl)
    goto disconnect;
  if (!sslMapAdd(client->socketFD, ssl)) {
    tlsFree(ssl);
    goto disconnect;
  }

  unsigned char nonce[CHALLENGE_BYTES];
  if (RAND_bytes(nonce, CHALLENGE_BYTES) != 1) {
    sendError(client->socketFD, "Server could not generate challenge");
    goto disconnect;
  }

  char nonceHex[CHALLENGE_HEX_SIZE];
  bytesToHex(nonce, sizeof(nonce), nonceHex);
  char challenge[MSG_SIZE];
  snprintf(challenge, sizeof(challenge), "CHALLENGE|%s|%s\n",
           PROTOCOL_VERSION, nonceHex);
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

  setSocketTimeoutsMs(client->socketFD, 0, 10000);

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
  pthread_mutex_lock(&g_context->mutex);
  Room *room = client->currentRoom >= 0 &&
                       client->currentRoom < g_context->roomCount
                   ? g_context->rooms[client->currentRoom]
                   : NULL;
  pthread_mutex_unlock(&g_context->mutex);
  if (room) {
    char left[MSG_SIZE];
    snprintf(left, sizeof(left), "INFO|ROOM_LEFT|%s\n", client->name);
    broadcastToRoomTls(room, client->socketFD, left);
  }
  leaveCurrentRoom(client);
  pthread_mutex_lock(&g_context->mutex);
  tokenMapRemoveByFD(client->socketFD);
  pthread_mutex_unlock(&g_context->mutex);
  sslMapRemove(client->socketFD);
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

  printf("Server listening on port %d (TLS, protocol v%s)\n", serverPort,
         PROTOCOL_VERSION);

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
      platformCloseSocket(client->socketFD);
      free(client->address);
      free(client);
      continue;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, handleClient, client) != 0) {
      perror("pthread_create");
      sslMapRemove(client->socketFD);
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
