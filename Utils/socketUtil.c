#include "socketUtil.h"

static pthread_mutex_t s_printLock = PTHREAD_MUTEX_INITIALIZER;

void print(const char *message) {
  pthread_mutex_lock(&s_printLock);
  fputs(message, stdout);
  fflush(stdout);
  pthread_mutex_unlock(&s_printLock);
}

SocketHandle createTCPSocket(void) {
  SocketHandle fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == INVALID_SOCKET_HANDLE)
    perror("socket");
  return fd;
}

SocketAddress *createSocketAddress(const char *ipAddr, int port,
                                   bool isClient) {
  SocketAddress *addr = calloc(1, sizeof(SocketAddress));
  if (!addr) {
    perror("calloc");
    return NULL;
  }

  addr->sin_family = AF_INET;
  addr->sin_port = htons((uint16_t)port);

  if (isClient) {
    if (inet_pton(AF_INET, ipAddr, &addr->sin_addr) <= 0) {
      perror("inet_pton");
      free(addr);
      return NULL;
    }
  } else {
    addr->sin_addr.s_addr = INADDR_ANY;
  }
  return addr;
}

int connectSocket(SocketHandle socketFD, SocketAddress *address) {
  if (connect(socketFD, (struct sockaddr *)address, sizeof(*address)) != 0) {
    perror("connect");
    return -1;
  }
  return 0;
}

int bindSocket(SocketHandle socketFD, SocketAddress *address) {
  if (bind(socketFD, (struct sockaddr *)address, sizeof(*address)) != 0) {
    perror("bind");
    exit(EXIT_FAILURE);
  }
  return 0;
}

Client *acceptClient(SocketHandle serverSocketFD) {
  Client *client = calloc(1, sizeof(Client));
  SocketAddress *clientAddr = calloc(1, sizeof(SocketAddress));

  if (!client || !clientAddr) {
    free(client);
    free(clientAddr);
    return NULL;
  }

  socklen_t addrSize = sizeof(SocketAddress);
  client->socketFD =
      accept(serverSocketFD, (struct sockaddr *)clientAddr, &addrSize);
  client->address = clientAddr;
  client->success = (client->socketFD != INVALID_SOCKET_HANDLE);
  client->currentRoom = -1;
  client->error = client->success ? 0 : platformSocketErrno();

  snprintf(client->name, MAX_NAME_LEN, "pending");

  return client;
}

ServerContext *createServerContext(SocketHandle socketFD, int maxClients,
                                   int maxRooms) {
  ServerContext *ctx = calloc(1, sizeof(ServerContext));
  if (!ctx) {
    perror("calloc");
    exit(EXIT_FAILURE);
  }

  ctx->socketFD = socketFD;
  ctx->maxClients = maxClients;
  ctx->maxRooms = maxRooms;

  ctx->clients = calloc((size_t)maxClients, sizeof(Client *));
  ctx->rooms = calloc((size_t)maxRooms, sizeof(Room *));

  if (!ctx->clients || !ctx->rooms) {
    perror("calloc");
    exit(EXIT_FAILURE);
  }

  pthread_mutex_init(&ctx->mutex, NULL);
  return ctx;
}

void destroyServerContext(ServerContext *context) {
  if (!context)
    return;

  pthread_mutex_destroy(&context->mutex);

  for (int i = 0; i < context->roomCount; i++)
    destroyRoom(context->rooms[i]);

  free(context->rooms);
  free(context->clients);
  free(context);
}

bool addClient(ServerContext *context, Client *client) {
  pthread_mutex_lock(&context->mutex);

  if (context->clientCount >= (size_t)context->maxClients) {
    pthread_mutex_unlock(&context->mutex);
    return false;
  }

  context->clients[context->clientCount++] = client;
  pthread_mutex_unlock(&context->mutex);
  return true;
}

void removeClient(ServerContext *context, SocketHandle socketFD) {
  pthread_mutex_lock(&context->mutex);

  for (size_t i = 0; i < context->clientCount; i++) {
    if (context->clients[i]->socketFD == socketFD) {
      context->clients[i] = context->clients[--context->clientCount];
      break;
    }
  }

  pthread_mutex_unlock(&context->mutex);
}

Room *createRoom(const char *name, const char *password) {
  Room *room = calloc(1, sizeof(Room));
  if (!room)
    return NULL;

  strncpy(room->name, name, MAX_NAME_LEN - 1);

  room->hasPassword = (password != NULL && password[0] != '\0');
  if (room->hasPassword)
    strncpy(room->password, password, MAX_PASSWORD_LEN - 1);

  room->members = calloc(MAX_ROOM_MEMBERS, sizeof(SocketHandle));
  if (!room->members) {
    free(room);
    return NULL;
  }

  room->maxMembers = MAX_ROOM_MEMBERS;
  room->lastActivity = time(NULL);

  return room;
}

void destroyRoom(Room *room) {
  if (!room)
    return;
  free(room->members);
  free(room);
}

int findRoomIndex(ServerContext *context, const char *name) {
  for (int i = 0; i < context->roomCount; i++)
    if (strcmp(context->rooms[i]->name, name) == 0)
      return i;
  return -1;
}

bool addMemberToRoom(Room *room, SocketHandle socketFD) {
  if (room->memberCount >= room->maxMembers)
    return false;
  room->members[room->memberCount++] = socketFD;
  return true;
}

bool removeMemberFromRoom(Room *room, SocketHandle socketFD) {
  for (int i = 0; i < room->memberCount; i++) {
    if (room->members[i] == socketFD) {
      room->members[i] = room->members[--room->memberCount];
      return true;
    }
  }
  return false;
}

void updateRoomActivity(Room *room) { room->lastActivity = time(NULL); }

void cleanupInactiveRooms(ServerContext *context) {
  time_t now = time(NULL);
  pthread_mutex_lock(&context->mutex);

  for (int i = 0; i < context->roomCount; i++) {
    if (context->rooms[i]->memberCount == 0 &&
        difftime(now, context->rooms[i]->lastActivity) > ROOM_TIMEOUT) {
      destroyRoom(context->rooms[i]);
      for (int j = i; j + 1 < context->roomCount; j++)
        context->rooms[j] = context->rooms[j + 1];
      context->rooms[--context->roomCount] = NULL;

      for (size_t j = 0; j < context->clientCount; j++) {
        if (context->clients[j]->currentRoom > i)
          context->clients[j]->currentRoom--;
      }
      i--;
    }
  }

  pthread_mutex_unlock(&context->mutex);
}

void broadcastToRoom(ServerContext *context, int roomIdx, SocketHandle senderFD,
                     const char *msg) {
  SocketHandle fds[MAX_ROOM_MEMBERS];
  int count = 0;

  pthread_mutex_lock(&context->mutex);
  Room *room = context->rooms[roomIdx];
  updateRoomActivity(room);
  for (int i = 0; i < room->memberCount; i++)
    if (room->members[i] != senderFD)
      fds[count++] = room->members[i];
  pthread_mutex_unlock(&context->mutex);

  size_t msgLen = strlen(msg);
  for (int i = 0; i < count; i++)
    send(fds[i], msg, msgLen, 0);
}
