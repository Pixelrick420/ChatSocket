#pragma once
#ifndef SOCKETUTIL_H
#define SOCKETUTIL_H

#include <ctype.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "platform.h"

#define MSG_SIZE         4096
#define MAX_MESSAGE_TEXT 1400
#define PORT             2077
#define MAX_NAME_LEN       64
#define MAX_PASSWORD_LEN  256
#define MAX_ROOM_TOPIC_LEN 256
#define ROOM_OWNER_TOKEN_SIZE 65
#define MAX_ROOM_MEMBERS   32
#define ROOM_TIMEOUT     3600

#define COLOR_RESET  "\033[0m"
#define COLOR_GREEN  "\033[1;32m"
#define COLOR_CYAN   "\033[1;36m"
#define COLOR_RED    "\033[1;31m"
#define COLOR_YELLOW "\033[1;33m"


typedef struct sockaddr_in SocketAddress;
typedef struct
{
    char   name[MAX_NAME_LEN];
    char   password[MAX_PASSWORD_LEN];
    char   topic[MAX_ROOM_TOPIC_LEN];
    char   ownerToken[ROOM_OWNER_TOKEN_SIZE];
    bool   hasPassword;
    SocketHandle *members;
    int    memberCount;
    int    maxMembers;
    time_t lastActivity;
} Room;
typedef struct
{
    SocketHandle  socketFD;
    SocketAddress *address;
    char           name[MAX_NAME_LEN];
    char           pendingRoomName[MAX_NAME_LEN];
    char           roomSessionId[33];
    uint64_t       roomSendSeq;
    int            currentRoom;
    bool           hasConfirmedName;
    bool           waitingForRoomProof;
    time_t         rateWindow;
    unsigned int   framesInWindow;
    unsigned int   dmInitsInWindow;
    bool           success;
    int            error;
} Client;
typedef struct
{
    SocketHandle socketFD;
    Client   **clients;
    size_t     clientCount;
    int        maxClients;
    Room     **rooms;
    int        roomCount;
    int        maxRooms;
    pthread_mutex_t mutex;
} ServerContext;


void print(const char *message);
SocketHandle   createTCPSocket(void);
SocketAddress *createSocketAddress(const char *ipAddr, int port, bool isClient);
int connectSocket(SocketHandle socketFD, SocketAddress *address);
int bindSocket  (SocketHandle socketFD, SocketAddress *address);
Client        *acceptClient   (SocketHandle serverSocketFD);
ServerContext *createServerContext(SocketHandle socketFD, int maxClients, int maxRooms);
void           destroyServerContext(ServerContext *context);
bool addClient   (ServerContext *context, Client *client);
void removeClient(ServerContext *context, SocketHandle socketFD);
Room *createRoom        (const char *name, const char *password);
void  destroyRoom       (Room *room);
int   findRoomIndex     (ServerContext *context, const char *name);
bool  addMemberToRoom   (Room *room, SocketHandle socketFD);
bool  removeMemberFromRoom(Room *room, SocketHandle socketFD);
void  updateRoomActivity(Room *room);
void  cleanupInactiveRooms(ServerContext *context);
void broadcastToRoom(ServerContext *context, int roomIdx,
                     SocketHandle senderFD, const char *msg);

#endif
