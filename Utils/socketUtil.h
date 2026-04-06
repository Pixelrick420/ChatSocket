#pragma once
#ifndef SOCKETUTIL_H
#define SOCKETUTIL_H

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define MSG_SIZE         2048
#define PORT             2077
#define MAX_NAME_LEN       64
#define MAX_PASSWORD_LEN  256
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
    bool   hasPassword;
    int   *members;
    int    memberCount;
    int    maxMembers;
    time_t lastActivity;
} Room;
typedef struct
{
    int           socketFD;
    SocketAddress *address;
    char           name[MAX_NAME_LEN];
    int            currentRoom;
    bool           success;
    int            error;
} Client;
typedef struct
{
    int        socketFD;
    Client   **clients;
    size_t     clientCount;
    int        maxClients;
    Room     **rooms;
    int        roomCount;
    int        maxRooms;
    pthread_mutex_t mutex;
} ServerContext;


void print(const char *message);
int            createTCPSocket(void);
SocketAddress *createSocketAddress(const char *ipAddr, int port, bool isClient);
int connectSocket(int socketFD, SocketAddress *address);
int bindSocket  (int socketFD, SocketAddress *address);
Client        *acceptClient   (int serverSocketFD);
ServerContext *createServerContext(int socketFD, int maxClients, int maxRooms);
void           destroyServerContext(ServerContext *context);
bool addClient   (ServerContext *context, Client *client);
void removeClient(ServerContext *context, int socketFD);
Room *createRoom        (const char *name, const char *password);
void  destroyRoom       (Room *room);
int   findRoomIndex     (ServerContext *context, const char *name);
bool  addMemberToRoom   (Room *room, int socketFD);
bool  removeMemberFromRoom(Room *room, int socketFD);
void  updateRoomActivity(Room *room);
void  cleanupInactiveRooms(ServerContext *context);
void broadcastToRoom(ServerContext *context, int roomIdx,
                     int senderFD, const char *msg);

#endif
