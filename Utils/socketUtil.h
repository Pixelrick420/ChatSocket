#ifndef SOCKETUTIL_H
#define SOCKETUTIL_H

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MSG_SIZE 2048
#define PORT 2077
#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_RED "\033[1;31m"
#define COLOR_YELLOW "\033[1;33m"

typedef enum
{
    CMD_HELP,
    CMD_NAME,
    CMD_CREATE,
    CMD_ENTER,
    CMD_LEAVE,
    CMD_EXIT,
    CMD_MESSAGE,
    CMD_UNKNOWN
} CommandType;

typedef struct sockaddr_in SocketAddress;
typedef struct Room
{
    char name[64];
    char password[128];
    bool hasPassword;
    int* members;
    int memberCount;
    int maxMembers;
    time_t lastActivity;
} Room;

typedef struct
{
    int socketFD;
    SocketAddress* address;
    int error;
    bool success;
    char name[64];
    int currentRoom;
} Client;

typedef struct
{
    int socketFD;
    pthread_mutex_t mutex;
    Client** clients;
    size_t clientCount;
    int size;
    Room** rooms;
    int roomCount;
    int maxRooms;
} ServerContext;

void print(char* message);
int createTCPIPv4Socket();
SocketAddress* getSocketAddress(char* ipAddr, int port, bool isClient);
int connectToSocket(int socketFD, SocketAddress* address, int size);
int bindServerToSocket(int socketFD, SocketAddress* address, int size);
Client* createClient(int socketFD, SocketAddress* clientAddr);
void recieveMessages(int socketFD);
ServerContext* createContext(int socketFD, int size);
void cleanupServer(ServerContext* context);
int addClient(ServerContext* context, Client* client);
void removeClient(ServerContext* context, int socketFD);
void broadcastMessage(ServerContext* context, int senderFD, const char* msg, size_t len);
int findRoom(ServerContext* context, const char* name);
Room* createRoom(const char* name, const char* password);
void cleanupInactiveRooms(ServerContext* context);
void broadcastToRoom(ServerContext* context, int roomIdx, int senderFD, const char* msg, size_t len);
#endif
