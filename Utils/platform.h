#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <direct.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET SocketHandle;
#define INVALID_SOCKET_HANDLE INVALID_SOCKET
#define SOCKETCHAT_PATH_SEP '\\'
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
typedef int SocketHandle;
#define INVALID_SOCKET_HANDLE (-1)
#define SOCKETCHAT_PATH_SEP '/'
#endif

bool platformInit(void);
void platformCleanup(void);
int platformCloseSocket(SocketHandle socketFD);
int platformShutdownSocket(SocketHandle socketFD);
int platformCloseFd(int fd);
void platformSleepMs(unsigned int ms);
bool platformLocalTime(time_t now, struct tm *outTm);
bool platformGetHomeDir(char *out, size_t outSize);
bool platformGetConfigDir(char *out, size_t outSize);
bool platformEnsureDir(const char *path);
bool platformSecureUserFileFd(int fd);
char *platformStrDup(const char *src);
int platformSocketErrno(void);
bool platformSetSocketNonBlocking(SocketHandle socketFD, bool enabled);
uint64_t platformMonotonicMs(void);
