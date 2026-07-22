#include "platform.h"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

bool platformInit(void) {
#ifdef _WIN32
  static bool initialized = false;
  if (initialized)
    return true;

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return false;

  initialized = true;
#endif
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);
#endif
  return true;
}

void platformCleanup(void) {
#ifdef _WIN32
  WSACleanup();
#endif
}

int platformCloseSocket(SocketHandle socketFD) {
#ifdef _WIN32
  return closesocket(socketFD);
#else
  return close(socketFD);
#endif
}

int platformShutdownSocket(SocketHandle socketFD) {
#ifdef _WIN32
  return shutdown(socketFD, SD_BOTH);
#else
  return shutdown(socketFD, SHUT_RDWR);
#endif
}

int platformCloseFd(int fd) {
#ifdef _WIN32
  return _close(fd);
#else
  return close(fd);
#endif
}

void platformSleepMs(unsigned int ms) {
#ifdef _WIN32
  Sleep(ms);
#else
  struct timespec req;
  req.tv_sec = (time_t)(ms / 1000U);
  req.tv_nsec = (long)((ms % 1000U) * 1000000L);
  while (nanosleep(&req, &req) != 0 && errno == EINTR) {
  }
#endif
}

bool platformLocalTime(time_t now, struct tm *outTm) {
  if (!outTm)
    return false;

#ifdef _WIN32
  return localtime_s(outTm, &now) == 0;
#else
  return localtime_r(&now, outTm) != NULL;
#endif
}

bool platformGetHomeDir(char *out, size_t outSize) {
  if (!out || outSize == 0)
    return false;

  const char *home = getenv("HOME");
#ifdef _WIN32
  if (!home || !home[0])
    home = getenv("USERPROFILE");
#else
  if (!home || !home[0]) {
    struct passwd *pw = getpwuid(getuid());
    if (pw)
      home = pw->pw_dir;
  }
#endif

  if (!home || !home[0])
    return false;

  int n = snprintf(out, outSize, "%s", home);
  return n >= 0 && (size_t)n < outSize;
}

bool platformGetConfigDir(char *out, size_t outSize) {
  if (!out || outSize == 0)
    return false;

#ifdef _WIN32
  const char *base = getenv("APPDATA");
  char home[512];
  if ((!base || !base[0]) && !platformGetHomeDir(home, sizeof(home)))
    return false;
  if (!base || !base[0])
    base = home;
  int n = snprintf(out, outSize, "%s%cSocketChat", base, SOCKETCHAT_PATH_SEP);
#else
  char home[512];
  if (!platformGetHomeDir(home, sizeof(home)))
    return false;
  int n = snprintf(out, outSize, "%s%c.socketchat", home, SOCKETCHAT_PATH_SEP);
#endif
  return n >= 0 && (size_t)n < outSize;
}

bool platformEnsureDir(const char *path) {
  if (!path || !path[0])
    return false;

#ifdef _WIN32
  if (_mkdir(path) == 0 || errno == EEXIST)
    return true;
#else
  if (mkdir(path, 0700) == 0)
    return true;
  if (errno == EEXIST) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid()) {
      errno = EPERM;
      return false;
    }
    if ((st.st_mode & 0777) != 0700 && chmod(path, 0700) != 0)
      return false;
    return true;
  }
#endif

  return false;
}

bool platformSecureUserFileFd(int fd) {
#ifdef _WIN32
  return fd >= 0;
#else
  struct stat st;
  if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      st.st_uid != geteuid()) {
    errno = EPERM;
    return false;
  }
  return fchmod(fd, 0600) == 0;
#endif
}

char *platformStrDup(const char *src) {
  if (!src)
    return NULL;

  size_t len = strlen(src) + 1;
  char *copy = malloc(len);
  if (!copy)
    return NULL;
  memcpy(copy, src, len);
  return copy;
}

int platformSocketErrno(void) {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}
