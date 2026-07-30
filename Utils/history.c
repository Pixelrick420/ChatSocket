#include "history.h"
#include "identity.h"

#include <ctype.h>
#include <fcntl.h>

#define MAX_LINE 2048

static bool historyEnabled(void) {
  const char *value = getenv("SOCKETCHAT_HISTORY");
  return !value || strcmp(value, "0") != 0;
}

static bool historyPath(const char *peerToken, char *out, size_t outSize) {
  if (!peerToken || strlen(peerToken) != TOKEN_HEX_LEN)
    return false;
  for (size_t i = 0; peerToken[i]; i++) {
    if (!isxdigit((unsigned char)peerToken[i]))
      return false;
  }

  char dir[512];
  if (!platformGetConfigDir(dir, sizeof(dir)))
    return false;
  snprintf(out, outSize, "%s%cdm_%.64s.log", dir, SOCKETCHAT_PATH_SEP,
           peerToken);
  return true;
}

static bool ensureDir(void) {
  char dir[512];
  if (!platformGetConfigDir(dir, sizeof(dir)))
    return false;
  return platformEnsureDir(dir);
}

static size_t escapeNewlines(const char *msg, char *buf, size_t bufSize) {
  size_t j = 0;
  for (size_t i = 0; msg[i] && j + 2 < bufSize; i++) {
    if (msg[i] == '\n') {
      buf[j++] = '\\';
      buf[j++] = 'n';
    } else {
      buf[j++] = msg[i];
    }
  }
  buf[j] = '\0';
  return j;
}

bool historyAppend(const char *peerToken, bool sent, const char *message) {
  if (!historyEnabled())
    return true;
  if (!ensureDir())
    return false;

  char path[512 + 96];
  if (!historyPath(peerToken, path, sizeof(path)))
    return false;

  int flags = O_WRONLY | O_CREAT | O_APPEND;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
  flags |= O_NONBLOCK;
#endif
  int fd = open(path, flags, 0600);
  if (fd < 0)
    return false;
  if (!platformSecureUserFileFd(fd)) {
    platformCloseFd(fd);
    return false;
  }
  FILE *f = fdopen(fd, "a");
  if (!f) {
    platformCloseFd(fd);
    return false;
  }

  time_t now = time(NULL);
  struct tm tmInfo;
  char ts[32] = "0000-00-00T00:00:00";
  if (platformLocalTime(now, &tmInfo))
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmInfo);

  char escaped[MAX_LINE];
  escapeNewlines(message, escaped, sizeof(escaped));

  fprintf(f, "%s %s %s\n", ts, sent ? ">>>" : "<<<", escaped);
  fclose(f);
  return true;
}

static int compareHistoryEntries(const void *lhs, const void *rhs) {
  const HistoryDmEntry *a = (const HistoryDmEntry *)lhs;
  const HistoryDmEntry *b = (const HistoryDmEntry *)rhs;

  if (a->lastActive < b->lastActive)
    return 1;
  if (a->lastActive > b->lastActive)
    return -1;
  return strcmp(a->token, b->token);
}

size_t historyLoadEntries(HistoryDmEntry *entries, size_t maxEntries) {
  if (!historyEnabled() || !entries || maxEntries == 0)
    return 0;

  char dir[1024];
  if (!platformGetConfigDir(dir, sizeof(dir)))
    return 0;

  DIR *d = opendir(dir);
  if (!d)
    return 0;

  size_t capacity = 16;
  size_t count = 0;
  HistoryDmEntry *allEntries = calloc(capacity, sizeof(HistoryDmEntry));
  if (!allEntries) {
    closedir(d);
    return 0;
  }

  struct dirent *entry;
  while ((entry = readdir(d)) != NULL) {
    if (strncmp(entry->d_name, "dm_", 3) != 0)
      continue;

    size_t len = strlen(entry->d_name);
    if (len != 3 + TOKEN_HEX_LEN + 4 ||
        strcmp(entry->d_name + len - 4, ".log") != 0)
      continue;

    if (count == capacity) {
      size_t newCapacity = capacity * 2;
      HistoryDmEntry *grown =
          realloc(allEntries, newCapacity * sizeof(HistoryDmEntry));
      if (!grown)
        break;
      allEntries = grown;
      capacity = newCapacity;
    }

    size_t tokenLen = len - 3 - 4;
    memcpy(allEntries[count].token, entry->d_name + 3, tokenLen);
    allEntries[count].token[tokenLen] = '\0';
    bool validToken = true;
    for (size_t i = 0; i < tokenLen; i++) {
      if (!isxdigit((unsigned char)allEntries[count].token[i])) {
        validToken = false;
        break;
      }
    }
    if (!validToken)
      continue;

    char fullPath[1024 + NAME_MAX + 2];
    snprintf(fullPath, sizeof(fullPath), "%s/%s", dir, entry->d_name);
    struct stat st;
    allEntries[count].lastActive = (stat(fullPath, &st) == 0) ? st.st_mtime : 0;
    count++;
  }
  closedir(d);

  qsort(allEntries, count, sizeof(HistoryDmEntry), compareHistoryEntries);

  size_t copied = count < maxEntries ? count : maxEntries;
  for (size_t i = 0; i < copied; i++)
    entries[i] = allEntries[i];
  free(allEntries);
  return copied;
}
