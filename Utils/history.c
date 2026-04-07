#include "history.h"
#include "identity.h"

#define MAX_LINE 2048

static const char *homeDir(void) {
  const char *h = getenv("HOME");
  if (h)
    return h;
  struct passwd *pw = getpwuid(getuid());
  return pw ? pw->pw_dir : NULL;
}

static bool historyPath(const char *peerToken, char *out, size_t outSize) {
  const char *home = homeDir();
  if (!home)
    return false;
  snprintf(out, outSize, "%s/.socketchat/dm_%.64s.log", home, peerToken);
  return true;
}

static bool ensureDir(void) {
  const char *home = homeDir();
  if (!home)
    return false;
  char dir[512];
  snprintf(dir, sizeof(dir), "%s/.socketchat", home);
  if (mkdir(dir, 0700) != 0 && errno != EEXIST)
    return false;
  return true;
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

static void printUnescaped(const char *line) {
  for (size_t i = 0; line[i]; i++) {
    if (line[i] == '\\' && line[i + 1] == 'n') {
      putchar('\n');
      i++;
    } else {
      putchar(line[i]);
    }
  }
}

bool historyAppend(const char *peerToken, bool sent, const char *message) {
  if (!ensureDir())
    return false;

  char path[512];
  if (!historyPath(peerToken, path, sizeof(path)))
    return false;

  FILE *f = fopen(path, "a");
  if (!f)
    return false;

  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  char ts[32] = "0000-00-00T00:00:00";
  if (tm_info)
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

  char escaped[MAX_LINE];
  escapeNewlines(message, escaped, sizeof(escaped));

  fprintf(f, "%s %s %s\n", ts, sent ? ">>>" : "<<<", escaped);
  fclose(f);
  return true;
}

void historyPrint(const char *peerToken, size_t count) {
  char path[512];
  if (!historyPath(peerToken, path, sizeof(path)))
    return;

  FILE *f = fopen(path, "r");
  if (!f) {
    printf("  (no history)\n");
    return;
  }

  if (count == 0) {

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {

      size_t len = strlen(line);
      if (len > 0 && line[len - 1] == '\n')
        line[len - 1] = '\0';
      printUnescaped(line);
      putchar('\n');
    }
  } else {

    char **ring = calloc(count, sizeof(char *));
    if (!ring) {
      fclose(f);
      return;
    }

    size_t idx = 0, total = 0;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
      size_t len = strlen(line);
      if (len > 0 && line[len - 1] == '\n')
        line[len - 1] = '\0';
      free(ring[idx % count]);
      ring[idx % count] = strdup(line);
      idx++;
      total++;
    }

    size_t start = (total > count) ? idx % count : 0;
    size_t n = (total < count) ? total : count;
    for (size_t i = 0; i < n; i++) {
      char *l = ring[(start + i) % count];
      if (l) {
        printUnescaped(l);
        putchar('\n');
      }
    }

    for (size_t i = 0; i < count; i++)
      free(ring[i]);
    free(ring);
  }

  fclose(f);
}

bool historyExists(const char *peerToken) {
  char path[512];
  if (!historyPath(peerToken, path, sizeof(path)))
    return false;
  struct stat st;
  return stat(path, &st) == 0 && st.st_size > 0;
}

void historyListAll(void) {
  const char *home = homeDir();
  if (!home) {
    printf("  (cannot read home directory)\n");
    return;
  }

  char dir[1024];
  snprintf(dir, sizeof(dir), "%s/.socketchat", home);

  DIR *d = opendir(dir);
  if (!d) {
    printf("  (no chat history found)\n");
    return;
  }

  int found = 0;
  struct dirent *entry;
  while ((entry = readdir(d)) != NULL) {

    if (strncmp(entry->d_name, "dm_", 3) != 0)
      continue;
    size_t len = strlen(entry->d_name);
    if (len < 8)
      continue;
    if (strcmp(entry->d_name + len - 4, ".log") != 0)
      continue;

    size_t tokenLen = len - 3 - 4;
    char token[TOKEN_STR_SIZE + 1];
    if (tokenLen > TOKEN_STR_SIZE)
      tokenLen = TOKEN_STR_SIZE;
    memcpy(token, entry->d_name + 3, tokenLen);
    token[tokenLen] = '\0';

    char fullPath[1024 + NAME_MAX + 2];
    snprintf(fullPath, sizeof(fullPath), "%s/%s", dir, entry->d_name);
    struct stat st;
    char timeStr[32] = "unknown";
    if (stat(fullPath, &st) == 0) {
      struct tm *tm = localtime(&st.st_mtime);
      strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M", tm);
    }
    printf("  %s  (last active: %s)\n", token, timeStr);
    found++;
  }
  closedir(d);

  if (found == 0)
    printf("  (no DM history found)\n");
}
