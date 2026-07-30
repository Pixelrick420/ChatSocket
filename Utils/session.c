#include "session.h"

static uint64_t g_sessionCount = 0;
static char g_counterPath[1024] = {0};
static pthread_mutex_t g_counterMutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_initialized = false;

bool sessionCounterInit(const char *counterFilePath) {
  if (!counterFilePath || !counterFilePath[0]) {
    fprintf(stderr, "sessionCounter: Invalid file path\n");
    return false;
  }

  pthread_mutex_lock(&g_counterMutex);

  strncpy(g_counterPath, counterFilePath, sizeof(g_counterPath) - 1);
  g_counterPath[sizeof(g_counterPath) - 1] = '\0';

  FILE *file = fopen(g_counterPath, "rb");
  if (file) {

    if (fread(&g_sessionCount, sizeof(g_sessionCount), 1, file) != 1) {
      fprintf(stderr,
              "sessionCounter: Failed to read counter file, starting at 0\n");
      g_sessionCount = 0;
    }
    fclose(file);
  } else {

    g_sessionCount = 0;
    file = fopen(g_counterPath, "wb");
    if (file) {
      if (fwrite(&g_sessionCount, sizeof(g_sessionCount), 1, file) != 1) {
        fprintf(stderr,
                "sessionCounter: Failed to write initial counter file\n");
        pthread_mutex_unlock(&g_counterMutex);
        return false;
      }
      fclose(file);
    } else {
      fprintf(stderr, "sessionCounter: Cannot create counter file: %s\n",
              strerror(errno));
      pthread_mutex_unlock(&g_counterMutex);
      return false;
    }
  }

  g_initialized = true;
  pthread_mutex_unlock(&g_counterMutex);

  printf("Session counter initialized: %lu total sessions\n",
         (unsigned long)g_sessionCount);
  return true;
}

uint64_t sessionCounterIncrement(void) {
  if (!g_initialized) {
    fprintf(stderr, "sessionCounter: Not initialized\n");
    return 0;
  }

  pthread_mutex_lock(&g_counterMutex);

  g_sessionCount++;
  uint64_t newCount = g_sessionCount;

  char tempPath[1100];
  snprintf(tempPath, sizeof(tempPath), "%s.tmp", g_counterPath);

  FILE *file = fopen(tempPath, "wb");
  if (!file) {
    fprintf(stderr, "sessionCounter: Failed to create temp file: %s\n",
            strerror(errno));
    pthread_mutex_unlock(&g_counterMutex);
    return newCount;
  }

  if (fwrite(&newCount, sizeof(newCount), 1, file) != 1) {
    fprintf(stderr, "sessionCounter: Failed to write counter: %s\n",
            strerror(errno));
    fclose(file);
    unlink(tempPath);
    pthread_mutex_unlock(&g_counterMutex);
    return newCount;
  }

  fclose(file);

  if (rename(tempPath, g_counterPath) != 0) {
    fprintf(stderr, "sessionCounter: Failed to rename temp file: %s\n",
            strerror(errno));
    unlink(tempPath);
  }

  pthread_mutex_unlock(&g_counterMutex);
  return newCount;
}

uint64_t sessionCounterGet(void) {
  if (!g_initialized) {
    return 0;
  }

  pthread_mutex_lock(&g_counterMutex);
  uint64_t count = g_sessionCount;
  pthread_mutex_unlock(&g_counterMutex);

  return count;
}

void sessionCounterCleanup(void) {
  pthread_mutex_lock(&g_counterMutex);
  g_initialized = false;
  g_counterPath[0] = '\0';
  pthread_mutex_unlock(&g_counterMutex);
  pthread_mutex_destroy(&g_counterMutex);
}
