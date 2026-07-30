#include "identity.h"

static void bytesToHex(const unsigned char *bytes, size_t len, char *out) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hex[bytes[i] >> 4];
    out[i * 2 + 1] = hex[bytes[i] & 0x0f];
  }
  out[len * 2] = '\0';
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static bool hexToBytes(const char *hex, size_t hexLen, unsigned char *out,
                       size_t outLen) {
  if (hexLen != outLen * 2)
    return false;
  for (size_t i = 0; i < outLen; i++) {
    int hi = hexNibble(hex[i * 2]);
    int lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return false;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return true;
}

static char *identityFilePath(void) {
  char dirPath[CONFIG_DIR_MAX];
  if (!platformGetConfigDir(dirPath, sizeof(dirPath))) {
    fprintf(stderr, "identity: cannot determine config directory\n");
    return NULL;
  }

  if (!platformEnsureDir(dirPath)) {
    perror("identity: mkdir config dir");
    return NULL;
  }

  char *path = malloc(IDENTITY_PATH_MAX);
  if (!path)
    return NULL;
  snprintf(path, IDENTITY_PATH_MAX, "%s%cidentity.key", dirPath,
           SOCKETCHAT_PATH_SEP);
  return path;
}

static char *usernameFilePath(void) {
  char dirPath[CONFIG_DIR_MAX];
  if (!platformGetConfigDir(dirPath, sizeof(dirPath)))
    return NULL;
  if (!platformEnsureDir(dirPath))
    return NULL;

  char *path = malloc(IDENTITY_PATH_MAX);
  if (!path)
    return NULL;
  snprintf(path, IDENTITY_PATH_MAX, "%s%cusername", dirPath,
           SOCKETCHAT_PATH_SEP);
  return path;
}

static int openPrivateFile(const char *path, int flags) {
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
  flags |= O_NONBLOCK;
#endif
  int fd = open(path, flags, 0600);
  if (fd < 0)
    return -1;
  if (!platformSecureUserFileFd(fd)) {
    platformCloseFd(fd);
    return -1;
  }
  return fd;
}

static bool safeStoredToken(const char *token) {
  if (!token || strlen(token) != TOKEN_HEX_LEN)
    return false;
  for (size_t i = 0; token[i]; i++) {
    if (!isxdigit((unsigned char)token[i]))
      return false;
  }
  return true;
}

static bool safeStoredName(const char *name, bool allowSpaces) {
  if (!name || !name[0] || strlen(name) >= MAX_NAME_LEN)
    return false;
  for (size_t i = 0; name[i]; i++) {
    unsigned char ch = (unsigned char)name[i];
    if (!(isalnum(ch) || ch == '-' || ch == '_' || ch == '.' ||
          (allowSpaces && (ch == ' ' || ch == '\'' || ch == '@'))))
      return false;
  }
  return true;
}

static bool deriveEd25519PublicKey(const unsigned char seed[IDENTITY_KEY_BYTES],
                                   unsigned char pub[IDENTITY_KEY_BYTES]) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed,
                                                IDENTITY_KEY_BYTES);
  if (!pkey)
    return false;

  size_t pubLen = IDENTITY_KEY_BYTES;
  int ok = EVP_PKEY_get_raw_public_key(pkey, pub, &pubLen);
  EVP_PKEY_free(pkey);
  return ok == 1 && pubLen == IDENTITY_KEY_BYTES;
}

bool identityLoadOrCreate(Identity *id) {
  memset(id, 0, sizeof(*id));

  char *path = identityFilePath();
  if (!path)
    return false;

  int readFd = openPrivateFile(path, O_RDONLY);
  struct stat keyStat;
  bool exactSize = readFd >= 0 && fstat(readFd, &keyStat) == 0 &&
                   keyStat.st_size == IDENTITY_KEY_BYTES;
  FILE *f = readFd >= 0 ? fdopen(readFd, "rb") : NULL;
  if (readFd >= 0 && !f)
    platformCloseFd(readFd);
  if (f) {
    size_t n = fread(id->priv, 1, IDENTITY_KEY_BYTES, f);
    bool validFile = exactSize && n == IDENTITY_KEY_BYTES && !ferror(f);
    fclose(f);
    if (validFile) {
      if (!deriveEd25519PublicKey(id->priv, id->pub)) {
        fprintf(stderr, "identity: failed to derive public key\n");
        free(path);
        return false;
      }
      bytesToHex(id->pub, IDENTITY_KEY_BYTES, id->token);
      free(path);
      return true;
    }
    fprintf(stderr, "identity: key file is invalid; refusing to replace it\n");
    free(path);
    return false;
  }

  if (RAND_bytes(id->priv, IDENTITY_KEY_BYTES) != 1) {
    fprintf(stderr, "identity: RAND_bytes failed\n");
    free(path);
    return false;
  }

  if (!deriveEd25519PublicKey(id->priv, id->pub)) {
    fprintf(stderr, "identity: failed to derive public key from new seed\n");
    free(path);
    return false;
  }

  int fd = openPrivateFile(path, O_WRONLY | O_CREAT | O_EXCL);
  if (fd < 0) {
    perror("identity: open identity.key for writing");
    free(path);
    return false;
  }
  size_t offset = 0;
  while (offset < IDENTITY_KEY_BYTES) {
    ssize_t written = write(fd, id->priv + offset, IDENTITY_KEY_BYTES - offset);
    if (written > 0) {
      offset += (size_t)written;
      continue;
    }
    if (written < 0 && errno == EINTR)
      continue;
    break;
  }
#ifndef _WIN32
  bool durable = offset == IDENTITY_KEY_BYTES && fsync(fd) == 0;
#else
  bool durable = offset == IDENTITY_KEY_BYTES;
#endif
  if (!durable)
    remove(path);
  platformCloseFd(fd);
  if (!durable) {
    fprintf(stderr, "identity: short write to identity.key\n");
    free(path);
    return false;
  }

  bytesToHex(id->pub, IDENTITY_KEY_BYTES, id->token);
  fprintf(stderr, "identity: new identity created — token: %s\n", id->token);
  free(path);
  return true;
}

bool identitySign(const Identity *id, const unsigned char *msg, size_t msgLen,
                  unsigned char sigOut[SIG_BYTES]) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                id->priv, IDENTITY_KEY_BYTES);
  if (!pkey)
    return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = false;
  size_t sigLen = SIG_BYTES;

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
      EVP_DigestSign(ctx, sigOut, &sigLen, msg, msgLen) == 1 &&
      sigLen == SIG_BYTES) {
    ok = true;
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

bool identityVerify(const char *pubHex, const unsigned char *msg, size_t msgLen,
                    const unsigned char sig[SIG_BYTES]) {
  if (!pubHex || strlen(pubHex) != TOKEN_HEX_LEN)
    return false;

  unsigned char pubBytes[IDENTITY_KEY_BYTES];
  if (!hexToBytes(pubHex, TOKEN_HEX_LEN, pubBytes, IDENTITY_KEY_BYTES))
    return false;

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubBytes,
                                               IDENTITY_KEY_BYTES);
  if (!pkey)
    return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  void *sigVoid = (void *)sig;
  int rc = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
  if (rc == 1)
    rc = EVP_DigestVerify(ctx, (const unsigned char *)sigVoid, SIG_BYTES, msg,
                          msgLen);

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return rc == 1;
}

void identityPrintToken(const Identity *id) {
  printf("Your token: %s\n", id->token);
}

bool identityLoadUsername(char *username, size_t maxLen) {
  char *path = usernameFilePath();
  if (!path)
    return false;

  int fd = openPrivateFile(path, O_RDONLY);
  FILE *f = fd >= 0 ? fdopen(fd, "r") : NULL;
  if (fd >= 0 && !f)
    platformCloseFd(fd);
  if (!f) {
    free(path);
    return false;
  }

  int readSize = (maxLen > (size_t)INT_MAX) ? INT_MAX : (int)maxLen;
  if (fgets(username, readSize, f)) {
    size_t len = strlen(username);
    while (len > 0 &&
           (username[len - 1] == '\n' || username[len - 1] == '\r')) {
      username[--len] = '\0';
    }
    fclose(f);
    free(path);
    return safeStoredName(username, false);
  }
  fclose(f);
  free(path);
  return false;
}

bool identitySaveUsername(const char *username) {
  if (!safeStoredName(username, false))
    return false;
  char *path = usernameFilePath();
  if (!path)
    return false;

  int fd = openPrivateFile(path, O_WRONLY | O_CREAT | O_TRUNC);
  FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
  if (fd >= 0 && !f)
    platformCloseFd(fd);
  if (!f) {
    free(path);
    return false;
  }

  fprintf(f, "%s\n", username);
  fclose(f);
  free(path);
  return true;
}

size_t identityLoadDmNickEntries(DmNickEntry *entries, size_t maxEntries) {
  if (!entries || maxEntries == 0)
    return 0;

  char dirPath[CONFIG_DIR_MAX];
  if (!platformGetConfigDir(dirPath, sizeof(dirPath)))
    return 0;

  char path[IDENTITY_PATH_MAX];
  snprintf(path, sizeof(path), "%s%cdm_nicks.tsv", dirPath,
           SOCKETCHAT_PATH_SEP);

  int fd = openPrivateFile(path, O_RDONLY);
  FILE *f = fd >= 0 ? fdopen(fd, "r") : NULL;
  if (fd >= 0 && !f)
    platformCloseFd(fd);
  if (!f)
    return 0;

  size_t count = 0;
  char line[256];
  while (fgets(line, sizeof(line), f) && count < maxEntries) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';
    if (len == 0)
      continue;

    char *tab = strchr(line, '\t');
    if (!tab)
      continue;
    *tab++ = '\0';

    if (!safeStoredToken(line) || !safeStoredName(tab, true))
      continue;

    snprintf(entries[count].token, sizeof(entries[count].token), "%s", line);
    snprintf(entries[count].nick, sizeof(entries[count].nick), "%s", tab);
    count++;
  }

  fclose(f);
  return count;
}

bool identitySaveDmNickEntries(const DmNickEntry *entries, size_t count) {
  if (!entries)
    return false;

  char dirPath[CONFIG_DIR_MAX];
  if (!platformGetConfigDir(dirPath, sizeof(dirPath)))
    return false;
  if (!platformEnsureDir(dirPath))
    return false;

  char path[IDENTITY_PATH_MAX];
  snprintf(path, sizeof(path), "%s%cdm_nicks.tsv", dirPath,
           SOCKETCHAT_PATH_SEP);

  int fd = openPrivateFile(path, O_WRONLY | O_CREAT | O_TRUNC);
  FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
  if (fd >= 0 && !f)
    platformCloseFd(fd);
  if (!f)
    return false;

  for (size_t i = 0; i < count; i++) {
    if (safeStoredToken(entries[i].token) &&
        safeStoredName(entries[i].nick, true))
      fprintf(f, "%s\t%s\n", entries[i].token, entries[i].nick);
  }

  fclose(f);
  return true;
}
