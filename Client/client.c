#include "../Utils/aes.h"
#include "../Utils/ecdh.h"
#include "../Utils/history.h"
#include "../Utils/identity.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 2077

static FILE *g_logFile = NULL;
static char g_logPath[256] = {0};

static void logOpen(void) {
  const char *home = getenv("HOME");
  if (!home)
    return;
  pid_t pid = getpid();
  snprintf(g_logPath, sizeof(g_logPath), "%s/.socketchat/client_%d.log", home, pid);
  g_logFile = fopen(g_logPath, "a");
  if (!g_logFile) {
    perror("log: fopen");
    return;
  }
  setvbuf(g_logFile, NULL, _IOLBF, 0);
}

static void clientLog(const char *fmt, ...) {
  if (!g_logFile)
    return;
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char ts[32] = "?";
  if (t)
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", t);
  fprintf(g_logFile, "[%s] ", ts);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(g_logFile, fmt, ap);
  va_end(ap);
  if (fmt[strlen(fmt) - 1] != '\n')
    fputc('\n', g_logFile);
}

static int g_socketFD = -1;
static SSL *g_ssl = NULL;
static Identity g_identity = {0};

static RoomEncryption g_encryption = {0};
static char g_currentRoom[MAX_NAME_LEN] = {0};
static bool g_inRoom = false;

static struct {
  char roomName[MAX_NAME_LEN];
  unsigned char key[32];
  bool hasKey;
  bool pending;
} g_pendingRoom = {0};

typedef struct {
  bool active;
  char peerToken[TOKEN_STR_SIZE];
  unsigned char key[32];
  bool pending;
  unsigned char pendingKey[32];
  char pendingToken[TOKEN_STR_SIZE];
} DmSession;
static DmSession g_dm = {0};

static struct termios g_origTermios;
static bool g_readingPassword = false;
static char g_passwordBuffer[MSG_SIZE] = {0};
static size_t g_passwordLen = 0;
static bool g_waitingForRoomJoin = false;
static bool g_expectServerResponse = false;  // true when we sent a msg that will get echoed back

typedef struct {
  char buffer[MSG_SIZE];
  size_t length;
  pthread_mutex_t mutex;
  bool connected;
} InputState;

static InputState g_input = {
    .buffer = {0},
    .length = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .connected = true,
};

static bool sendToServer(const char *message);
static void printPrompt(void);

static void disableRawMode(void) {
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_origTermios);
}

static void enableRawMode(void) {
  struct termios raw;
  tcgetattr(STDIN_FILENO, &raw);
  raw.c_lflag &= ~(ICANON | ECHO);
  raw.c_cc[VMIN] = 1;
  raw.c_cc[VTIME] = 0;
  tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

static void clearScreen(void) { print("\033[2J\033[H"); }
static void eraseInputLine(void) { print("\r\033[K"); }

static void redrawInputLine(void) {
  printPrompt();
}

static void printPrompt(void) {
  pthread_mutex_lock(&g_input.mutex);
  if (g_dm.active) {
    char shortToken[17];
    snprintf(shortToken, sizeof(shortToken), "%.16s", g_dm.peerToken);
    printf(COLOR_GREEN "[DM:%.8s...]> " COLOR_RESET "%s", shortToken, g_input.buffer);
  } else if (g_inRoom) {
    printf(COLOR_GREEN "[#%.14s]> " COLOR_RESET "%s", g_currentRoom, g_input.buffer);
  } else {
    printf(COLOR_GREEN ">>> " COLOR_RESET "%s", g_input.buffer);
  }
  fflush(stdout);
  pthread_mutex_unlock(&g_input.mutex);
}

static void printMessage(const char *color, const char *prefix,
                         const char *message) {
  char formatted[MSG_SIZE * 2];
  snprintf(formatted, sizeof(formatted), "%s%s%s%s", color, prefix, message,
           COLOR_RESET);
  print(formatted);
}

static void commitRoomEntry(void) {
  clientLog("commitRoomEntry: entering room '%s' hasKey=%d",
            g_pendingRoom.roomName, g_pendingRoom.hasKey);
  memset(&g_encryption, 0, sizeof(g_encryption));
  g_inRoom = false;
  snprintf(g_currentRoom, sizeof(g_currentRoom), "%s", g_pendingRoom.roomName);
  g_inRoom = true;
  if (g_pendingRoom.hasKey) {
    memcpy(g_encryption.key, g_pendingRoom.key, 32);
    snprintf(g_encryption.roomName, sizeof(g_encryption.roomName), "%s",
             g_pendingRoom.roomName);
    g_encryption.hasKey = true;
  }
  memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
}

static void clearRoomState(void) {
  clientLog("clearRoomState: leaving room '%s'", g_currentRoom);
  memset(&g_encryption, 0, sizeof(g_encryption));
  memset(g_currentRoom, 0, sizeof(g_currentRoom));
  g_inRoom = false;
  memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
}

static void clearDmSession(void) {
  clientLog("clearDmSession");
  memset(&g_dm, 0, sizeof(g_dm));
}

static bool encryptAndSendDm(const char *message, size_t msgLen) {
  unsigned char ciphertext[MSG_SIZE];
  int ciphertextLen = encryptMessage((const unsigned char *)message, msgLen,
                                     g_dm.key, ciphertext);
  if (ciphertextLen <= 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to encrypt DM\n");
    return false;
  }
  char encoded[MSG_SIZE * 2];
  encodeBase64(ciphertext, (size_t)ciphertextLen, encoded);
  char toSend[MSG_SIZE * 2 + TOKEN_STR_SIZE + 16];
  snprintf(toSend, sizeof(toSend), "DM:%s:ENC:%s\n", g_dm.peerToken, encoded);
  return sendToServer(toSend);
}

static bool decryptAndDisplayDm(const char *encryptedData) {
  unsigned char decoded[MSG_SIZE];
  int decodedLen = decodeBase64(encryptedData, decoded);
  if (decodedLen <= 0)
    return false;
  unsigned char decrypted[MSG_SIZE];
  int decryptedLen =
      decryptMessage(decoded, (size_t)decodedLen, g_dm.key, decrypted);
  if (decryptedLen <= 0)
    return false;
  decrypted[decryptedLen] = '\0';

  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  char ts[16] = "00:00";
  if (tm_info)
    strftime(ts, sizeof(ts), "%H:%M", tm_info);

  char formatted[MSG_SIZE * 2];
  snprintf(formatted, sizeof(formatted), "%s[%s] %s%s\n", COLOR_CYAN,
           ts, (char *)decrypted, COLOR_RESET);
  print(formatted);
  historyAppend(g_dm.peerToken, false, (char *)decrypted);
  return true;
}

static bool encryptAndSendRoom(const char *message, size_t msgLen) {
  unsigned char ciphertext[MSG_SIZE];
  int ciphertextLen = encryptMessage((const unsigned char *)message, msgLen,
                                     g_encryption.key, ciphertext);
  if (ciphertextLen <= 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to encrypt message\n");
    return false;
  }
  char encoded[MSG_SIZE * 2];
  encodeBase64(ciphertext, (size_t)ciphertextLen, encoded);
  char toSend[MSG_SIZE * 2 + 10];
  snprintf(toSend, sizeof(toSend), "ENC:%s\n", encoded);
  return sendToServer(toSend);
}

static bool decryptAndDisplayRoom(const char *encryptedData,
                                   const char *username) {
  unsigned char decoded[MSG_SIZE];
  int decodedLen = decodeBase64(encryptedData, decoded);
  if (decodedLen <= 0)
    return false;
  unsigned char decrypted[MSG_SIZE];
  int decryptedLen =
      decryptMessage(decoded, (size_t)decodedLen, g_encryption.key, decrypted);
  if (decryptedLen <= 0)
    return false;
  decrypted[decryptedLen] = '\0';

  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  char ts[16] = "00:00";
  if (tm_info)
    strftime(ts, sizeof(ts), "%H:%M", tm_info);

  char formatted[MSG_SIZE * 2];
  if (username[0])
    snprintf(formatted, sizeof(formatted), "%s[%s] %s: %s%s\n", COLOR_CYAN,
             ts, username, decrypted, COLOR_RESET);
  else
    snprintf(formatted, sizeof(formatted), "%s[%s] %s%s\n", COLOR_CYAN, ts,
             decrypted, COLOR_RESET);
  print(formatted);
  return true;
}

static void handleIncomingDm(const char *frame) {
  const char *p = frame + 3;
  if (strlen(p) < TOKEN_HEX_LEN + 1)
    return;
  char senderToken[TOKEN_STR_SIZE];
  memcpy(senderToken, p, TOKEN_HEX_LEN);
  senderToken[TOKEN_HEX_LEN] = '\0';
  const char *payload = p + TOKEN_HEX_LEN + 1;

  if (strncmp(payload, "DM_REQ:", 7) == 0) {
    const char *peerPubHex = payload + 7;
    char trimmed[TOKEN_STR_SIZE];
    snprintf(trimmed, sizeof(trimmed), "%.*s", TOKEN_HEX_LEN, peerPubHex);
    unsigned char peerPubX25519[32];
    if (!tokenToX25519PublicKey(trimmed, peerPubX25519)) {
      printMessage(COLOR_RED, "[!] ", "DM_REQ: bad sender public key\n");
      return;
    }
    unsigned char myPrivX25519[32];
    if (!identityEd25519PrivToX25519(g_identity.priv, myPrivX25519)) {
      printMessage(COLOR_RED, "[!] ", "DM_REQ: key conversion failed\n");
      return;
    }
    unsigned char sharedKey[32];
    bool ecdhOk = ecdhDeriveKey(myPrivX25519, peerPubX25519, sharedKey);
    memset(myPrivX25519, 0, sizeof(myPrivX25519));
    if (!ecdhOk) {
      printMessage(COLOR_RED, "[!] ", "DM_REQ: ECDH failed\n");
      return;
    }
    g_dm.pending = true;
    snprintf(g_dm.pendingToken, sizeof(g_dm.pendingToken), "%s", senderToken);
    memcpy(g_dm.pendingKey, sharedKey, 32);
    char shortToken[17];
    snprintf(shortToken, sizeof(shortToken), "%.16s", senderToken);
    char notifyMsg[MSG_SIZE];
    if (historyExists(senderToken))
      snprintf(notifyMsg, sizeof(notifyMsg),
              "[*] DM from %.16s... (use /dm %.64s to reply)\n",
              shortToken, senderToken);
    else
      snprintf(notifyMsg, sizeof(notifyMsg),
              "[*] DM from %.16s... (use /dm %.64s to reply)\n",
              shortToken, senderToken);
    printMessage(COLOR_YELLOW, "", notifyMsg);
    redrawInputLine();
    return;
  }

  if (strncmp(payload, "ENC:", 4) == 0) {
    if (g_dm.active &&
        strncmp(g_dm.peerToken, senderToken, TOKEN_HEX_LEN) == 0) {
      eraseInputLine();
      if (!decryptAndDisplayDm(payload + 4))
        printMessage(COLOR_RED, "[!] ", "Failed to decrypt DM\n");
      redrawInputLine();
      return;
    }
    if (g_dm.pending &&
        strncmp(g_dm.pendingToken, senderToken, TOKEN_HEX_LEN) == 0) {
      g_dm.active = true;
      g_dm.pending = false;
      snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", g_dm.pendingToken);
      memcpy(g_dm.key, g_dm.pendingKey, 32);
      memset(g_dm.pendingKey, 0, sizeof(g_dm.pendingKey));
      eraseInputLine();
      printMessage(COLOR_YELLOW, "", "[*] DM session resumed\n");
      if (!decryptAndDisplayDm(payload + 4))
        printMessage(COLOR_RED, "[!] ", "Failed to decrypt DM\n");
      redrawInputLine();
      return;
    }
    eraseInputLine();
    printMessage(COLOR_RED, "", "[!] Encrypted DM from unknown session\n");
    redrawInputLine();
    return;
  }
}

static bool handleRoomResponse(const char *text) {
  if (g_pendingRoom.pending) {
    pthread_mutex_lock(&g_input.mutex);
    g_waitingForRoomJoin = false;
    pthread_mutex_unlock(&g_input.mutex);

    if (strncmp(text, "Entered room '", 14) == 0) {
      commitRoomEntry();
      g_expectServerResponse = false;
      return true;
    }
    if (strncmp(text, "Left room", 9) == 0) {
      clearRoomState();
      g_expectServerResponse = false;
      return true;
    }
    if (strncmp(text, "Incorrect password", 18) == 0 ||
        strncmp(text, "Room '", 6) == 0) {

      memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
      g_expectServerResponse = false;
      return false;
    }
  }

  if (strncmp(text, "Room '", 6) == 0 && strstr(text, "' created") != NULL) {
    g_expectServerResponse = false;
    return true;
  }

  return false;
}

static void finalizePasswordEntry(void) {
  printf("\n");
  fflush(stdout);

  char passwordHash[SHA256_HEX_SIZE];
  sha256Hex(g_passwordBuffer, g_passwordLen, passwordHash);

  char toSend[MSG_SIZE];
  memcpy(toSend, passwordHash, SHA256_HEX_SIZE - 1);
  toSend[SHA256_HEX_SIZE - 1] = '\n';
  toSend[SHA256_HEX_SIZE] = '\0';
  clientLog("Sending hashed password to server for room '%s'",
            g_pendingRoom.roomName);
  sendToServer(toSend);

  if (g_passwordLen > 0) {
    deriveKeyFromPassword(g_passwordBuffer, g_pendingRoom.key);
    g_pendingRoom.hasKey = true;
  } else {
    memset(g_pendingRoom.key, 0, 32);
    g_pendingRoom.hasKey = false;
  }

  memset(g_passwordBuffer, 0, sizeof(g_passwordBuffer));
  memset(passwordHash, 0, sizeof(passwordHash));
  g_passwordLen = 0;
  pthread_mutex_lock(&g_input.mutex);
  g_readingPassword = false;
  pthread_mutex_unlock(&g_input.mutex);

  pthread_mutex_lock(&g_input.mutex);
  g_input.buffer[0] = '\0';
  g_input.length = 0;
  pthread_mutex_unlock(&g_input.mutex);
  printPrompt();
}

static void displayIncomingMessage(char *buffer) {
  bool isMsg = (buffer[0] == 'M' && buffer[1] == 'S' && buffer[2] == 'G');
  bool isErr = (buffer[0] == 'E' && buffer[1] == 'R' && buffer[2] == 'R');
  bool isRes = (buffer[0] == 'R' && buffer[1] == 'E' && buffer[2] == 'S');
  bool isPas = (buffer[0] == 'P' && buffer[1] == 'A' && buffer[2] == 'S');
  bool isDm = (buffer[0] == 'D' && buffer[1] == 'M' && buffer[2] == ':');

clientLog("recv: %.80s", buffer);
  eraseInputLine();
  pthread_mutex_lock(&g_input.mutex);
  g_input.buffer[0] = '\0';
  g_input.length = 0;
  pthread_mutex_unlock(&g_input.mutex);

  if (isDm) {
    handleIncomingDm(buffer);
    return;
  }

  if (isMsg) {
    const char *payload = buffer + 3;
    char username[64] = {0};
    const char *messageStart = payload;
    const char *colon = strchr(payload, ':');
    if (colon && colon != payload) {
      size_t ulen = (size_t)(colon - payload);
      if (ulen < sizeof(username)) {
        memcpy(username, payload, ulen);
        username[ulen] = '\0';
        messageStart = colon + 2;
      }
    }
    if (isEncryptedMessage(messageStart) && g_encryption.hasKey) {
      if (!decryptAndDisplayRoom(messageStart + 4, username))
        printMessage(COLOR_RED, "[!] ", "Failed to decrypt message\n");
    } else if (isEncryptedMessage(messageStart) && !g_encryption.hasKey) {
      printMessage(COLOR_RED, "",
                   "[!] Encrypted message (not in encrypted room)\n");
    } else {
      char text[MSG_SIZE];
      snprintf(text, sizeof(text), "%s", messageStart);
      size_t tlen = strlen(text);
      while (tlen > 0 && (text[tlen - 1] == '\n' || text[tlen - 1] == '\r'))
        text[--tlen] = '\0';

      time_t now = time(NULL);
      struct tm *tm_info = localtime(&now);
      char ts[16] = "00:00";
      if (tm_info)
        strftime(ts, sizeof(ts), "%H:%M", tm_info);

      char formatted[MSG_SIZE * 2];
      if (username[0])
        snprintf(formatted, sizeof(formatted), "%s[%s] %s: %s%s\n", COLOR_CYAN,
                 ts, username, text, COLOR_RESET);
      else
        snprintf(formatted, sizeof(formatted), "%s[%s] %s%s\n", COLOR_CYAN, ts,
                 text, COLOR_RESET);
      print(formatted);
    }
  } else if (isErr) {
    printMessage(COLOR_RED, "[!] ", buffer + 3);
  } else if (isRes) {
    const char *text = buffer + 3;
    bool success = handleRoomResponse(text);
    printMessage(COLOR_YELLOW, "[*] ", text);
    if (success)
      printPrompt();
    else
      printPrompt();
  } else if (isPas) {
    pthread_mutex_lock(&g_input.mutex);
    g_readingPassword = true;
    memset(g_passwordBuffer, 0, sizeof(g_passwordBuffer));
    g_passwordLen = 0;
    g_waitingForRoomJoin = false;
    pthread_mutex_unlock(&g_input.mutex);
    printf("\n");
    fflush(stdout);
    printf(COLOR_YELLOW "%s" COLOR_RESET, buffer + 3);
    fflush(stdout);
    return;
  } else {
    printMessage(COLOR_RED, "[!] ", "Unknown message from server\n");
  }
}

static void handleDisconnect(void) {
  pthread_mutex_lock(&g_input.mutex);
  g_input.connected = false;
  pthread_mutex_unlock(&g_input.mutex);
  eraseInputLine();
  printMessage(COLOR_RED, "\n[!] ", "Disconnected from server\n");
  printMessage(COLOR_YELLOW, "[*] ", "Press Enter to exit.\n");
  fflush(stdout);
  close(g_socketFD);
}

static void *receiveThread(void *arg) {
  (void)arg;
  char buffer[MSG_SIZE];
  while (true) {
    ssize_t received = tlsRecv(g_ssl, buffer, MSG_SIZE);
    if (received <= 0) {
      handleDisconnect();
      break;
    }
    buffer[received] = '\0';
    displayIncomingMessage(buffer);
  }
  return NULL;
}

static bool sendToServer(const char *message) {
  pthread_mutex_lock(&g_input.mutex);
  bool connected = g_input.connected;
  pthread_mutex_unlock(&g_input.mutex);
  if (!connected) {
    printMessage(COLOR_RED, "[!] ", "Not connected\n");
    return false;
  }
  size_t len = strlen(message);
  if (len >= MSG_SIZE) {
    printMessage(COLOR_RED, "[!] ", "Message too long\n");
    return false;
  }
  clientLog("send: %.120s", message);
  if (!tlsSend(g_ssl, message, len)) {
    handleDisconnect();
    return false;
  }
  return true;
}

static void handleLeaveCommand(void) {
  clearRoomState();
  sendToServer("/leave\n");
}

static void handleTokenCommand(void) {
  char msg[MSG_SIZE];
  snprintf(msg, sizeof(msg), COLOR_YELLOW "[*] Your token: %s\n" COLOR_RESET,
           g_identity.token);
  print(msg);
}

static void handleListCommand(void) {
  print(COLOR_YELLOW "[*] DM conversations:\n");
  historyListAll();
  print(COLOR_RESET);
}

static void handleDmCommand(const char *token) {
  if (strlen(token) != TOKEN_HEX_LEN) {
    printMessage(COLOR_RED, "[!] ", "Invalid token (64 hex chars)\n");
    return;
  }
  unsigned char peerPubX25519[32];
  if (!tokenToX25519PublicKey(token, peerPubX25519)) {
    printMessage(COLOR_RED, "[!] ", "Token contains invalid hex\n");
    return;
  }
  unsigned char myPrivX25519[32];
  if (!identityEd25519PrivToX25519(g_identity.priv, myPrivX25519)) {
    printMessage(COLOR_RED, "[!] ", "Key conversion failed\n");
    return;
  }
  unsigned char sharedKey[32];
  bool ecdhOk = ecdhDeriveKey(myPrivX25519, peerPubX25519, sharedKey);
  memset(myPrivX25519, 0, sizeof(myPrivX25519));
  if (!ecdhOk) {
    printMessage(COLOR_RED, "[!] ", "ECDH failed\n");
    return;
  }
  bool hasHistory = historyExists(token);
  if (hasHistory) {
    char msg[MSG_SIZE];
    snprintf(msg, sizeof(msg),
             COLOR_YELLOW "[*] " COLOR_RESET "History with %.16s...:\n", token);
    print(msg);
    disableRawMode();
    historyPrint(token, 0);
    enableRawMode();
    print("\n");
  }
  clearDmSession();
  g_dm.active = true;
  snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", token);
  memcpy(g_dm.key, sharedKey, 32);
  char dmReq[MSG_SIZE];
  snprintf(dmReq, sizeof(dmReq), "DM:%s:DM_REQ:%s\n", token, g_identity.token);
  sendToServer(dmReq);
  char msg[MSG_SIZE];
  snprintf(msg, sizeof(msg),
           COLOR_YELLOW "[*] " COLOR_RESET
                        "DM session opened with %.16s...%s\n",
           token, hasHistory ? " (continuing)" : "");
  print(msg);
}

static void handleDmLeaveCommand(void) {
  if (!g_dm.active) {
    printMessage(COLOR_YELLOW, "[*] ", "Not in a DM session\n");
    return;
  }
  clearDmSession();
  printMessage(COLOR_YELLOW, "[*] ", "DM session closed\n");
}

static bool processInput(char *message, size_t msgLen) {
  if (msgLen == 0)
    return true;

  clientLog("processInput: '%s'", message);

  // Room commands work even when not in a room
  if (strcmp(message, "/exit") == 0) {
    sendToServer("/exit\n");
    return false;
  }
  if (strncmp(message, "/create ", 8) == 0) {
    if (g_dm.active) {
      clearDmSession();
      printMessage(COLOR_YELLOW, "[*] ", "DM session closed (creating room)\n");
      printPrompt();
    }
    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
    g_expectServerResponse = true;
    return true;
  }
  if (strncmp(message, "/enter ", 7) == 0) {
    if (g_dm.active) {
      clearDmSession();
      printMessage(COLOR_YELLOW, "[*] ", "DM session closed (entering room)\n");
      printPrompt();
    }
    char roomName[MAX_NAME_LEN] = {0};
    sscanf(message + 7, "%63s", roomName);
    memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
    snprintf(g_pendingRoom.roomName, sizeof(g_pendingRoom.roomName), "%s", roomName);
    g_pendingRoom.pending = true;
    pthread_mutex_lock(&g_input.mutex);
    g_waitingForRoomJoin = true;
    pthread_mutex_unlock(&g_input.mutex);
    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
    g_expectServerResponse = true;
    return true;
  }
  if (strcmp(message, "/leave") == 0) {
    handleLeaveCommand();
    g_expectServerResponse = true;
    return true;
  }
  if (strcmp(message, "/rooms") == 0) {
    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
    g_expectServerResponse = true;
    return true;
  }
  if (strcmp(message, "/help") == 0) {
    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
    g_expectServerResponse = true;
    return true;
  }
  if (strcmp(message, "/clear") == 0) {
    eraseInputLine();
    clearScreen();
    print("SocketChat CLI (E2E Encrypted, TLS)\n");
    printf("Your token:   " COLOR_GREEN "%s\n\n" COLOR_RESET, g_identity.token);
    pthread_mutex_lock(&g_input.mutex);
    g_input.buffer[0] = '\0';
    g_input.length = 0;
    pthread_mutex_unlock(&g_input.mutex);
    return true;
  }
  if (strcmp(message, "/token") == 0) {
    eraseInputLine();
    handleTokenCommand();
    return true;
  }
  if (strcmp(message, "/list") == 0) {
    eraseInputLine();
    handleListCommand();
    return true;
  }
  if (strcmp(message, "/leave") == 0) {
    handleLeaveCommand();
    return true;
  }
  if (strcmp(message, "/dmleave") == 0) {
    eraseInputLine();
    handleDmLeaveCommand();
    return true;
  }
  if (strncmp(message, "/dm ", 4) == 0) {
    char token[TOKEN_STR_SIZE] = {0};
    sscanf(message + 4, "%64s", token);
    handleDmCommand(token);
    return true;
  }

  // ---------- DM ACTIVE CASE ----------
  if (g_dm.active) {
    // Allow certain commands even in DM
    if (message[0] == '/') {
      char toSend[MSG_SIZE];
      snprintf(toSend, sizeof(toSend), "%s\n", message);
      sendToServer(toSend);
      return true;
    }
    if (!encryptAndSendDm(message, msgLen))
      return true;
    historyAppend(g_dm.peerToken, true, message);
    g_expectServerResponse = true;
    return true;
  }

  if (!g_inRoom) {
    printMessage(COLOR_YELLOW, "[*] ", "Not in a room – use /enter <room>\n");
    return true;
  }

  if (g_encryption.hasKey)
    encryptAndSendRoom(message, msgLen);
  else {
    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
  }

  g_expectServerResponse = true;
  return true;
}

static void inputLoop(void) {
  char normalBuf[MSG_SIZE] = {0};
  size_t normalLen = 0;
  printPrompt();

  while (true) {
    pthread_mutex_lock(&g_input.mutex);
    bool connected = g_input.connected;
    bool waitingForRoomJoin = g_waitingForRoomJoin;
    pthread_mutex_unlock(&g_input.mutex);
    if (!connected)
      break;

    pthread_mutex_lock(&g_input.mutex);
    bool readingPasswordNow = g_readingPassword;
    pthread_mutex_unlock(&g_input.mutex);

    if (waitingForRoomJoin && !readingPasswordNow) {
      usleep(10000);
      continue;
    }

    char c;
    if (read(STDIN_FILENO, &c, 1) != 1)
      continue;

    pthread_mutex_lock(&g_input.mutex);
    readingPasswordNow = g_readingPassword;
    pthread_mutex_unlock(&g_input.mutex);

    if (readingPasswordNow) {
      if (c == '\n' || c == '\r') {
        finalizePasswordEntry();
      } else if (c == 127 || c == 8) {
        if (g_passwordLen > 0) {
          g_passwordLen--;
          g_passwordBuffer[g_passwordLen] = '\0';
          printf("\b \b");
          fflush(stdout);
        }
      } else if (isprint((unsigned char)c) && g_passwordLen < MSG_SIZE - 1) {
        g_passwordBuffer[g_passwordLen++] = c;
        g_passwordBuffer[g_passwordLen] = '\0';
        printf("*");
        fflush(stdout);
      }
      continue;
    }

    if (c == '\n' || c == '\r') {
      normalBuf[normalLen] = '\0';
      printf("\n");
      if (!processInput(normalBuf, normalLen))
        break;

      normalLen = 0;
      normalBuf[0] = '\0';

      pthread_mutex_lock(&g_input.mutex);
      g_input.buffer[0] = '\0';
      g_input.length = 0;
      pthread_mutex_unlock(&g_input.mutex);

      printPrompt();
    } else if ((c == 127 || c == 8) && normalLen > 0) {
      normalLen--;
      normalBuf[normalLen] = '\0';
      printf("\b \b");
      fflush(stdout);
      pthread_mutex_lock(&g_input.mutex);
      snprintf(g_input.buffer, sizeof(g_input.buffer), "%s", normalBuf);
      g_input.length = normalLen;
      pthread_mutex_unlock(&g_input.mutex);
    } else if (isprint((unsigned char)c) && normalLen < MSG_SIZE - 1) {
      normalBuf[normalLen++] = c;
      normalBuf[normalLen] = '\0';
      printf("%c", c);
      fflush(stdout);
      pthread_mutex_lock(&g_input.mutex);
      snprintf(g_input.buffer, sizeof(g_input.buffer), "%s", normalBuf);
      g_input.length = normalLen;
      pthread_mutex_unlock(&g_input.mutex);
    }
  }
}

static bool connectToServer(const char *ip, int port) {
  g_socketFD = createTCPSocket();
  if (g_socketFD < 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to create socket\n");
    return false;
  }
  struct addrinfo hints = {0};
  struct addrinfo *servinfo = NULL;
  char portStr[16];
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  snprintf(portStr, sizeof(portStr), "%d", port);
  if (getaddrinfo(ip, portStr, &hints, &servinfo) != 0 || !servinfo) {
    printMessage(COLOR_RED, "[!] ", "Failed to resolve hostname\n");
    close(g_socketFD);
    return false;
  }
  char resolvedIP[INET_ADDRSTRLEN];
  struct sockaddr_in *ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
  inet_ntop(AF_INET, &ipv4->sin_addr, resolvedIP, sizeof(resolvedIP));
  freeaddrinfo(servinfo);
  SocketAddress *address = createSocketAddress(resolvedIP, port, true);
  if (!address) {
    printMessage(COLOR_RED, "[!] ", "Failed to create socket address\n");
    close(g_socketFD);
    return false;
  }
  if (connectSocket(g_socketFD, address) != 0) {
    printf(COLOR_RED "[!] " COLOR_RESET "Failed to connect to %s:%d\n", ip,
           port);
    close(g_socketFD);
    free(address);
    return false;
  }
  free(address);
  SSL_CTX *ctx = tlsClientCtxCreate();
  if (!ctx) {
    printMessage(COLOR_RED, "[!] ", "Failed to create TLS context\n");
    close(g_socketFD);
    return false;
  }
  g_ssl = tlsClientConnect(ctx, g_socketFD);
  SSL_CTX_free(ctx);
  if (!g_ssl) {
    printMessage(COLOR_RED, "[!] ", "TLS handshake failed\n");
    close(g_socketFD);
    return false;
  }
  clientLog("connectToServer: TLS connected to %s:%d", ip, port);
  return true;
}

int main(int argc, char *argv[]) {
  tcgetattr(STDIN_FILENO, &g_origTermios);
  atexit(disableRawMode);
  enableRawMode();

  logOpen();
  clientLog("=== client starting ===");
  if (!identityLoadOrCreate(&g_identity)) {
    fprintf(stderr, "Fatal: could not load or create identity\n");
    return 1;
  }
  clientLog("identity loaded, token=%.16s...", g_identity.token);
  const char *ip = DEFAULT_IP;
  int port = DEFAULT_PORT;
  if (argc > 1) {
    char *arg = argv[1];
    char *colon = strchr(arg, ':');
    if (colon) {
      *colon = '\0';
      ip = arg;
      port = atoi(colon + 1);
    } else {
      ip = arg;
    }
  }

  if (!connectToServer(ip, port))
    return 1;

  {
    char challengeBuf[MSG_SIZE];
    ssize_t n = tlsRecv(g_ssl, challengeBuf, sizeof(challengeBuf));
    if (n <= 0 || strncmp(challengeBuf, "CHALLENGE:", 10) != 0 ||
        strlen(challengeBuf) < 10 + CHALLENGE_HEX_LEN) {
      fprintf(stderr, "auth: invalid challenge\n");
      tlsFree(g_ssl);
      close(g_socketFD);
      return 1;
    }
    const char *hexNonce = challengeBuf + 10;
    unsigned char nonce[CHALLENGE_BYTES];
    bool ok = true;
    for (int i = 0; i < CHALLENGE_BYTES && ok; i++) {
      int hi = -1, lo = -1;
      char hc = hexNonce[i * 2], lc = hexNonce[i * 2 + 1];
      if (hc >= '0' && hc <= '9')
        hi = hc - '0';
      else if (hc >= 'a' && hc <= 'f')
        hi = hc - 'a' + 10;
      else if (hc >= 'A' && hc <= 'F')
        hi = hc - 'A' + 10;
      else
        ok = false;
      if (lc >= '0' && lc <= '9')
        lo = lc - '0';
      else if (lc >= 'a' && lc <= 'f')
        lo = lc - 'a' + 10;
      else if (lc >= 'A' && lc <= 'F')
        lo = lc - 'A' + 10;
      else
        ok = false;
      if (ok)
        nonce[i] = (unsigned char)((hi << 4) | lo);
    }
    if (!ok) {
      fprintf(stderr, "auth: malformed nonce\n");
      tlsFree(g_ssl);
      close(g_socketFD);
      return 1;
    }
    unsigned char sig[SIG_BYTES];
    if (!identitySign(&g_identity, nonce, CHALLENGE_BYTES, sig)) {
      fprintf(stderr, "auth: sign failed\n");
      tlsFree(g_ssl);
      close(g_socketFD);
      return 1;
    }
    static const char hx[] = "0123456789abcdef";
    char sigHex[SIG_HEX_SIZE];
    for (int i = 0; i < SIG_BYTES; i++) {
      sigHex[i * 2] = hx[sig[i] >> 4];
      sigHex[i * 2 + 1] = hx[sig[i] & 0xf];
    }
    sigHex[SIG_HEX_LEN] = '\0';
    char authMsg[MSG_SIZE];
    snprintf(authMsg, sizeof(authMsg), "AUTH:%s:%s\n", g_identity.token,
             sigHex);
    if (!tlsSend(g_ssl, authMsg, strlen(authMsg))) {
      fprintf(stderr, "auth: send failed\n");
      tlsFree(g_ssl);
      close(g_socketFD);
      return 1;
    }
    char ackBuf[MSG_SIZE];
    n = tlsRecv(g_ssl, ackBuf, sizeof(ackBuf));
    if (n <= 0 || strncmp(ackBuf, "RESAuthenticated", 16) != 0) {
      fprintf(stderr, "auth: rejected: %s\n", n > 3 ? ackBuf + 3 : ackBuf);
      tlsFree(g_ssl);
      close(g_socketFD);
      return 1;
    }
    clientLog("auth: authenticated successfully");
  }

  pthread_t recvTid;
  if (pthread_create(&recvTid, NULL, receiveThread, NULL) != 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to create receive thread\n");
    tlsFree(g_ssl);
    close(g_socketFD);
    return 1;
  }

  clearScreen();
  print("SocketChat CLI (E2E Encrypted, TLS)\n");
  printf("Connected to " COLOR_GREEN "%s:%d\n" COLOR_RESET, ip, port);
  printf("Your token:   " COLOR_GREEN "%s\n" COLOR_RESET, g_identity.token);
  print("Type /help to view commands\n\n");
  enableRawMode();
  inputLoop();
  pthread_join(recvTid, NULL);
  disableRawMode();
  clientLog("=== client shutting down ===");
  printMessage(COLOR_YELLOW, "\n[*] ", "Shutting down...\n");
  tlsFree(g_ssl);
  close(g_socketFD);
  pthread_mutex_destroy(&g_input.mutex);
  if (g_logFile)
    fclose(g_logFile);
  return 0;
}
