#include "../Utils/aes.h"
#include "../Utils/socketUtil.h"

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 2077

static int g_socketFD = -1;
static RoomEncryption g_encryption = {0};
static struct termios g_origTermios;

typedef struct {
  char buffer[MSG_SIZE];
  size_t length;
  pthread_mutex_t mutex;
  bool connected;
  bool waitingForPassword;
} InputState;

static InputState g_input = {
    .buffer = {0},
    .length = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .connected = true,
    .waitingForPassword = false,
};

static bool sendToServer(const char *message);

static void disableRawMode(void) {
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_origTermios);
}

static void enableRawMode(void) {
  tcgetattr(STDIN_FILENO, &g_origTermios);
  atexit(disableRawMode);

  struct termios raw = g_origTermios;
  raw.c_lflag &= ~(ICANON | ECHO);
  raw.c_cc[VMIN] = 1;
  raw.c_cc[VTIME] = 0;
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static void clearScreen(void) { print("\033[2J\033[H"); }

static void eraseInputLine(void) {
  pthread_mutex_lock(&g_input.mutex);
  print("\r\033[K");
  pthread_mutex_unlock(&g_input.mutex);
}

static void redrawInputLine(void) {
  pthread_mutex_lock(&g_input.mutex);
  printf(COLOR_GREEN ">>> " COLOR_RESET "%s", g_input.buffer);
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

static void clearEncryption(void) {
  memset(&g_encryption, 0, sizeof(g_encryption));
}

static bool encryptAndSend(const char *message, size_t msgLen) {
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

static bool decryptAndDisplay(const char *encryptedData, const char *username) {
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

  char formatted[MSG_SIZE * 2];
  if (username[0])
    snprintf(formatted, sizeof(formatted), "%s<< %s: %s%s\n", COLOR_CYAN,
             username, decrypted, COLOR_RESET);
  else
    snprintf(formatted, sizeof(formatted), "%s<< %s%s\n", COLOR_CYAN, decrypted,
             COLOR_RESET);

  print(formatted);
  return true;
}

static void displayIncomingMessage(char *buffer) {

  bool isMsg = (buffer[0] == 'M' && buffer[1] == 'S' && buffer[2] == 'G');
  bool isErr = (buffer[0] == 'E' && buffer[1] == 'R' && buffer[2] == 'R');
  bool isRes = (buffer[0] == 'R' && buffer[1] == 'E' && buffer[2] == 'S');
  bool isPas = (buffer[0] == 'P' && buffer[1] == 'A' && buffer[2] == 'S');

  eraseInputLine();

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

      if (!decryptAndDisplay(messageStart + 4, username))
        printMessage(COLOR_RED, "[!] ", "Failed to decrypt message\n");
    } else {

      char text[MSG_SIZE];
      strncpy(text, messageStart, MSG_SIZE - 1);
      text[MSG_SIZE - 1] = '\0';
      size_t tlen = strlen(text);
      while (tlen > 0 && (text[tlen - 1] == '\n' || text[tlen - 1] == '\r'))
        text[--tlen] = '\0';

      char formatted[MSG_SIZE * 2];
      if (username[0])
        snprintf(formatted, sizeof(formatted), "%s<< %s: %s%s\n", COLOR_CYAN,
                 username, text, COLOR_RESET);
      else
        snprintf(formatted, sizeof(formatted), "%s<< %s%s\n", COLOR_CYAN, text,
                 COLOR_RESET);
      print(formatted);
    }
  }

  else if (isErr) {
    printMessage(COLOR_RED, "[!] ", buffer + 3);
  }

  else if (isRes) {
    printMessage(COLOR_YELLOW, "[*] ", buffer + 3);
  }

  else if (isPas) {

    printMessage(COLOR_YELLOW, "[*] ", buffer + 3);

    pthread_mutex_lock(&g_input.mutex);
    g_input.waitingForPassword = true;
    pthread_mutex_unlock(&g_input.mutex);
    return;
  } else {

    printMessage(COLOR_RED, "[!] ", "Unknown message type from server:\n");
    printMessage(COLOR_RED, "    ", buffer);
    print("\n");
  }

  redrawInputLine();
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
    ssize_t received = recv(g_socketFD, buffer, MSG_SIZE - 1, 0);

    if (received == 0) {

      handleDisconnect();
      break;
    } else if (received < 0) {
      if (errno == EINTR)
        continue;
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
    printMessage(COLOR_RED, "[!] ", "Cannot send: not connected to server\n");
    return false;
  }

  size_t length = strlen(message) + 1;
  if (length >= MSG_SIZE) {
    printMessage(COLOR_RED, "[!] ", "Message too long\n");
    return false;
  }

  ssize_t sent = send(g_socketFD, message, length, 0);
  if (sent < 0) {
    if (errno == EPIPE || errno == ECONNRESET)
      handleDisconnect();
    else
      printMessage(COLOR_RED, "[!] ", "Send failed\n");
    return false;
  }

  return true;
}

static void handleLeaveCommand(void) {
  clearEncryption();
  sendToServer("/leave\n");
}

static bool processInput(char *message, size_t msgLen) {

  pthread_mutex_lock(&g_input.mutex);
  bool needsPass = g_input.waitingForPassword;
  if (needsPass)
    g_input.waitingForPassword = false;
  pthread_mutex_unlock(&g_input.mutex);

  if (needsPass) {

    deriveKeyFromPassword(message, g_encryption.key);
    g_encryption.hasKey = true;

    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
    return true;
  }

  if (msgLen == 0)
    return true;

  if (strcmp(message, "/exit") == 0) {
    sendToServer("/exit\n");
    return false;
  }

  if (strcmp(message, "/clear") == 0) {
    clearScreen();
    print("SocketChat CLI (E2E Encrypted)\n\n");
    return true;
  }

  if (strcmp(message, "/leave") == 0) {
    handleLeaveCommand();
    return true;
  }

  if (strncmp(message, "/enter ", 7) == 0) {

    char roomName[64] = {0};
    sscanf(message + 7, "%63s", roomName);
    strncpy(g_encryption.roomName, roomName, sizeof(g_encryption.roomName) - 1);

    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
    return true;
  }

  if (message[0] == '/') {

    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
    return true;
  }

  if (g_encryption.hasKey)
    encryptAndSend(message, msgLen);
  else {
    char toSend[MSG_SIZE];
    snprintf(toSend, sizeof(toSend), "%s\n", message);
    sendToServer(toSend);
  }

  return true;
}

static void updateInputBuffer(const char *message, size_t msgLen) {
  pthread_mutex_lock(&g_input.mutex);
  strncpy(g_input.buffer, message, MSG_SIZE - 1);
  g_input.buffer[msgLen] = '\0';
  g_input.length = msgLen;
  pthread_mutex_unlock(&g_input.mutex);
}

static void clearInputBuffer(void) {
  pthread_mutex_lock(&g_input.mutex);
  g_input.buffer[0] = '\0';
  g_input.length = 0;
  pthread_mutex_unlock(&g_input.mutex);
}

static void inputLoop(void) {
  char message[MSG_SIZE] = {0};
  size_t msgLen = 0;

  printf(COLOR_GREEN ">>> " COLOR_RESET);
  fflush(stdout);

  while (true) {
    pthread_mutex_lock(&g_input.mutex);
    bool connected = g_input.connected;
    pthread_mutex_unlock(&g_input.mutex);

    if (!connected)
      break;

    char c;
    if (read(STDIN_FILENO, &c, 1) != 1)
      continue;

    if (c == '\n' || c == '\r') {
      message[msgLen] = '\0';
      printf("\n");

      if (!processInput(message, msgLen))
        break;

      msgLen = 0;
      message[0] = '\0';
      clearInputBuffer();

      pthread_mutex_lock(&g_input.mutex);
      bool waiting = g_input.waitingForPassword;
      pthread_mutex_unlock(&g_input.mutex);

      if (!waiting) {
        printf(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);
      }
    } else if ((c == 127 || c == 8) && msgLen > 0) {
      msgLen--;
      message[msgLen] = '\0';
      printf("\b \b");
      fflush(stdout);
      updateInputBuffer(message, msgLen);
    } else if (isprint((unsigned char)c) && msgLen < MSG_SIZE - 1) {
      message[msgLen++] = c;
      message[msgLen] = '\0';
      printf("%c", c);
      fflush(stdout);
      updateInputBuffer(message, msgLen);
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
    printMessage(COLOR_YELLOW, "[*] ",
                 "Is the server running and reachable?\n");
    close(g_socketFD);
    free(address);
    return false;
  }

  free(address);
  return true;
}

int main(int argc, char *argv[]) {
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

  pthread_t recvTid;
  if (pthread_create(&recvTid, NULL, receiveThread, NULL) != 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to create receive thread\n");
    close(g_socketFD);
    return 1;
  }
  pthread_detach(recvTid);

  clearScreen();
  print("SocketChat CLI (E2E Encrypted)\n");
  printf("Connected to " COLOR_GREEN "%s:%d\n" COLOR_RESET, ip, port);
  print("Do /help to view commands\n\n");

  enableRawMode();
  inputLoop();
  disableRawMode();

  printMessage(COLOR_YELLOW, "\n[*] ", "Shutting down...\n");
  close(g_socketFD);
  pthread_mutex_destroy(&g_input.mutex);

  return 0;
}
