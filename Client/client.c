#include "../Utils/aes.h"
#include "../Utils/contacts.h"
#include "../Utils/ecdh.h"
#include "../Utils/history.h"
#include "../Utils/identity.h"
#include "../Utils/protocol.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#include <ctype.h>
#include <stdarg.h>
#include <termios.h>

#if defined(__GNUC__) || defined(__clang__)
#define PRINTF_FMT(fmtIndex, firstArg) __attribute__((format(printf, fmtIndex, firstArg)))
#else
#define PRINTF_FMT(fmtIndex, firstArg)
#endif

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 2077

typedef struct {
  bool active;
  bool protectedRoom;
  char currentName[MAX_NAME_LEN];
  char pendingName[MAX_NAME_LEN];
  char pendingSalt[ROOM_SALT_HEX_SIZE];
  unsigned char key[32];
  unsigned char pendingKey[32];
} RoomState;

typedef struct {
  bool active;
  bool awaitingAck;
  char peerToken[TOKEN_STR_SIZE];
  unsigned char key[32];
  unsigned char pendingPriv[32];
  unsigned char pendingPub[32];
} DmSession;

typedef struct {
  char buffer[MSG_SIZE];
  size_t length;
  pthread_mutex_t mutex;
  bool connected;
  bool readingRoomSecret;
  char roomSecret[MSG_SIZE];
  size_t roomSecretLen;
} InputState;

static FILE *g_logFile = NULL;
static char g_logPath[512] = {0};
static SocketHandle g_socketFD = INVALID_SOCKET_HANDLE;
static SSL *g_ssl = NULL;
static Identity g_identity = {0};
static char g_username[MAX_NAME_LEN] = {0};
static RoomState g_room = {0};
static DmSession g_dm = {0};
static struct termios g_origTermios;
static InputState g_input = {
    .buffer = {0},
    .length = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .connected = true,
    .readingRoomSecret = false,
    .roomSecret = {0},
    .roomSecretLen = 0,
};

static ContactBook g_contacts = {0};

static void clientLog(const char *fmt, ...) PRINTF_FMT(1, 2);
static void printMessage(const char *color, const char *prefix,
                         const char *message);

static void logOpen(void) {
  char configDir[512];
  if (!platformGetConfigDir(configDir, sizeof(configDir)))
    return;
  if (!platformEnsureDir(configDir))
    return;

  pid_t pid = getpid();
  snprintf(g_logPath, sizeof(g_logPath), "%s%cclient_%d.log", configDir,
           SOCKETCHAT_PATH_SEP, pid);
  g_logFile = fopen(g_logPath, "a");
  if (!g_logFile)
    return;
  setvbuf(g_logFile, NULL, _IOLBF, 0);
}

static void clientLog(const char *fmt, ...) {
  if (!g_logFile)
    return;

  time_t now = time(NULL);
  struct tm tmInfo;
  char ts[32] = "?";
  if (platformLocalTime(now, &tmInfo))
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmInfo);

  fprintf(g_logFile, "[%s] ", ts);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(g_logFile, fmt, ap);
  va_end(ap);
  if (fmt[strlen(fmt) - 1] != '\n')
    fputc('\n', g_logFile);
}

static void disableRawMode(void) {
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_origTermios);
}

static void enableRawMode(void) {
  struct termios raw;
  tcgetattr(STDIN_FILENO, &raw);
  raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
  raw.c_cc[VMIN] = 1;
  raw.c_cc[VTIME] = 0;
  tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

static void clearScreen(void) { print("\033[2J\033[H"); }
static void eraseInputLine(void) { print("\r\033[K"); }

static void clearRoomState(void) {
  memset(&g_room, 0, sizeof(g_room));
}

static void clearDmSession(void) {
  memset(&g_dm, 0, sizeof(g_dm));
}

static void reloadDmHistoryIndex(void) {
  contactsLoad(&g_contacts);
  if (g_dm.peerToken[0])
    contactsRememberToken(&g_contacts, g_dm.peerToken);
}

static void saveDmNicknames(void) {
  contactsSaveNicknames(&g_contacts);
}

static void rememberDmToken(const char *token) {
  contactsRememberToken(&g_contacts, token);
}

static void formatDmLabel(const char *token, char *out, size_t outSize) {
  contactsFormatLabel(&g_contacts, token, out, outSize);
}

static int dmContactCount(void) {
  return (int)g_contacts.count;
}

static bool isNumericReference(const char *text) {
  if (!text || !text[0])
    return false;

  for (size_t i = 0; text[i]; i++) {
    if (!isdigit((unsigned char)text[i]))
      return false;
  }
  return true;
}

static bool isTokenHex(const char *text) {
  if (!text || strlen(text) != TOKEN_HEX_LEN)
    return false;
  for (size_t i = 0; text[i]; i++) {
    if (!isxdigit((unsigned char)text[i]))
      return false;
  }
  return true;
}

static const char *skipSpaces(const char *text) {
  while (text && *text == ' ')
    text++;
  return text;
}

static void copyTrimmed(const char *input, char *out, size_t outSize) {
  if (!out || outSize == 0)
    return;

  out[0] = '\0';
  if (!input)
    return;

  input = skipSpaces(input);
  size_t len = strlen(input);
  while (len > 0 && input[len - 1] == ' ')
    len--;
  if (len >= outSize)
    len = outSize - 1;
  memcpy(out, input, len);
  out[len] = '\0';
}

static bool splitFirstArgument(const char *input, char *first,
                               size_t firstSize, const char **restOut) {
  if (!first || firstSize == 0)
    return false;

  first[0] = '\0';
  if (restOut)
    *restOut = NULL;

  input = skipSpaces(input);
  if (!input || !input[0])
    return false;

  size_t rawLen = 0;
  while (input[rawLen] && input[rawLen] != ' ')
    rawLen++;

  size_t copyLen = rawLen;
  if (copyLen >= firstSize)
    copyLen = firstSize - 1;
  memcpy(first, input, copyLen);
  first[copyLen] = '\0';

  if (restOut)
    *restOut = skipSpaces(input + rawLen);
  return true;
}

static void printContactMatches(const char *query, const ContactMatch *matches,
                                size_t matchCount) {
  if (matchCount == 0) {
    printf(COLOR_RED "[!] No contact matches \"%s\"\n" COLOR_RESET, query);
    return;
  }

  printf(COLOR_YELLOW "[*] Contacts matching \"%s\":\n" COLOR_RESET, query);
  for (size_t i = 0; i < matchCount; i++) {
    char reference[128];
    contactsFormatReference(&g_contacts, matches[i].index, reference,
                            sizeof(reference));
    printf("  %zu. %s\n", matches[i].index + 1, reference);
  }
}

static bool resolveDmReference(const char *input, char *tokenOut,
                               size_t tokenOutSize, bool allowDirectToken,
                               bool announceAmbiguity) {
  if (!tokenOut || tokenOutSize == 0)
    return false;

  char query[128];
  copyTrimmed(input, query, sizeof(query));
  if (!query[0]) {
    if (announceAmbiguity)
      printMessage(COLOR_RED, "[!] ", "Contact reference is empty\n");
    return false;
  }

  ContactMatch matches[8];
  size_t matchCount = 0;
  ContactLookupStatus status =
      contactsLookup(&g_contacts, query, matches, 8, &matchCount);
  if (status == CONTACT_LOOKUP_UNIQUE && matchCount > 0) {
    const DmContact *contact = contactsGet(&g_contacts, matches[0].index);
    if (!contact)
      return false;
    snprintf(tokenOut, tokenOutSize, "%s", contact->token);
    return true;
  }

  if (status == CONTACT_LOOKUP_AMBIGUOUS) {
    if (announceAmbiguity) {
      printMessage(COLOR_RED, "[!] ",
                   "Multiple contacts match that query. Use /search or a number.\n");
      printContactMatches(query, matches, matchCount);
    }
    return false;
  }

  if (allowDirectToken && isTokenHex(query)) {
    snprintf(tokenOut, tokenOutSize, "%s", query);
    return true;
  }

  if (announceAmbiguity)
    printf(COLOR_RED "[!] No contact matches \"%s\"\n" COLOR_RESET, query);
  return false;
}

static void printPrompt(void) {
  pthread_mutex_lock(&g_input.mutex);
  if (g_dm.active) {
    char dmLabel[64];
    formatDmLabel(g_dm.peerToken, dmLabel, sizeof(dmLabel));
    printf(COLOR_GREEN "[DM:%.18s]> " COLOR_RESET "%s", dmLabel,
           g_input.buffer);
  } else if (g_room.active) {
    printf(COLOR_GREEN "[#%.14s]> " COLOR_RESET "%s", g_room.currentName,
           g_input.buffer);
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

static bool sendRawFrame(const char *frame) {
  pthread_mutex_lock(&g_input.mutex);
  bool connected = g_input.connected;
  pthread_mutex_unlock(&g_input.mutex);
  if (!connected)
    return false;
  clientLog("send: %.160s", frame);
  if (!tlsSend(g_ssl, frame, strlen(frame))) {
    return false;
  }
  return true;
}

static bool signDmFrame(const char *frameType, const char *fromToken,
                        const char *toToken, const char *pubHex,
                        unsigned char sigOut[SIG_BYTES]) {
  char transcript[256];
  int len = snprintf(transcript, sizeof(transcript), "%s|%s|%s|%s", frameType,
                     fromToken, toToken, pubHex);
  if (len <= 0 || (size_t)len >= sizeof(transcript))
    return false;
  return identitySign(&g_identity, (const unsigned char *)transcript, (size_t)len,
                      sigOut);
}

static bool verifyDmFrame(const char *frameType, const char *fromToken,
                          const char *toToken, const char *pubHex,
                          const unsigned char sig[SIG_BYTES]) {
  char transcript[256];
  int len = snprintf(transcript, sizeof(transcript), "%s|%s|%s|%s", frameType,
                     fromToken, toToken, pubHex);
  if (len <= 0 || (size_t)len >= sizeof(transcript))
    return false;
  return identityVerify(fromToken, (const unsigned char *)transcript, (size_t)len,
                        sig);
}

static bool encryptAndSendRoom(const char *message) {
  char encodedText[MSG_SIZE * 2];
  if (!g_room.protectedRoom) {
    if (!protocolEncodeText(message, encodedText, sizeof(encodedText))) {
      printMessage(COLOR_RED, "[!] ", "Message too long\n");
      return false;
    }
  } else {
    unsigned char ciphertext[MSG_SIZE];
    int clen = encryptMessage((const unsigned char *)message, strlen(message),
                              g_room.key, ciphertext);
    if (clen <= 0) {
      printMessage(COLOR_RED, "[!] ", "Failed to encrypt room message\n");
      return false;
    }
    encodeBase64(ciphertext, (size_t)clen, encodedText);
  }

  char frame[MSG_SIZE * 2 + 32];
  snprintf(frame, sizeof(frame), "ROOM_SEND|%s\n", encodedText);
  return sendRawFrame(frame);
}

static bool encryptAndSendDm(const char *message) {
  unsigned char ciphertext[MSG_SIZE];
  int clen = encryptMessage((const unsigned char *)message, strlen(message),
                            g_dm.key, ciphertext);
  if (clen <= 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to encrypt DM\n");
    return false;
  }

  char encoded[MSG_SIZE * 2];
  encodeBase64(ciphertext, (size_t)clen, encoded);

  char frame[MSG_SIZE * 2 + TOKEN_STR_SIZE + 32];
  snprintf(frame, sizeof(frame), "DM_SEND|%s|%s\n", g_dm.peerToken, encoded);
  return sendRawFrame(frame);
}

static void printTimestamped(const char *label, const char *message,
                             const char *color) {
  time_t now = time(NULL);
  struct tm tmInfo;
  char ts[16] = "00:00";
  if (platformLocalTime(now, &tmInfo))
    strftime(ts, sizeof(ts), "%H:%M", &tmInfo);

  char line[MSG_SIZE * 2];
  if (label && label[0])
    snprintf(line, sizeof(line), "[%s] %s: %s\n", ts, label, message);
  else
    snprintf(line, sizeof(line), "[%s] %s\n", ts, message);
  printMessage(color, "", line);
}

static void showRoomMessage(const char *sender, const char *payload) {
  char text[MSG_SIZE];
  if (!g_room.protectedRoom) {
    if (!protocolDecodeText(payload, text, sizeof(text))) {
      printMessage(COLOR_RED, "[!] ", "Failed to decode room message\n");
      return;
    }
  } else {
    unsigned char decoded[MSG_SIZE];
    int dlen = decodeBase64(payload, decoded);
    if (dlen <= 0) {
      printMessage(COLOR_RED, "[!] ", "Failed to decode encrypted room message\n");
      return;
    }
    unsigned char decrypted[MSG_SIZE];
    int plen = decryptMessage(decoded, (size_t)dlen, g_room.key, decrypted);
    if (plen <= 0) {
      printMessage(COLOR_RED, "[!] ", "Failed to decrypt room message\n");
      return;
    }
    decrypted[plen] = '\0';
    snprintf(text, sizeof(text), "%s", (char *)decrypted);
  }
  printTimestamped(sender, text, COLOR_CYAN);
}

static void showDmMessage(const char *senderToken, const char *payload) {
  if (!g_dm.active || strcmp(g_dm.peerToken, senderToken) != 0) {
    char dmLabel[64];
    formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
    printf(COLOR_YELLOW "[*] Received DM for inactive contact %s\n" COLOR_RESET,
           dmLabel);
    return;
  }

  unsigned char decoded[MSG_SIZE];
  int dlen = decodeBase64(payload, decoded);
  if (dlen <= 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to decode DM payload\n");
    return;
  }

  unsigned char decrypted[MSG_SIZE];
  int plen = decryptMessage(decoded, (size_t)dlen, g_dm.key, decrypted);
  if (plen <= 0) {
    printMessage(COLOR_RED, "[!] ", "Failed to decrypt DM\n");
    return;
  }

  decrypted[plen] = '\0';
  historyAppend(senderToken, false, (char *)decrypted);
  rememberDmToken(senderToken);
  char dmLabel[64];
  formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
  printTimestamped(dmLabel, (char *)decrypted, COLOR_CYAN);
}

static void finalizeRoomSecretEntry(void) {
  printf("\n");
  fflush(stdout);

  char verifier[SHA256_HEX_SIZE];
  if (!verifyRoomSecret(g_room.pendingName, g_input.roomSecret, g_room.pendingSalt,
                        verifier, g_room.pendingKey)) {
    printMessage(COLOR_RED, "[!] ", "Failed to derive room secret\n");
    goto cleanup;
  }

  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "ROOM_PROOF|%s|%s\n", g_room.pendingName,
           verifier);
  sendRawFrame(frame);

cleanup:
  memset(g_input.roomSecret, 0, sizeof(g_input.roomSecret));
  g_input.roomSecretLen = 0;
  pthread_mutex_lock(&g_input.mutex);
  g_input.readingRoomSecret = false;
  pthread_mutex_unlock(&g_input.mutex);
}

static void handleDmInit(const char *senderToken, const char *peerPubHex,
                         const char *sigHex) {
  if (strlen(senderToken) != TOKEN_HEX_LEN || strlen(peerPubHex) != 64 ||
      strlen(sigHex) != SIG_HEX_LEN) {
    printMessage(COLOR_RED, "[!] ", "Malformed DM_INIT frame\n");
    return;
  }

  unsigned char sig[SIG_BYTES];
  unsigned char peerPub[32];
  if (!hexToBytes(sigHex, sig, sizeof(sig)) || !hexToBytes(peerPubHex, peerPub, sizeof(peerPub))) {
    printMessage(COLOR_RED, "[!] ", "Invalid DM_INIT encoding\n");
    return;
  }
  if (!verifyDmFrame("DM_INIT", senderToken, g_identity.token, peerPubHex, sig)) {
    printMessage(COLOR_RED, "[!] ", "DM_INIT signature verification failed\n");
    return;
  }

  unsigned char myPub[32];
  unsigned char myPriv[32];
  if (!x25519GenerateKeypair(myPub, myPriv)) {
    printMessage(COLOR_RED, "[!] ", "Failed to generate DM session keys\n");
    return;
  }

  unsigned char sessionKey[32];
  if (!ecdhDeriveSessionKey(myPriv, peerPub, senderToken, g_identity.token,
                            peerPub, myPub, sessionKey)) {
    memset(myPriv, 0, sizeof(myPriv));
    printMessage(COLOR_RED, "[!] ", "Failed to derive DM session key\n");
    return;
  }

  char myPubHex[65];
  bytesToHex(myPub, sizeof(myPub), myPubHex);
  unsigned char ackSig[SIG_BYTES];
  if (!signDmFrame("DM_ACK", g_identity.token, senderToken, myPubHex, ackSig)) {
    memset(myPriv, 0, sizeof(myPriv));
    printMessage(COLOR_RED, "[!] ", "Failed to sign DM acknowledgment\n");
    return;
  }

  char ackSigHex[SIG_HEX_SIZE];
  bytesToHex(ackSig, sizeof(ackSig), ackSigHex);
  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "DM_ACK|%s|%s|%s\n", senderToken, myPubHex,
           ackSigHex);
  sendRawFrame(frame);

  clearDmSession();
  g_dm.active = true;
  snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", senderToken);
  memcpy(g_dm.key, sessionKey, sizeof(sessionKey));
  rememberDmToken(senderToken);

  memset(myPriv, 0, sizeof(myPriv));
  char dmLabel[64];
  formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
  printf(COLOR_YELLOW "[*] DM session established with %s\n" COLOR_RESET,
         dmLabel);
}

static void handleDmAck(const char *senderToken, const char *peerPubHex,
                        const char *sigHex) {
  if (!g_dm.awaitingAck || strcmp(g_dm.peerToken, senderToken) != 0)
    return;

  unsigned char sig[SIG_BYTES];
  unsigned char peerPub[32];
  if (!hexToBytes(sigHex, sig, sizeof(sig)) || !hexToBytes(peerPubHex, peerPub, sizeof(peerPub))) {
    printMessage(COLOR_RED, "[!] ", "Invalid DM_ACK encoding\n");
    return;
  }

  if (!verifyDmFrame("DM_ACK", senderToken, g_identity.token, peerPubHex, sig)) {
    printMessage(COLOR_RED, "[!] ", "DM_ACK signature verification failed\n");
    return;
  }

  unsigned char sessionKey[32];
  if (!ecdhDeriveSessionKey(g_dm.pendingPriv, peerPub, g_identity.token,
                            senderToken, g_dm.pendingPub, peerPub, sessionKey)) {
    printMessage(COLOR_RED, "[!] ", "Failed to derive DM session key\n");
    return;
  }

  g_dm.active = true;
  g_dm.awaitingAck = false;
  memcpy(g_dm.key, sessionKey, sizeof(sessionKey));
  memset(g_dm.pendingPriv, 0, sizeof(g_dm.pendingPriv));
  memset(g_dm.pendingPub, 0, sizeof(g_dm.pendingPub));
  rememberDmToken(senderToken);
  char dmLabel[64];
  formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
  printf(COLOR_YELLOW "[*] DM session ready with %s\n" COLOR_RESET, dmLabel);
}

static void displayIncomingMessage(char *buffer) {
  char *parts[PROTOCOL_MAX_PARTS] = {0};
  size_t partCount = protocolSplitFields(buffer, parts, PROTOCOL_MAX_PARTS);
  if (partCount == 0)
    return;

  clientLog("recv: %.160s", buffer);
  eraseInputLine();
  pthread_mutex_lock(&g_input.mutex);
  g_input.buffer[0] = '\0';
  g_input.length = 0;
  pthread_mutex_unlock(&g_input.mutex);

  if (strcmp(parts[0], "ERR") == 0 && partCount >= 2) {
    printMessage(COLOR_RED, "[!] ", parts[1]);
    print("\n");
  } else if (strcmp(parts[0], "OK") == 0 && partCount >= 2) {
    if (strcmp(parts[1], "ROOM_ENTERED") == 0 && partCount >= 3) {
      g_room.active = true;
      snprintf(g_room.currentName, sizeof(g_room.currentName), "%s",
               g_room.pendingName);
      g_room.protectedRoom = strcmp(parts[2], "PROTECTED") == 0;
      if (g_room.protectedRoom)
        memcpy(g_room.key, g_room.pendingKey, sizeof(g_room.key));
      printMessage(COLOR_YELLOW, "[*] ", "Entered room\n");
    } else if (strcmp(parts[1], "ROOM_LEFT") == 0) {
      clearRoomState();
      printMessage(COLOR_YELLOW, "[*] ", "Left room\n");
    } else if (strcmp(parts[1], "ROOM_CREATED") == 0) {
      printMessage(COLOR_YELLOW, "[*] ", "Room created\n");
    } else if (strcmp(parts[1], "NAME_SET") == 0) {
      printMessage(COLOR_YELLOW, "[*] ", "Name updated\n");
    } else if (strcmp(parts[1], "BYE") == 0) {
      printMessage(COLOR_YELLOW, "[*] ", "Server closed the session\n");
    }
  } else if (strcmp(parts[0], "INFO") == 0 && partCount >= 2) {
    if (strcmp(parts[1], "ROOMS_BEGIN") == 0) {
      printMessage(COLOR_YELLOW, "[*] ", "Rooms:\n");
    } else if (strcmp(parts[1], "ROOM") == 0 && partCount >= 4) {
      char line[MSG_SIZE];
      snprintf(line, sizeof(line), "  %-20s [%s]\n", parts[2], parts[3]);
      print(line);
    } else if (strcmp(parts[1], "ROOMS_END") == 0) {
    } else if (strcmp(parts[1], "ROOM_JOINED") == 0 && partCount >= 3) {
      char line[MSG_SIZE];
      snprintf(line, sizeof(line), "%s joined the room\n", parts[2]);
      printMessage(COLOR_YELLOW, "[*] ", line);
    } else if (strcmp(parts[1], "ROOM_LEFT") == 0 && partCount >= 3) {
      char line[MSG_SIZE];
      snprintf(line, sizeof(line), "%s left the room\n", parts[2]);
      printMessage(COLOR_YELLOW, "[*] ", line);
    } else if (strcmp(parts[1], "NAME_CHANGED") == 0 && partCount >= 4) {
      char line[MSG_SIZE];
      snprintf(line, sizeof(line), "%s is now %s\n", parts[2], parts[3]);
      printMessage(COLOR_YELLOW, "[*] ", line);
    }
  } else if (strcmp(parts[0], "ROOM_CHALLENGE") == 0 && partCount >= 3) {
    snprintf(g_room.pendingName, sizeof(g_room.pendingName), "%s", parts[1]);
    snprintf(g_room.pendingSalt, sizeof(g_room.pendingSalt), "%s", parts[2]);
    pthread_mutex_lock(&g_input.mutex);
    g_input.readingRoomSecret = true;
    g_input.roomSecret[0] = '\0';
    g_input.roomSecretLen = 0;
    pthread_mutex_unlock(&g_input.mutex);
    printf("\n" COLOR_YELLOW "Room secret: " COLOR_RESET);
    fflush(stdout);
    return;
  } else if (strcmp(parts[0], "ROOM_MSG") == 0 && partCount >= 3) {
    showRoomMessage(parts[1], parts[2]);
  } else if (strcmp(parts[0], "DM_INIT") == 0 && partCount >= 4) {
    handleDmInit(parts[1], parts[2], parts[3]);
  } else if (strcmp(parts[0], "DM_ACK") == 0 && partCount >= 4) {
    handleDmAck(parts[1], parts[2], parts[3]);
  } else if (strcmp(parts[0], "DM_MSG") == 0 && partCount >= 3) {
    showDmMessage(parts[1], parts[2]);
  } else {
    printMessage(COLOR_RED, "[!] ", "Unknown frame from server\n");
  }

  printPrompt();
}

static void handleDisconnect(void) {
  pthread_mutex_lock(&g_input.mutex);
  g_input.connected = false;
  pthread_mutex_unlock(&g_input.mutex);
  eraseInputLine();
  printMessage(COLOR_RED, "\n[!] ", "Disconnected from server\n");
  fflush(stdout);
  if (g_socketFD != INVALID_SOCKET_HANDLE)
    platformCloseSocket(g_socketFD);
}

static void *receiveThread(void *arg) {
  (void)arg;
  char buffer[MSG_SIZE];
  while (true) {
    ssize_t received = tlsRecv(g_ssl, buffer, sizeof(buffer));
    if (received <= 0) {
      handleDisconnect();
      break;
    }
    buffer[received] = '\0';
    displayIncomingMessage(buffer);
  }
  return NULL;
}

static void handleTokenCommand(void) {
  char msg[MSG_SIZE];
  snprintf(msg, sizeof(msg), COLOR_YELLOW "[*] Your token: %s\n" COLOR_RESET,
           g_identity.token);
  print(msg);
}

static void handleListCommand(void) {
  reloadDmHistoryIndex();
  print(COLOR_YELLOW "[*] Direct contacts:\n" COLOR_RESET);
  for (int i = 0; i < dmContactCount(); i++) {
    char reference[128];
    contactsFormatReference(&g_contacts, (size_t)i, reference,
                            sizeof(reference));
    printf("  %d. %s\n", i + 1, reference);
  }
  if (dmContactCount() == 0)
    print("  (no DM contacts)\n");
}

static void handleNickCommand(const char *target, const char *nick) {
  reloadDmHistoryIndex();

  char token[TOKEN_STR_SIZE] = {0};
  if (!target || !target[0] || strcmp(target, "@") == 0) {
    if (!g_dm.active) {
      printMessage(COLOR_RED, "[!] ",
                   "Start a DM first or pass a contact reference\n");
      return;
    }
    snprintf(token, sizeof(token), "%s", g_dm.peerToken);
  } else if (!resolveDmReference(target, token, sizeof(token), true, true)) {
    return;
  }

  if (strcmp(nick, "-") == 0) {
    if (!contactsClearNickname(&g_contacts, token)) {
      printMessage(COLOR_RED, "[!] ", "No nickname is set for that contact\n");
      return;
    }
    saveDmNicknames();
    printMessage(COLOR_YELLOW, "[*] ", "Nickname cleared\n");
    return;
  }

  char error[128];
  if (!contactsSetNickname(&g_contacts, token, nick, error, sizeof(error))) {
    printf(COLOR_RED "[!] %s\n" COLOR_RESET, error);
    return;
  }
  saveDmNicknames();
  printMessage(COLOR_YELLOW, "[*] ", "Nickname saved\n");
}

static void handleSearchCommand(const char *query) {
  reloadDmHistoryIndex();

  ContactMatch matches[8];
  size_t matchCount = contactsSearch(&g_contacts, query, matches, 8);
  printContactMatches(query, matches, matchCount);
}

static void handleDmCommand(const char *input) {
  reloadDmHistoryIndex();

  char token[TOKEN_STR_SIZE] = {0};
  if (!resolveDmReference(input, token, sizeof(token), true, true))
    return;

  unsigned char myPub[32];
  unsigned char myPriv[32];
  if (!x25519GenerateKeypair(myPub, myPriv)) {
    printMessage(COLOR_RED, "[!] ", "Failed to generate DM session keys\n");
    return;
  }

  char myPubHex[65];
  bytesToHex(myPub, sizeof(myPub), myPubHex);

  unsigned char sig[SIG_BYTES];
  if (!signDmFrame("DM_INIT", g_identity.token, token, myPubHex, sig)) {
    printMessage(COLOR_RED, "[!] ", "Failed to sign DM request\n");
    memset(myPriv, 0, sizeof(myPriv));
    return;
  }

  char sigHex[SIG_HEX_SIZE];
  bytesToHex(sig, sizeof(sig), sigHex);

  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "DM_INIT|%s|%s|%s\n", token, myPubHex, sigHex);
  if (!sendRawFrame(frame)) {
    memset(myPriv, 0, sizeof(myPriv));
    return;
  }

  clearDmSession();
  g_dm.awaitingAck = true;
  snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", token);
  memcpy(g_dm.pendingPriv, myPriv, sizeof(g_dm.pendingPriv));
  memcpy(g_dm.pendingPub, myPub, sizeof(g_dm.pendingPub));
  memset(myPriv, 0, sizeof(myPriv));
  rememberDmToken(token);
  char dmLabel[64];
  formatDmLabel(token, dmLabel, sizeof(dmLabel));
  printf(COLOR_YELLOW "[*] DM request sent to %s\n" COLOR_RESET, dmLabel);
}

static bool processInput(char *message) {
  if (!message[0])
    return true;

  if (strcmp(message, "/exit") == 0) {
    sendRawFrame("QUIT\n");
    return false;
  }
  if (strcmp(message, "/help") == 0) {
    print(
        "/name <name>\n"
        "/rooms\n"
        "/create <room>\n"
        "/create <room> -p <secret>\n"
        "/enter <room>\n"
        "/leave\n"
        "/dm <contact>\n"
        "/dmleave\n"
        "/list\n"
        "/search <query>\n"
        "/nick [@|contact] <name>\n"
        "/nick <contact> -\n"
        "/token\n"
        "/clear\n"
        "/exit\n");
    return true;
  }
  if (strncmp(message, "/name ", 6) == 0) {
    char name[MAX_NAME_LEN];
    if (sscanf(message + 6, "%63s", name) != 1 || !protocolIsSafeIdentifier(name)) {
      printMessage(COLOR_RED, "[!] ", "Invalid name\n");
      return true;
    }
    snprintf(g_username, sizeof(g_username), "%s", name);
    identitySaveUsername(name);
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "SET_NAME|%s\n", name);
    sendRawFrame(frame);
    return true;
  }
  if (strcmp(message, "/rooms") == 0) {
    sendRawFrame("ROOM_LIST\n");
    return true;
  }
  if (strncmp(message, "/create ", 8) == 0) {
    char room[MAX_NAME_LEN];
    char secret[256];
    if (strstr(message + 8, " -p ") != NULL) {
      if (sscanf(message + 8, "%63s -p %255s", room, secret) != 2) {
        printMessage(COLOR_RED, "[!] ", "Usage: /create <room> -p <secret>\n");
        return true;
      }
      char saltHex[ROOM_SALT_HEX_SIZE];
      char verifierHex[SHA256_HEX_SIZE];
      unsigned char roomKey[32];
      if (!createRoomSecrets(room, secret, saltHex, verifierHex, roomKey)) {
        printMessage(COLOR_RED, "[!] ", "Failed to create room secret material\n");
        return true;
      }
      char frame[MSG_SIZE];
      snprintf(frame, sizeof(frame), "ROOM_CREATE|%s|PROTECTED|%s|%s\n", room,
               saltHex, verifierHex);
      sendRawFrame(frame);
      return true;
    }

    if (sscanf(message + 8, "%63s", room) != 1) {
      printMessage(COLOR_RED, "[!] ", "Usage: /create <room>\n");
      return true;
    }
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "ROOM_CREATE|%s|OPEN\n", room);
    sendRawFrame(frame);
    return true;
  }
  if (strncmp(message, "/enter ", 7) == 0) {
    char room[MAX_NAME_LEN];
    if (sscanf(message + 7, "%63s", room) != 1) {
      printMessage(COLOR_RED, "[!] ", "Usage: /enter <room>\n");
      return true;
    }
    snprintf(g_room.pendingName, sizeof(g_room.pendingName), "%s", room);
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "ROOM_ENTER|%s\n", room);
    sendRawFrame(frame);
    return true;
  }
  if (strcmp(message, "/leave") == 0) {
    sendRawFrame("ROOM_LEAVE\n");
    return true;
  }
  if (strcmp(message, "/token") == 0) {
    handleTokenCommand();
    return true;
  }
  if (strcmp(message, "/list") == 0) {
    handleListCommand();
    return true;
  }
  if (strncmp(message, "/search ", 8) == 0) {
    char query[128];
    copyTrimmed(message + 8, query, sizeof(query));
    if (!query[0]) {
      printMessage(COLOR_RED, "[!] ", "Usage: /search <query>\n");
      return true;
    }
    handleSearchCommand(query);
    return true;
  }
  if (strcmp(message, "/dmleave") == 0) {
    clearDmSession();
    printMessage(COLOR_YELLOW, "[*] ", "DM session closed\n");
    return true;
  }
  if (strncmp(message, "/dm ", 4) == 0) {
    char target[128];
    copyTrimmed(message + 4, target, sizeof(target));
    if (!target[0]) {
      printMessage(COLOR_RED, "[!] ", "Usage: /dm <contact>\n");
      return true;
    }
    handleDmCommand(target);
    return true;
  }
  if (strncmp(message, "/nick ", 6) == 0) {
    const char *args = skipSpaces(message + 6);
    char first[128];
    const char *rest = NULL;
    if (!splitFirstArgument(args, first, sizeof(first), &rest) || !first[0]) {
      printMessage(COLOR_RED, "[!] ", "Usage: /nick [@|contact] <name>\n");
      return true;
    }

    if (strcmp(first, "@") == 0) {
      char nick[MAX_NAME_LEN];
      copyTrimmed(rest, nick, sizeof(nick));
      if (!nick[0]) {
        printMessage(COLOR_RED, "[!] ", "Usage: /nick @ <name>\n");
        return true;
      }
      handleNickCommand("@", nick);
      return true;
    }

    if (!g_dm.active) {
      if (!rest || !rest[0]) {
        printMessage(COLOR_RED, "[!] ", "Usage: /nick <contact> <name>\n");
        return true;
      }

      char nick[MAX_NAME_LEN];
      copyTrimmed(rest, nick, sizeof(nick));
      if (!nick[0]) {
        printMessage(COLOR_RED, "[!] ", "Usage: /nick <contact> <name>\n");
        return true;
      }
      handleNickCommand(first, nick);
      return true;
    }

    if (rest && rest[0] &&
        (isNumericReference(first) || isTokenHex(first))) {
      char probeToken[TOKEN_STR_SIZE];
      if (resolveDmReference(first, probeToken, sizeof(probeToken), true, false)) {
        char nick[MAX_NAME_LEN];
        copyTrimmed(rest, nick, sizeof(nick));
        if (!nick[0]) {
          printMessage(COLOR_RED, "[!] ", "Usage: /nick <contact> <name>\n");
          return true;
        }
        handleNickCommand(first, nick);
        return true;
      }
    }

    char nick[MAX_NAME_LEN];
    copyTrimmed(args, nick, sizeof(nick));
    if (!nick[0]) {
      printMessage(COLOR_RED, "[!] ", "Usage: /nick [@|contact] <name>\n");
      return true;
    }
    handleNickCommand("@", nick);
    return true;
  }
  if (strcmp(message, "/clear") == 0) {
    clearScreen();
    return true;
  }

  if (g_dm.active) {
    if (encryptAndSendDm(message)) {
      historyAppend(g_dm.peerToken, true, message);
      printTimestamped(g_username, message, COLOR_GREEN);
    }
    return true;
  }

  if (!g_room.active) {
    printMessage(COLOR_YELLOW, "[*] ", "Not in a room\n");
    return true;
  }

  if (encryptAndSendRoom(message))
    printTimestamped(g_username, message, COLOR_GREEN);
  return true;
}

static void inputLoop(void) {
  char normalBuf[MSG_SIZE] = {0};
  size_t normalLen = 0;
  printPrompt();

  while (true) {
    pthread_mutex_lock(&g_input.mutex);
    bool connected = g_input.connected;
    pthread_mutex_unlock(&g_input.mutex);
    if (!connected)
      break;

    char c;
    if (read(STDIN_FILENO, &c, 1) != 1)
      continue;

    pthread_mutex_lock(&g_input.mutex);
    bool readingRoomSecret = g_input.readingRoomSecret;
    pthread_mutex_unlock(&g_input.mutex);

    if (readingRoomSecret) {
      if (c == '\n' || c == '\r') {
        finalizeRoomSecretEntry();
        printPrompt();
      } else if ((c == 127 || c == 8) && g_input.roomSecretLen > 0) {
        g_input.roomSecret[--g_input.roomSecretLen] = '\0';
        printf("\b \b");
        fflush(stdout);
      } else if (isprint((unsigned char)c) && g_input.roomSecretLen < MSG_SIZE - 1) {
        g_input.roomSecret[g_input.roomSecretLen++] = c;
        g_input.roomSecret[g_input.roomSecretLen] = '\0';
        printf("*");
        fflush(stdout);
      }
      continue;
    }

    if (c == '\n' || c == '\r') {
      normalBuf[normalLen] = '\0';
      printf("\n");
      if (!processInput(normalBuf))
        break;

      normalLen = 0;
      normalBuf[0] = '\0';
      pthread_mutex_lock(&g_input.mutex);
      g_input.buffer[0] = '\0';
      g_input.length = 0;
      pthread_mutex_unlock(&g_input.mutex);
      printPrompt();
    } else if ((c == 127 || c == 8) && normalLen > 0) {
      normalBuf[--normalLen] = '\0';
      printf("\b \b");
      fflush(stdout);
      pthread_mutex_lock(&g_input.mutex);
      snprintf(g_input.buffer, sizeof(g_input.buffer), "%s", normalBuf);
      g_input.length = normalLen;
      pthread_mutex_unlock(&g_input.mutex);
    } else if (isprint((unsigned char)c) && normalLen < MSG_SIZE - 1) {
      normalBuf[normalLen++] = c;
      normalBuf[normalLen] = '\0';
      putchar(c);
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
  if (g_socketFD == INVALID_SOCKET_HANDLE)
    return false;

  struct addrinfo hints = {0};
  struct addrinfo *servinfo = NULL;
  char portStr[16];
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  snprintf(portStr, sizeof(portStr), "%d", port);
  if (getaddrinfo(ip, portStr, &hints, &servinfo) != 0 || !servinfo)
    return false;

  char resolvedIP[INET_ADDRSTRLEN];
  struct sockaddr_in *ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
  inet_ntop(AF_INET, &ipv4->sin_addr, resolvedIP, sizeof(resolvedIP));
  freeaddrinfo(servinfo);

  SocketAddress *address = createSocketAddress(resolvedIP, port, true);
  if (!address)
    return false;

  if (connectSocket(g_socketFD, address) != 0) {
    free(address);
    return false;
  }
  free(address);

  SSL_CTX *ctx = tlsClientCtxCreate();
  if (!ctx)
    return false;
  g_ssl = tlsClientConnect(ctx, g_socketFD);
  SSL_CTX_free(ctx);
  if (!g_ssl)
    return false;

  char serverLabel[128];
  snprintf(serverLabel, sizeof(serverLabel), "%s:%d", ip, port);
  if (!tlsTrustOnFirstUse(g_ssl, serverLabel)) {
    tlsFree(g_ssl);
    g_ssl = NULL;
    return false;
  }

  return true;
}

static bool authenticate(void) {
  char challengeBuf[MSG_SIZE];
  ssize_t n = tlsRecv(g_ssl, challengeBuf, sizeof(challengeBuf));
  if (n <= 0)
    return false;

  char *parts[PROTOCOL_MAX_PARTS] = {0};
  size_t partCount = protocolSplitFields(challengeBuf, parts, PROTOCOL_MAX_PARTS);
  if (partCount < 2 || strcmp(parts[0], "CHALLENGE") != 0 ||
      strlen(parts[1]) != CHALLENGE_HEX_LEN)
    return false;

  unsigned char nonce[CHALLENGE_BYTES];
  if (!hexToBytes(parts[1], nonce, sizeof(nonce)))
    return false;

  unsigned char sig[SIG_BYTES];
  if (!identitySign(&g_identity, nonce, sizeof(nonce), sig))
    return false;

  char sigHex[SIG_HEX_SIZE];
  bytesToHex(sig, sizeof(sig), sigHex);

  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "AUTH|%s|%s\n", g_identity.token, sigHex);
  if (!sendRawFrame(frame))
    return false;

  char ackBuf[MSG_SIZE];
  n = tlsRecv(g_ssl, ackBuf, sizeof(ackBuf));
  if (n <= 0)
    return false;

  partCount = protocolSplitFields(ackBuf, parts, PROTOCOL_MAX_PARTS);
  return partCount >= 2 && strcmp(parts[0], "OK") == 0 &&
         strcmp(parts[1], "AUTH") == 0;
}

int main(int argc, char *argv[]) {
  if (!platformInit()) {
    fprintf(stderr, "Failed to initialize networking\n");
    return 1;
  }

  tcgetattr(STDIN_FILENO, &g_origTermios);
  atexit(disableRawMode);
  enableRawMode();

  logOpen();
  if (!identityLoadOrCreate(&g_identity)) {
    fprintf(stderr, "Fatal: could not load or create identity\n");
    return 1;
  }

  if (identityLoadUsername(g_username, sizeof(g_username))) {
  } else {
    snprintf(g_username, sizeof(g_username), "%.8s", g_identity.token);
  }
  reloadDmHistoryIndex();

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

  if (!connectToServer(ip, port)) {
    fprintf(stderr, "Failed to connect to %s:%d\n", ip, port);
    return 1;
  }
  if (!authenticate()) {
    fprintf(stderr, "Authentication failed\n");
    return 1;
  }

  char nameFrame[MSG_SIZE];
  snprintf(nameFrame, sizeof(nameFrame), "SET_NAME|%s\n", g_username);
  sendRawFrame(nameFrame);

  pthread_t recvTid;
  if (pthread_create(&recvTid, NULL, receiveThread, NULL) != 0) {
    fprintf(stderr, "Failed to create receive thread\n");
    return 1;
  }

  clearScreen();
  print("SocketChat CLI (protocol v2, stronger E2E)\n");
  printf("Connected to " COLOR_GREEN "%s:%d\n" COLOR_RESET, ip, port);
  printf("Your token:   " COLOR_GREEN "%s\n" COLOR_RESET, g_identity.token);
  print("Type /help to view commands\n\n");

  inputLoop();
  if (g_socketFD != INVALID_SOCKET_HANDLE)
    platformShutdownSocket(g_socketFD);
  pthread_join(recvTid, NULL);

  if (g_ssl)
    tlsFree(g_ssl);
  if (g_socketFD != INVALID_SOCKET_HANDLE)
    platformCloseSocket(g_socketFD);
  pthread_mutex_destroy(&g_input.mutex);
  if (g_logFile)
    fclose(g_logFile);
  platformCleanup();
  return 0;
}
