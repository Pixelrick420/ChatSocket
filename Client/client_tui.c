#include "../Utils/aes.h"
#include "../Utils/ecdh.h"
#include "../Utils/history.h"
#include "../Utils/identity.h"
#include "../Utils/protocol.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>

#if defined(__GNUC__) || defined(__clang__)
#define PRINTF_FMT(fmtIndex, firstArg) __attribute__((format(printf, fmtIndex, firstArg)))
#else
#define PRINTF_FMT(fmtIndex, firstArg)
#endif

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 2077
#define MAX_MESSAGES 1000
#define SIDEBAR_WIDTH 34
#define UI_RENDER_LINES 256
#define UI_RENDER_LINE_MAX 512

typedef enum {
  UI_MSG_CHAT,
  UI_MSG_INFO,
  UI_MSG_ERROR,
  UI_MSG_SELF
} UiMessageTone;

typedef struct {
  char text[MSG_SIZE * 2];
  UiMessageTone tone;
} UiMessage;

typedef struct {
  int panelR;
  int panelG;
  int panelB;
  int borderR;
  int borderG;
  int borderB;
  int accentR;
  int accentG;
  int accentB;
  int mutedR;
  int mutedG;
  int mutedB;
} UiTheme;

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
  bool connected;
  bool readingRoomSecret;
  char roomSecret[MSG_SIZE];
  size_t roomSecretLen;
} InputState;

static FILE *g_logFile = NULL;
static char g_logPath[512] = {0};
static char g_serverLabel[128] = "offline";
static SocketHandle g_socketFD = INVALID_SOCKET_HANDLE;
static SSL *g_ssl = NULL;
static Identity g_identity = {0};
static char g_username[MAX_NAME_LEN] = {0};
static RoomState g_room = {0};
static DmSession g_dm = {0};
static struct termios g_origTermios;
static pthread_mutex_t g_stateMutex = PTHREAD_MUTEX_INITIALIZER;
static InputState g_input = {
    .buffer = {0},
    .length = 0,
    .connected = true,
    .readingRoomSecret = false,
    .roomSecret = {0},
    .roomSecretLen = 0,
};

static UiMessage g_messages[MAX_MESSAGES];
static int g_messageCount = 0;
static int g_messageScroll = 0;
static bool g_showHelp = false;
static bool g_roomsLoading = false;
static char g_rooms[50][MAX_NAME_LEN] = {{0}};
static char g_roomTypes[50][16] = {{0}};
static int g_roomCount = 0;
static char g_dmList[MAX_DM_NICKS][TOKEN_STR_SIZE] = {{0}};
static char g_dmNick[MAX_DM_NICKS][MAX_NAME_LEN] = {{0}};
static int g_dmCount = 0;
static int g_cursorRow = 1;
static int g_cursorCol = 1;
static bool g_cursorVisible = false;

static void clientLog(const char *fmt, ...) PRINTF_FMT(1, 2);
static void addMessage(UiMessageTone tone, const char *fmt, ...)
    PRINTF_FMT(2, 3);

static const char *UI_RESET = "\033[0m";
static const char *UI_HIDE_CURSOR = "\033[?25l";
static const char *UI_SHOW_CURSOR = "\033[?25h";
static const char *UI_ALT_ON = "\033[?1049h";
static const char *UI_ALT_OFF = "\033[?1049l";
static const UiTheme UI_THEME_ACTIVITY = {22, 26, 34, 62, 96, 136, 166, 204, 255,
                                          122, 144, 170};
static const UiTheme UI_THEME_NAV = {30, 24, 20, 129, 95, 45, 239, 196, 106,
                                     161, 139, 112};
static const UiTheme UI_THEME_INPUT = {20, 28, 28, 48, 113, 104, 144, 224, 203,
                                       122, 150, 147};
static const UiTheme UI_THEME_HELP = {30, 24, 36, 116, 92, 152, 219, 198, 255,
                                      150, 138, 172};

static void logOpen(void) {
  char configDir[512];
  if (!platformGetConfigDir(configDir, sizeof(configDir)))
    return;
  if (!platformEnsureDir(configDir))
    return;

  pid_t pid = getpid();
  snprintf(g_logPath, sizeof(g_logPath), "%s%ctui_%d.log", configDir,
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
  raw.c_cc[VMIN] = 0;
  raw.c_cc[VTIME] = 1;
  tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

static void uiMove(int row, int col) { printf("\033[%d;%dH", row, col); }

static void uiRgbFg(int r, int g, int b) {
  printf("\033[38;2;%d;%d;%dm", r, g, b);
}

static void uiRgbBg(int r, int g, int b) {
  printf("\033[48;2;%d;%d;%dm", r, g, b);
}

static void uiClearScreen(void) { print("\033[2J"); }

static void uiFillLine(int row, int cols, int r, int g, int b) {
  uiMove(row, 1);
  uiRgbBg(r, g, b);
  for (int i = 0; i < cols; i++)
    putchar(' ');
  print(UI_RESET);
}

static void uiDrawText(int row, int col, int fgR, int fgG, int fgB, int bgR,
                       int bgG, int bgB, const char *text) {
  uiMove(row, col);
  uiRgbBg(bgR, bgG, bgB);
  uiRgbFg(fgR, fgG, fgB);
  fputs(text, stdout);
  print(UI_RESET);
}

static void uiDrawTextRight(int row, int rightCol, int fgR, int fgG, int fgB,
                            int bgR, int bgG, int bgB, const char *text) {
  int width = (int)strlen(text);
  int start = rightCol - width + 1;
  if (start < 1)
    start = 1;
  uiDrawText(row, start, fgR, fgG, fgB, bgR, bgG, bgB, text);
}

static int clampInt(int value, int minValue, int maxValue) {
  if (value < minValue)
    return minValue;
  if (value > maxValue)
    return maxValue;
  return value;
}

static void uiDrawSectionLabel(int row, int col, int width, const char *title,
                               const char *value, const UiTheme *theme) {
  char line[128];
  if (value && value[0]) {
    snprintf(line, sizeof(line), "%s %s", title, value);
  } else {
    snprintf(line, sizeof(line), "%s", title);
  }
  char padded[128];
  snprintf(padded, sizeof(padded), "%-*.*s", width, width, line);
  uiDrawText(row, col, theme->accentR, theme->accentG, theme->accentB,
             theme->panelR, theme->panelG, theme->panelB, padded);
}

static void uiDrawBox(int x, int y, int w, int h, const char *title,
                      const UiTheme *theme) {
  if (w < 4 || h < 3)
    return;

  for (int row = 0; row < h; row++) {
    uiMove(y + row, x);
    uiRgbBg(theme->panelR, theme->panelG, theme->panelB);
    uiRgbFg(theme->borderR, theme->borderG, theme->borderB);
    if (row == 0) {
      putchar('+');
      for (int i = 0; i < w - 2; i++)
        putchar('-');
      putchar('+');
    } else if (row == h - 1) {
      putchar('+');
      for (int i = 0; i < w - 2; i++)
        putchar('-');
      putchar('+');
    } else {
      putchar('|');
      for (int i = 0; i < w - 2; i++)
        putchar(' ');
      putchar('|');
    }
    print(UI_RESET);
  }

  if (title && title[0] && w > 6) {
    char titleBuf[128];
    snprintf(titleBuf, sizeof(titleBuf), " %s ", title);
    uiDrawText(y, x + 2, theme->accentR, theme->accentG, theme->accentB,
               theme->panelR, theme->panelG, theme->panelB, titleBuf);
  }
}

static void uiGetSize(int *rows, int *cols) {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 &&
      ws.ws_col > 0) {
    *rows = ws.ws_row;
    *cols = ws.ws_col;
  } else {
    *rows = 30;
    *cols = 120;
  }
}

static void uiEnter(void) {
  print(UI_ALT_ON);
  uiClearScreen();
}

static void uiExit(void) {
  print(UI_RESET);
  print(UI_SHOW_CURSOR);
  print(UI_ALT_OFF);
}

static void uiSetCursor(int row, int col) {
  g_cursorRow = row;
  g_cursorCol = col;
  g_cursorVisible = true;
}

static void addMessage(UiMessageTone tone, const char *fmt, ...) {
  if (g_messageCount == MAX_MESSAGES) {
    memmove(&g_messages[0], &g_messages[1], sizeof(g_messages[0]) * (MAX_MESSAGES - 1));
    g_messageCount--;
  }

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(g_messages[g_messageCount].text, sizeof(g_messages[g_messageCount].text),
            fmt, ap);
  va_end(ap);
  g_messages[g_messageCount].tone = tone;
  g_messageCount++;
}

static void addTimestamped(UiMessageTone tone, const char *label,
                           const char *message) {
  time_t now = time(NULL);
  struct tm tmInfo;
  char ts[16] = "00:00";
  if (platformLocalTime(now, &tmInfo))
    strftime(ts, sizeof(ts), "%H:%M", &tmInfo);

  if (label && label[0])
    addMessage(tone, "[%s] %s: %s", ts, label, message);
  else
    addMessage(tone, "[%s] %s", ts, message);
}

static void clearRoomState(void) {
  memset(&g_room, 0, sizeof(g_room));
}

static void clearDmSession(void) {
  memset(&g_dm, 0, sizeof(g_dm));
}

static void reloadDmNicknames(void) {
  memset(g_dmNick, 0, sizeof(g_dmNick));
  DmNickEntry entries[MAX_DM_NICKS];
  size_t count = identityLoadDmNickEntries(entries, MAX_DM_NICKS);
  for (size_t i = 0; i < count; i++) {
    for (int j = 0; j < g_dmCount; j++) {
      if (strcmp(g_dmList[j], entries[i].token) == 0) {
        snprintf(g_dmNick[j], sizeof(g_dmNick[j]), "%s", entries[i].nick);
        break;
      }
    }
  }
}

static void reloadDmHistoryIndex(void) {
  g_dmCount = historyGetAll(g_dmList);
  reloadDmNicknames();
}

static void saveDmNicknames(void) {
  DmNickEntry entries[MAX_DM_NICKS];
  size_t count = 0;
  for (int i = 0; i < g_dmCount && count < MAX_DM_NICKS; i++) {
    if (!g_dmList[i][0] || !g_dmNick[i][0])
      continue;
    snprintf(entries[count].token, sizeof(entries[count].token), "%s", g_dmList[i]);
    snprintf(entries[count].nick, sizeof(entries[count].nick), "%s", g_dmNick[i]);
    count++;
  }
  identitySaveDmNickEntries(entries, count);
}

static void rememberDmToken(const char *token) {
  for (int i = 0; i < g_dmCount; i++) {
    if (strcmp(g_dmList[i], token) == 0)
      return;
  }
  if (g_dmCount < MAX_DM_NICKS) {
    snprintf(g_dmList[g_dmCount], sizeof(g_dmList[g_dmCount]), "%s", token);
    g_dmCount++;
  }
}

static int findDmByToken(const char *token) {
  if (!token || !token[0])
    return -1;

  for (int i = 0; i < g_dmCount; i++) {
    if (strcmp(g_dmList[i], token) == 0)
      return i;
  }
  return -1;
}

static void formatDmLabel(const char *token, char *out, size_t outSize) {
  if (!out || outSize == 0) {
    return;
  }

  int idx = findDmByToken(token);
  if (idx >= 0 && g_dmNick[idx][0]) {
    snprintf(out, outSize, "%s", g_dmNick[idx]);
    return;
  }

  if (token && token[0]) {
    snprintf(out, outSize, "%.12s", token);
    return;
  }

  snprintf(out, outSize, "none");
}

static void formatContextLabel(char *out, size_t outSize) {
  if (!out || outSize == 0)
    return;

  if (g_input.readingRoomSecret) {
    snprintf(out, outSize, "Unlock #%s", g_room.pendingName[0] ? g_room.pendingName : "room");
    return;
  }

  if (g_dm.active) {
    char dmLabel[64];
    formatDmLabel(g_dm.peerToken, dmLabel, sizeof(dmLabel));
    snprintf(out, outSize, "DM %s", dmLabel);
    return;
  }

  if (g_room.active) {
    snprintf(out, outSize, "#%s", g_room.currentName);
    return;
  }

  snprintf(out, outSize, "Lobby");
}

static void formatSecurityLabel(char *out, size_t outSize) {
  if (!out || outSize == 0)
    return;

  if (g_dm.active) {
    snprintf(out, outSize, "E2E DM");
  } else if (g_room.active && g_room.protectedRoom) {
    snprintf(out, outSize, "E2E ROOM");
  } else if (g_room.active) {
    snprintf(out, outSize, "OPEN ROOM");
  } else {
    snprintf(out, outSize, "PINNED TLS");
  }
}

static int wrapTextToWidth(const char *text, int width,
                           char out[][UI_RENDER_LINE_MAX], int maxLines) {
  if (!text || !text[0] || width <= 0 || maxLines <= 0)
    return 0;

  int count = 0;
  const char *cursor = text;

  while (*cursor && count < maxLines) {
    while (*cursor == ' ')
      cursor++;

    if (*cursor == '\n') {
      out[count][0] = '\0';
      count++;
      cursor++;
      continue;
    }

    int consumed = 0;
    int split = -1;
    while (cursor[consumed] && cursor[consumed] != '\n' && consumed < width) {
      if (cursor[consumed] == ' ')
        split = consumed;
      consumed++;
    }

    if (!cursor[consumed] || cursor[consumed] == '\n') {
      int len = consumed;
      while (len > 0 && cursor[len - 1] == ' ')
        len--;
      snprintf(out[count], UI_RENDER_LINE_MAX, "%.*s", len, cursor);
      count++;
      cursor += consumed;
      if (*cursor == '\n')
        cursor++;
      continue;
    }

    int len = (split > 0) ? split : consumed;
    while (len > 0 && cursor[len - 1] == ' ')
      len--;
    snprintf(out[count], UI_RENDER_LINE_MAX, "%.*s", len, cursor);
    count++;
    cursor += (split > 0) ? split + 1 : consumed;
  }

  return count;
}

static int findDmByReference(const char *input) {
  if (!input || !input[0])
    return -1;

  for (int i = 0; i < g_dmCount; i++) {
    if (g_dmNick[i][0] && strcmp(g_dmNick[i], input) == 0)
      return i;
  }
  for (int i = 0; i < g_dmCount; i++) {
    if (strncmp(g_dmList[i], input, strlen(input)) == 0)
      return i;
  }
  return -1;
}

static bool sendRawFrame(const char *frame) {
  pthread_mutex_lock(&g_stateMutex);
  bool connected = g_input.connected;
  pthread_mutex_unlock(&g_stateMutex);
  if (!connected)
    return false;

  clientLog("send: %.160s", frame);
  return tlsSend(g_ssl, frame, strlen(frame));
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
  char payload[MSG_SIZE * 2];
  if (!g_room.protectedRoom) {
    if (!protocolEncodeText(message, payload, sizeof(payload)))
      return false;
  } else {
    unsigned char ciphertext[MSG_SIZE];
    int clen = encryptMessage((const unsigned char *)message, strlen(message),
                              g_room.key, ciphertext);
    if (clen <= 0)
      return false;
    encodeBase64(ciphertext, (size_t)clen, payload);
  }

  char frame[MSG_SIZE * 2 + 32];
  snprintf(frame, sizeof(frame), "ROOM_SEND|%s\n", payload);
  return sendRawFrame(frame);
}

static bool encryptAndSendDm(const char *message) {
  unsigned char ciphertext[MSG_SIZE];
  int clen = encryptMessage((const unsigned char *)message, strlen(message),
                            g_dm.key, ciphertext);
  if (clen <= 0)
    return false;

  char payload[MSG_SIZE * 2];
  encodeBase64(ciphertext, (size_t)clen, payload);
  char frame[MSG_SIZE * 2 + TOKEN_STR_SIZE + 32];
  snprintf(frame, sizeof(frame), "DM_SEND|%s|%s\n", g_dm.peerToken, payload);
  return sendRawFrame(frame);
}

static void showRoomMessage(const char *sender, const char *payload) {
  char text[MSG_SIZE];
  if (!g_room.protectedRoom) {
    if (!protocolDecodeText(payload, text, sizeof(text))) {
      addMessage(UI_MSG_ERROR, "[!] Failed to decode room payload");
      return;
    }
  } else {
    unsigned char decoded[MSG_SIZE];
    int dlen = decodeBase64(payload, decoded);
    if (dlen <= 0) {
      addMessage(UI_MSG_ERROR, "[!] Failed to decode encrypted room payload");
      return;
    }
    unsigned char decrypted[MSG_SIZE];
    int plen = decryptMessage(decoded, (size_t)dlen, g_room.key, decrypted);
    if (plen <= 0) {
      addMessage(UI_MSG_ERROR, "[!] Failed to decrypt room payload");
      return;
    }
    decrypted[plen] = '\0';
    snprintf(text, sizeof(text), "%s", (char *)decrypted);
  }
  addTimestamped(UI_MSG_CHAT, sender, text);
}

static void showDmMessage(const char *senderToken, const char *payload) {
  if (!g_dm.active || strcmp(g_dm.peerToken, senderToken) != 0) {
    addMessage(UI_MSG_INFO, "[*] Received a DM for an inactive session");
    return;
  }

  unsigned char decoded[MSG_SIZE];
  int dlen = decodeBase64(payload, decoded);
  if (dlen <= 0) {
    addMessage(UI_MSG_ERROR, "[!] Failed to decode DM payload");
    return;
  }

  unsigned char decrypted[MSG_SIZE];
  int plen = decryptMessage(decoded, (size_t)dlen, g_dm.key, decrypted);
  if (plen <= 0) {
    addMessage(UI_MSG_ERROR, "[!] Failed to decrypt DM payload");
    return;
  }

  decrypted[plen] = '\0';
  historyAppend(senderToken, false, (char *)decrypted);
  rememberDmToken(senderToken);
  char dmLabel[64];
  formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
  addTimestamped(UI_MSG_CHAT, dmLabel, (char *)decrypted);
}

static void finalizeRoomSecretEntry(void) {
  char verifier[SHA256_HEX_SIZE];
  if (!verifyRoomSecret(g_room.pendingName, g_input.roomSecret, g_room.pendingSalt,
                        verifier, g_room.pendingKey)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to derive room secret");
  } else {
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "ROOM_PROOF|%s|%s\n", g_room.pendingName,
             verifier);
    sendRawFrame(frame);
  }

  memset(g_input.roomSecret, 0, sizeof(g_input.roomSecret));
  g_input.roomSecretLen = 0;
  g_input.readingRoomSecret = false;
}

static void handleDmInit(const char *senderToken, const char *peerPubHex,
                         const char *sigHex) {
  if (strlen(senderToken) != TOKEN_HEX_LEN || strlen(peerPubHex) != 64 ||
      strlen(sigHex) != SIG_HEX_LEN) {
    addMessage(UI_MSG_ERROR, "[!] Malformed DM_INIT frame");
    return;
  }

  unsigned char sig[SIG_BYTES];
  unsigned char peerPub[32];
  if (!hexToBytes(sigHex, sig, sizeof(sig)) ||
      !hexToBytes(peerPubHex, peerPub, sizeof(peerPub))) {
    addMessage(UI_MSG_ERROR, "[!] Invalid DM_INIT encoding");
    return;
  }
  if (!verifyDmFrame("DM_INIT", senderToken, g_identity.token, peerPubHex, sig)) {
    addMessage(UI_MSG_ERROR, "[!] DM_INIT signature verification failed");
    return;
  }

  unsigned char myPub[32];
  unsigned char myPriv[32];
  if (!x25519GenerateKeypair(myPub, myPriv)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to generate DM session keys");
    return;
  }

  unsigned char sessionKey[32];
  if (!ecdhDeriveSessionKey(myPriv, peerPub, senderToken, g_identity.token,
                            peerPub, myPub, sessionKey)) {
    memset(myPriv, 0, sizeof(myPriv));
    addMessage(UI_MSG_ERROR, "[!] Failed to derive DM session key");
    return;
  }

  char myPubHex[65];
  bytesToHex(myPub, sizeof(myPub), myPubHex);
  unsigned char ackSig[SIG_BYTES];
  if (!signDmFrame("DM_ACK", g_identity.token, senderToken, myPubHex, ackSig)) {
    memset(myPriv, 0, sizeof(myPriv));
    addMessage(UI_MSG_ERROR, "[!] Failed to sign DM acknowledgment");
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
  memset(myPriv, 0, sizeof(myPriv));
  rememberDmToken(senderToken);
  addMessage(UI_MSG_INFO, "[*] DM session established");
}

static void handleDmAck(const char *senderToken, const char *peerPubHex,
                        const char *sigHex) {
  if (!g_dm.awaitingAck || strcmp(g_dm.peerToken, senderToken) != 0)
    return;

  unsigned char sig[SIG_BYTES];
  unsigned char peerPub[32];
  if (!hexToBytes(sigHex, sig, sizeof(sig)) ||
      !hexToBytes(peerPubHex, peerPub, sizeof(peerPub))) {
    addMessage(UI_MSG_ERROR, "[!] Invalid DM_ACK encoding");
    return;
  }

  if (!verifyDmFrame("DM_ACK", senderToken, g_identity.token, peerPubHex, sig)) {
    addMessage(UI_MSG_ERROR, "[!] DM_ACK signature verification failed");
    return;
  }

  unsigned char sessionKey[32];
  if (!ecdhDeriveSessionKey(g_dm.pendingPriv, peerPub, g_identity.token,
                            senderToken, g_dm.pendingPub, peerPub, sessionKey)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to derive DM session key");
    return;
  }

  g_dm.active = true;
  g_dm.awaitingAck = false;
  memcpy(g_dm.key, sessionKey, sizeof(sessionKey));
  memset(g_dm.pendingPriv, 0, sizeof(g_dm.pendingPriv));
  memset(g_dm.pendingPub, 0, sizeof(g_dm.pendingPub));
  rememberDmToken(senderToken);
  addMessage(UI_MSG_INFO, "[*] DM session ready");
}

static void displayIncomingMessage(char *buffer) {
  char *parts[PROTOCOL_MAX_PARTS] = {0};
  size_t partCount = protocolSplitFields(buffer, parts, PROTOCOL_MAX_PARTS);
  if (partCount == 0)
    return;

  clientLog("recv: %.160s", buffer);

  if (strcmp(parts[0], "ERR") == 0 && partCount >= 2) {
    addMessage(UI_MSG_ERROR, "[!] %s", parts[1]);
  } else if (strcmp(parts[0], "OK") == 0 && partCount >= 2) {
    if (strcmp(parts[1], "ROOM_ENTERED") == 0 && partCount >= 3) {
      g_room.active = true;
      snprintf(g_room.currentName, sizeof(g_room.currentName), "%s",
               g_room.pendingName);
      g_room.protectedRoom = strcmp(parts[2], "PROTECTED") == 0;
      if (g_room.protectedRoom)
        memcpy(g_room.key, g_room.pendingKey, sizeof(g_room.key));
      addMessage(UI_MSG_INFO, "[*] Entered room %s", g_room.currentName);
    } else if (strcmp(parts[1], "ROOM_LEFT") == 0) {
      clearRoomState();
      addMessage(UI_MSG_INFO, "[*] Left room");
    } else if (strcmp(parts[1], "ROOM_CREATED") == 0) {
      addMessage(UI_MSG_INFO, "[*] Room created");
    } else if (strcmp(parts[1], "NAME_SET") == 0) {
      addMessage(UI_MSG_INFO, "[*] Name updated");
    }
  } else if (strcmp(parts[0], "INFO") == 0 && partCount >= 2) {
    if (strcmp(parts[1], "ROOMS_BEGIN") == 0) {
      g_roomCount = 0;
      g_roomsLoading = true;
      addMessage(UI_MSG_INFO, "[*] Refreshing rooms");
    } else if (strcmp(parts[1], "ROOM") == 0 && partCount >= 4) {
      if (g_roomCount < 50) {
        snprintf(g_rooms[g_roomCount], sizeof(g_rooms[g_roomCount]), "%s", parts[2]);
        snprintf(g_roomTypes[g_roomCount], sizeof(g_roomTypes[g_roomCount]), "%s",
                 parts[3]);
        g_roomCount++;
      }
    } else if (strcmp(parts[1], "ROOMS_END") == 0) {
      g_roomsLoading = false;
    } else if (strcmp(parts[1], "ROOM_JOINED") == 0 && partCount >= 3) {
      addMessage(UI_MSG_INFO, "[*] %s joined the room", parts[2]);
    } else if (strcmp(parts[1], "ROOM_LEFT") == 0 && partCount >= 3) {
      addMessage(UI_MSG_INFO, "[*] %s left the room", parts[2]);
    } else if (strcmp(parts[1], "NAME_CHANGED") == 0 && partCount >= 4) {
      addMessage(UI_MSG_INFO, "[*] %s is now %s", parts[2], parts[3]);
    }
  } else if (strcmp(parts[0], "ROOM_CHALLENGE") == 0 && partCount >= 3) {
    snprintf(g_room.pendingName, sizeof(g_room.pendingName), "%s", parts[1]);
    snprintf(g_room.pendingSalt, sizeof(g_room.pendingSalt), "%s", parts[2]);
    g_input.readingRoomSecret = true;
    g_input.roomSecret[0] = '\0';
    g_input.roomSecretLen = 0;
    addMessage(UI_MSG_INFO, "[*] Enter the room secret below");
  } else if (strcmp(parts[0], "ROOM_MSG") == 0 && partCount >= 3) {
    showRoomMessage(parts[1], parts[2]);
  } else if (strcmp(parts[0], "DM_INIT") == 0 && partCount >= 4) {
    handleDmInit(parts[1], parts[2], parts[3]);
  } else if (strcmp(parts[0], "DM_ACK") == 0 && partCount >= 4) {
    handleDmAck(parts[1], parts[2], parts[3]);
  } else if (strcmp(parts[0], "DM_MSG") == 0 && partCount >= 3) {
    showDmMessage(parts[1], parts[2]);
  } else {
    addMessage(UI_MSG_ERROR, "[!] Unknown frame from server");
  }
}

static void handleDisconnect(void) {
  pthread_mutex_lock(&g_stateMutex);
  g_input.connected = false;
  addMessage(UI_MSG_ERROR, "[!] Disconnected from server");
  pthread_mutex_unlock(&g_stateMutex);
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
    pthread_mutex_lock(&g_stateMutex);
    displayIncomingMessage(buffer);
    pthread_mutex_unlock(&g_stateMutex);
  }
  return NULL;
}

static void uiDrawMessages(int x, int y, int w, int h) {
  const UiTheme *theme = &UI_THEME_ACTIVITY;
  int visible = h - 2;
  int contentW = w - 4;
  if (visible <= 0 || contentW <= 0)
    return;

  int totalLines = 0;
  char wrapped[64][UI_RENDER_LINE_MAX];
  for (int i = 0; i < g_messageCount; i++) {
    int wrappedCount = wrapTextToWidth(g_messages[i].text, contentW, wrapped,
                                       (int)(sizeof(wrapped) / sizeof(wrapped[0])));
    totalLines += (wrappedCount > 0) ? wrappedCount : 1;
  }

  int maxScroll = totalLines > visible ? totalLines - visible : 0;
  if (g_messageScroll > maxScroll)
    g_messageScroll = maxScroll;
  if (g_messageScroll < 0)
    g_messageScroll = 0;

  char rendered[UI_RENDER_LINES][UI_RENDER_LINE_MAX];
  UiMessageTone tones[UI_RENDER_LINES];
  for (int row = 0; row < visible && row < UI_RENDER_LINES; row++) {
    rendered[row][0] = '\0';
    tones[row] = UI_MSG_CHAT;
  }

  int skip = g_messageScroll;
  int filled = 0;
  for (int msg = g_messageCount - 1; msg >= 0 && filled < visible; msg--) {
    int wrappedCount = wrapTextToWidth(g_messages[msg].text, contentW, wrapped,
                                       (int)(sizeof(wrapped) / sizeof(wrapped[0])));
    if (wrappedCount == 0) {
      snprintf(wrapped[0], sizeof(wrapped[0]), "%s", "");
      wrappedCount = 1;
    }

    for (int part = wrappedCount - 1; part >= 0 && filled < visible; part--) {
      if (skip > 0) {
        skip--;
        continue;
      }
      int slot = visible - 1 - filled;
      if (slot >= 0 && slot < UI_RENDER_LINES) {
        snprintf(rendered[slot], sizeof(rendered[slot]), "%s", wrapped[part]);
        tones[slot] = g_messages[msg].tone;
      }
      filled++;
    }
  }

  if (filled == 0) {
    snprintf(rendered[visible / 2], sizeof(rendered[visible / 2]),
             "No activity yet. Join a room or start a DM.");
    tones[visible / 2] = UI_MSG_INFO;
  }

  for (int row = 0; row < visible; row++) {
    int fgR = 191, fgG = 203, fgB = 214;
    switch (tones[row]) {
    case UI_MSG_INFO:
      fgR = 233; fgG = 196; fgB = 106;
      break;
    case UI_MSG_ERROR:
      fgR = 239; fgG = 108; fgB = 96;
      break;
    case UI_MSG_SELF:
      fgR = 152; fgG = 195; fgB = 121;
      break;
    case UI_MSG_CHAT:
    default:
      fgR = 191; fgG = 203; fgB = 214;
      break;
    }

    char padded[UI_RENDER_LINE_MAX];
    snprintf(padded, sizeof(padded), "%-*.*s", contentW, contentW, rendered[row]);
    uiDrawText(y + 1 + row, x + 2, fgR, fgG, fgB, theme->panelR, theme->panelG,
               theme->panelB, padded);
  }
}

static void uiDrawSidebar(int x, int y, int w, int h) {
  const UiTheme *theme = &UI_THEME_NAV;
  int contentW = w - 4;
  int row = y + 1;
  int endRow = y + h - 1;

  char context[64];
  char security[64];
  formatContextLabel(context, sizeof(context));
  formatSecurityLabel(security, sizeof(security));

  uiDrawSectionLabel(row++, x + 2, contentW, "SESSION", NULL, theme);
  if (row < endRow) {
    char line[128];
    snprintf(line, sizeof(line), "you    %s", g_username);
    uiDrawText(row++, x + 2, 223, 228, 231, theme->panelR, theme->panelG,
               theme->panelB, line);
  }
  if (row < endRow) {
    char line[128];
    snprintf(line, sizeof(line), "space  %s", context);
    uiDrawText(row++, x + 2, 223, 228, 231, theme->panelR, theme->panelG,
               theme->panelB, line);
  }
  if (row < endRow) {
    char line[128];
    snprintf(line, sizeof(line), "lock   %s", security);
    uiDrawText(row++, x + 2, theme->accentR, theme->accentG, theme->accentB,
               theme->panelR, theme->panelG, theme->panelB, line);
  }
  if (row < endRow) {
    char line[128];
    snprintf(line, sizeof(line), "relay  %.20s", g_serverLabel);
    uiDrawText(row++, x + 2, theme->mutedR, theme->mutedG, theme->mutedB,
               theme->panelR, theme->panelG, theme->panelB, line);
  }

  if (row < endRow)
    row++;

  char roomsCount[32];
  snprintf(roomsCount, sizeof(roomsCount), "(%d)", g_roomCount);
  if (row < endRow)
    uiDrawSectionLabel(row++, x + 2, contentW, "ROOMS", roomsCount, theme);
  if (g_roomCount == 0 && row < endRow) {
    uiDrawText(row++, x + 2, theme->mutedR, theme->mutedG, theme->mutedB,
               theme->panelR, theme->panelG, theme->panelB,
               "No rooms cached yet");
  }
  for (int i = 0; i < g_roomCount && row < endRow; i++) {
    char line[128];
    const char marker =
        strcmp(g_rooms[i], g_room.currentName) == 0 ? '>' : ' ';
    const char *roomType =
        strcmp(g_roomTypes[i], "PROTECTED") == 0 ? "locked" : "open";
    snprintf(line, sizeof(line), "%c %-14.14s %-6s", marker, g_rooms[i], roomType);
    uiDrawText(row++, x + 2,
               marker == '>' ? 246 : 223, marker == '>' ? 214 : 228,
               marker == '>' ? 133 : 231, theme->panelR, theme->panelG,
               theme->panelB, line);
  }

  if (row < endRow)
    row++;

  char dmCountText[32];
  snprintf(dmCountText, sizeof(dmCountText), "(%d)", g_dmCount);
  if (row < endRow)
    uiDrawSectionLabel(row++, x + 2, contentW, "DIRECT", dmCountText, theme);
  if (g_dmCount == 0 && row < endRow) {
    uiDrawText(row++, x + 2, theme->mutedR, theme->mutedG, theme->mutedB,
               theme->panelR, theme->panelG, theme->panelB,
               "No DM history yet");
  }
  for (int i = 0; i < g_dmCount && row < endRow; i++) {
    char dmLabel[64];
    formatDmLabel(g_dmList[i], dmLabel, sizeof(dmLabel));
    char line[128];
    snprintf(line, sizeof(line), "%c %-20.20s",
             strcmp(g_dmList[i], g_dm.peerToken) == 0 ? '>' : ' ', dmLabel);
    uiDrawText(row++, x + 2,
               strcmp(g_dmList[i], g_dm.peerToken) == 0 ? 144 : 223,
               strcmp(g_dmList[i], g_dm.peerToken) == 0 ? 224 : 228,
               strcmp(g_dmList[i], g_dm.peerToken) == 0 ? 203 : 231,
               theme->panelR, theme->panelG, theme->panelB, line);
  }
}

static void uiDrawInput(int x, int y, int w, int h) {
  const UiTheme *theme = &UI_THEME_INPUT;
  if (h < 4)
    return;

  int contentW = w - 4;
  int textW = w - 7;
  if (contentW <= 0 || textW <= 0)
    return;

  char prompt[96];
  char note[160];
  char meta[64];
  if (g_input.readingRoomSecret) {
    snprintf(prompt, sizeof(prompt), "secret for #%s",
             g_room.pendingName[0] ? g_room.pendingName : "room");
    snprintf(meta, sizeof(meta), "verifier only");
    snprintf(note, sizeof(note),
             "Local masking stays on while you type.");
  } else if (g_dm.active) {
    char dmLabel[64];
    formatDmLabel(g_dm.peerToken, dmLabel, sizeof(dmLabel));
    snprintf(prompt, sizeof(prompt), "direct to %s", dmLabel);
    snprintf(meta, sizeof(meta), "dm e2e");
    snprintf(note, sizeof(note), "Handshake is live. /dmleave exits the session.");
  } else if (g_room.active) {
    snprintf(prompt, sizeof(prompt), "room #%s", g_room.currentName);
    snprintf(meta, sizeof(meta), "%s",
             g_room.protectedRoom ? "room e2e" : "relay-visible");
    snprintf(note, sizeof(note), "%s",
             g_room.protectedRoom
                 ? "Messages encrypt before they leave this terminal."
                 : "This room is not end-to-end encrypted.");
  } else {
    snprintf(prompt, sizeof(prompt), "lobby");
    snprintf(meta, sizeof(meta), "commands");
    snprintf(note, sizeof(note), "Use /rooms, /enter, /create, /dm, or /help.");
  }

  char countText[32];
  size_t currentLen =
      g_input.readingRoomSecret ? g_input.roomSecretLen : g_input.length;
  snprintf(countText, sizeof(countText), "%s  %zu/%d", meta, currentLen,
           MSG_SIZE - 1);

  char promptLine[UI_RENDER_LINE_MAX];
  snprintf(promptLine, sizeof(promptLine), "%-*.*s", contentW, contentW, prompt);
  uiDrawText(y + 1, x + 2, theme->accentR, theme->accentG, theme->accentB,
             theme->panelR, theme->panelG, theme->panelB, promptLine);
  uiDrawTextRight(y + 1, x + w - 3, theme->mutedR, theme->mutedG,
                  theme->mutedB, theme->panelR, theme->panelG, theme->panelB,
                  countText);

  char content[MSG_SIZE];
  if (g_input.readingRoomSecret) {
    size_t stars = g_input.roomSecretLen;
    if (stars >= sizeof(content))
      stars = sizeof(content) - 1;
    memset(content, '*', stars);
    content[stars] = '\0';
  } else {
    snprintf(content, sizeof(content), "%s", g_input.buffer);
  }

  bool hasInput = currentLen > 0;
  const char *placeholder = g_input.readingRoomSecret
                                ? ""
                                : "Type a message or command";
  int scrollStart = 0;
  if (hasInput && (int)currentLen > textW)
    scrollStart = (int)currentLen - textW;

  char visible[UI_RENDER_LINE_MAX];
  if (hasInput) {
    snprintf(visible, sizeof(visible), "%.*s", textW, content + scrollStart);
  } else {
    snprintf(visible, sizeof(visible), "%s", placeholder);
  }

  char inputLine[UI_RENDER_LINE_MAX];
  snprintf(inputLine, sizeof(inputLine), "%-*.*s", textW, textW, visible);
  uiDrawText(y + 2, x + 2, theme->accentR, theme->accentG, theme->accentB,
             theme->panelR, theme->panelG, theme->panelB, "> ");
  uiDrawText(y + 2, x + 4,
             hasInput ? 233 : theme->mutedR,
             hasInput ? 237 : theme->mutedG,
             hasInput ? 243 : theme->mutedB,
             theme->panelR, theme->panelG, theme->panelB, inputLine);

  if (h >= 5) {
    char noteLine[UI_RENDER_LINE_MAX];
    snprintf(noteLine, sizeof(noteLine), "%-*.*s", contentW, contentW, note);
    uiDrawText(y + 3, x + 2, theme->mutedR, theme->mutedG, theme->mutedB,
               theme->panelR, theme->panelG, theme->panelB, noteLine);
  }

  int cursorOffset = hasInput ? clampInt((int)currentLen - scrollStart, 0, textW)
                              : 0;
  uiSetCursor(y + 2, x + 4 + cursorOffset);
}

static void uiDrawHelp(int rows, int cols) {
  const UiTheme *theme = &UI_THEME_HELP;
  int w = cols - 6;
  if (w > 84)
    w = 84;
  if (w < 46)
    w = cols - 4;
  int h = rows >= 20 ? 15 : 13;
  if (h > rows - 2)
    h = rows - 2;
  int x = ((cols - w) / 2) + 1;
  int y = ((rows - h) / 2) + 1;

  uiDrawBox(x, y, w, h, "Quick Help", theme);
  uiDrawSectionLabel(y + 2, x + 2, w - 4, "ROOMS", NULL, theme);
  uiDrawText(y + 3, x + 2, 233, 237, 243, theme->panelR, theme->panelG,
             theme->panelB, "/rooms   /create <room>   /create <room> -p <secret>");
  uiDrawText(y + 4, x + 2, 233, 237, 243, theme->panelR, theme->panelG,
             theme->panelB, "/enter <room>   /leave");
  uiDrawSectionLabel(y + 6, x + 2, w - 4, "DIRECT", NULL, theme);
  uiDrawText(y + 7, x + 2, 233, 237, 243, theme->panelR, theme->panelG,
             theme->panelB, "/dm <token|nick|prefix>   /dmleave   /list");
  uiDrawText(y + 8, x + 2, 233, 237, 243, theme->panelR, theme->panelG,
             theme->panelB, "/nick <target> <name>   /token");
  uiDrawSectionLabel(y + 10, x + 2, w - 4, "BASICS", NULL, theme);
  uiDrawText(y + 11, x + 2, 233, 237, 243, theme->panelR, theme->panelG,
             theme->panelB, "/name <name>   /help   /exit");
  if (h >= 15) {
    uiDrawText(y + 12, x + 2, theme->accentR, theme->accentG, theme->accentB,
               theme->panelR, theme->panelG, theme->panelB,
               "Enter sends. Up/Down scroll. PgUp/PgDn jumps. ? toggles this panel.");
    uiDrawText(y + 13, x + 2, theme->mutedR, theme->mutedG, theme->mutedB,
               theme->panelR, theme->panelG, theme->panelB,
               "Protected rooms and DMs stay encrypted on the client.");
  } else {
    uiDrawText(y + 12, x + 2, theme->mutedR, theme->mutedG, theme->mutedB,
               theme->panelR, theme->panelG, theme->panelB,
               "Enter sends. Up/Down scroll. ? closes help.");
  }
}

static void renderUi(void) {
  int rows, cols;
  uiGetSize(&rows, &cols);
  print(UI_HIDE_CURSOR);
  g_cursorVisible = false;

  if (rows < 12 || cols < 52) {
    uiClearScreen();
    uiFillLine(1, cols, 18, 23, 30);
    uiFillLine(2, cols, 22, 27, 34);
    uiDrawText(1, 2, 233, 237, 243, 18, 23, 30, "SocketChat");
    uiDrawText(2, 2, 127, 140, 156, 22, 27, 34,
               "Resize to at least 52x12 for the compact layout.");
    fflush(stdout);
    return;
  }

  bool showSidebar = cols >= 106 && rows >= 21;
  bool compact = !showSidebar;
  int topH = compact ? 1 : 2;
  int inputH = rows >= 21 ? 5 : 4;
  int sidebar = showSidebar ? clampInt(cols / 3, 30, 36) : 0;
  int messageW = compact ? cols - 1 : cols - sidebar - 3;
  int messageH = rows - topH - inputH;
  int messageY = topH + 1;
  int inputY = rows - inputH + 1;
  int connected = g_input.connected ? 1 : 0;
  const UiTheme *activityTheme = &UI_THEME_ACTIVITY;
  const UiTheme *navTheme = &UI_THEME_NAV;
  const UiTheme *inputTheme = &UI_THEME_INPUT;

  uiClearScreen();
  uiFillLine(1, cols, 18, 23, 30);
  if (!compact)
    uiFillLine(2, cols, 21, 25, 31);

  char context[64];
  char security[64];
  formatContextLabel(context, sizeof(context));
  formatSecurityLabel(security, sizeof(security));

  uiDrawText(1, 2, 233, 237, 243, 18, 23, 30, "SocketChat");
  char identityText[96];
  snprintf(identityText, sizeof(identityText), "%s  %.8s...", g_username,
           g_identity.token);

  if (compact) {
    char compactStatus[160];
    snprintf(compactStatus, sizeof(compactStatus), "%s | %s | %s | ? help",
             connected ? "connected" : "offline", context, security);
    uiDrawText(1, 15,
               connected ? 152 : 239, connected ? 195 : 108,
               connected ? 121 : 96, 18, 23, 30, compactStatus);
    uiDrawTextRight(1, cols - 2, 127, 140, 156, 18, 23, 30, identityText);

    uiDrawBox(1, messageY, messageW, messageH, "Activity", activityTheme);
    uiDrawBox(1, inputY, cols - 1, inputH, "Composer", inputTheme);
    uiDrawMessages(1, messageY, messageW, messageH);
  } else {
    uiDrawText(1, 15, navTheme->accentR, navTheme->accentG, navTheme->accentB,
               18, 23, 30, context);
    uiDrawText(1, 36, inputTheme->accentR, inputTheme->accentG,
               inputTheme->accentB, 18, 23, 30, security);
    uiDrawTextRight(1, cols - 2, 127, 140, 156, 18, 23, 30, identityText);

    char statusLine[256];
    snprintf(statusLine, sizeof(statusLine), "%s | relay %s | ? help",
             connected ? "connected" : "offline", g_serverLabel);
    uiDrawText(2, 2, 127, 140, 156, 21, 25, 31, statusLine);

    uiDrawBox(1, messageY, messageW, messageH, "Activity", activityTheme);
    uiDrawBox(messageW + 2, messageY, sidebar, messageH, "Navigator", navTheme);
    uiDrawBox(1, inputY, cols - 1, inputH, "Composer", inputTheme);
    uiDrawMessages(1, messageY, messageW, messageH);
    uiDrawSidebar(messageW + 2, messageY, sidebar, messageH);
  }

  uiDrawInput(1, inputY, cols - 1, inputH);

  int totalLines = 0;
  char wrapped[64][UI_RENDER_LINE_MAX];
  for (int i = 0; i < g_messageCount; i++) {
    int wrappedCount = wrapTextToWidth(g_messages[i].text, messageW - 4, wrapped,
                                       (int)(sizeof(wrapped) / sizeof(wrapped[0])));
    totalLines += (wrappedCount > 0) ? wrappedCount : 1;
  }
  int maxScroll = totalLines > (messageH - 2) ? totalLines - (messageH - 2) : 0;
  if (maxScroll > 0) {
    char scrollText[64];
    snprintf(scrollText, sizeof(scrollText), "scroll %d/%d", g_messageScroll,
             maxScroll);
    uiDrawTextRight(messageY, messageW - 1, activityTheme->mutedR,
                    activityTheme->mutedG, activityTheme->mutedB,
                    activityTheme->panelR, activityTheme->panelG,
                    activityTheme->panelB, scrollText);
  }

  if (g_showHelp)
    uiDrawHelp(rows, cols);

  if (g_showHelp) {
    g_cursorVisible = false;
  } else if (g_cursorVisible) {
    uiMove(clampInt(g_cursorRow, 1, rows), clampInt(g_cursorCol, 1, cols));
    print(UI_SHOW_CURSOR);
  }

  fflush(stdout);
}

typedef enum {
  KEY_NONE,
  KEY_CHAR,
  KEY_ENTER,
  KEY_BACKSPACE,
  KEY_UP,
  KEY_DOWN,
  KEY_PGUP,
  KEY_PGDN,
  KEY_HELP
} KeyType;

typedef struct {
  KeyType type;
  char ch;
} KeyEvent;

static KeyEvent readKeyEvent(void) {
  char c = 0;
  ssize_t n = read(STDIN_FILENO, &c, 1);
  if (n <= 0)
    return (KeyEvent){KEY_NONE, 0};

  if (c == '\r' || c == '\n')
    return (KeyEvent){KEY_ENTER, 0};
  if (c == 127 || c == 8)
    return (KeyEvent){KEY_BACKSPACE, 0};
  if (c == '?')
    return (KeyEvent){KEY_HELP, 0};
  if (c == 27) {
    char seq[3] = {0};
    if (read(STDIN_FILENO, &seq[0], 1) <= 0)
      return (KeyEvent){KEY_NONE, 0};
    if (read(STDIN_FILENO, &seq[1], 1) <= 0)
      return (KeyEvent){KEY_NONE, 0};
    if (seq[0] == '[') {
      if (seq[1] == 'A')
        return (KeyEvent){KEY_UP, 0};
      if (seq[1] == 'B')
        return (KeyEvent){KEY_DOWN, 0};
      if (seq[1] == '5') {
        read(STDIN_FILENO, &seq[2], 1);
        return (KeyEvent){KEY_PGUP, 0};
      }
      if (seq[1] == '6') {
        read(STDIN_FILENO, &seq[2], 1);
        return (KeyEvent){KEY_PGDN, 0};
      }
    }
    return (KeyEvent){KEY_NONE, 0};
  }
  if (isprint((unsigned char)c))
    return (KeyEvent){KEY_CHAR, c};
  return (KeyEvent){KEY_NONE, 0};
}

static void handleTokenCommand(void) {
  addMessage(UI_MSG_INFO, "[*] Your token: %s", g_identity.token);
}

static void handleListCommand(void) {
  reloadDmHistoryIndex();
  addMessage(UI_MSG_INFO, "[*] Loaded %d DM conversations", g_dmCount);
}

static void handleNickCommand(const char *target, const char *nick) {
  reloadDmHistoryIndex();
  int idx = findDmByReference(target);
  if (idx < 0) {
    addMessage(UI_MSG_ERROR, "[!] DM not found");
    return;
  }

  for (size_t i = 0; nick[i]; i++) {
    unsigned char ch = (unsigned char)nick[i];
    if (!(isalnum(ch) || ch == '-' || ch == '_')) {
      addMessage(UI_MSG_ERROR, "[!] Nicknames may use letters, digits, - and _");
      return;
    }
  }

  snprintf(g_dmNick[idx], sizeof(g_dmNick[idx]), "%s", nick);
  saveDmNicknames();
  addMessage(UI_MSG_INFO, "[*] Nickname saved");
}

static void handleDmCommand(const char *input) {
  reloadDmHistoryIndex();

  char token[TOKEN_STR_SIZE] = {0};
  if (strlen(input) == TOKEN_HEX_LEN) {
    snprintf(token, sizeof(token), "%s", input);
  } else {
    int idx = findDmByReference(input);
    if (idx < 0) {
      addMessage(UI_MSG_ERROR, "[!] Unknown DM reference");
      return;
    }
    snprintf(token, sizeof(token), "%s", g_dmList[idx]);
  }

  unsigned char myPub[32];
  unsigned char myPriv[32];
  if (!x25519GenerateKeypair(myPub, myPriv)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to generate DM session keys");
    return;
  }

  char myPubHex[65];
  bytesToHex(myPub, sizeof(myPub), myPubHex);
  unsigned char sig[SIG_BYTES];
  if (!signDmFrame("DM_INIT", g_identity.token, token, myPubHex, sig)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to sign DM request");
    memset(myPriv, 0, sizeof(myPriv));
    return;
  }

  char sigHex[SIG_HEX_SIZE];
  bytesToHex(sig, sizeof(sig), sigHex);
  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "DM_INIT|%s|%s|%s\n", token, myPubHex, sigHex);
  if (!sendRawFrame(frame)) {
    memset(myPriv, 0, sizeof(myPriv));
    addMessage(UI_MSG_ERROR, "[!] Failed to send DM request");
    return;
  }

  clearDmSession();
  g_dm.awaitingAck = true;
  snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", token);
  memcpy(g_dm.pendingPriv, myPriv, sizeof(g_dm.pendingPriv));
  memcpy(g_dm.pendingPub, myPub, sizeof(g_dm.pendingPub));
  memset(myPriv, 0, sizeof(myPriv));
  rememberDmToken(token);
  addMessage(UI_MSG_INFO, "[*] DM request sent");
}

static bool processCommand(char *message) {
  if (!message[0])
    return true;

  if (strcmp(message, "/exit") == 0) {
    sendRawFrame("QUIT\n");
    return false;
  }
  if (strcmp(message, "/help") == 0) {
    g_showHelp = !g_showHelp;
    return true;
  }
  if (strncmp(message, "/name ", 6) == 0) {
    char name[MAX_NAME_LEN];
    if (sscanf(message + 6, "%63s", name) != 1 || !protocolIsSafeIdentifier(name)) {
      addMessage(UI_MSG_ERROR, "[!] Invalid name");
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
        addMessage(UI_MSG_ERROR, "[!] Usage: /create <room> -p <secret>");
        return true;
      }
      char saltHex[ROOM_SALT_HEX_SIZE];
      char verifierHex[SHA256_HEX_SIZE];
      unsigned char roomKey[32];
      if (!createRoomSecrets(room, secret, saltHex, verifierHex, roomKey)) {
        addMessage(UI_MSG_ERROR, "[!] Failed to create room secret material");
        return true;
      }
      char frame[MSG_SIZE];
      snprintf(frame, sizeof(frame), "ROOM_CREATE|%s|PROTECTED|%s|%s\n", room,
               saltHex, verifierHex);
      sendRawFrame(frame);
      return true;
    }
    if (sscanf(message + 8, "%63s", room) != 1) {
      addMessage(UI_MSG_ERROR, "[!] Usage: /create <room>");
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
      addMessage(UI_MSG_ERROR, "[!] Usage: /enter <room>");
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
  if (strcmp(message, "/list") == 0) {
    handleListCommand();
    return true;
  }
  if (strcmp(message, "/token") == 0) {
    handleTokenCommand();
    return true;
  }
  if (strcmp(message, "/dmleave") == 0) {
    clearDmSession();
    addMessage(UI_MSG_INFO, "[*] DM session closed");
    return true;
  }
  if (strncmp(message, "/dm ", 4) == 0) {
    char target[128];
    if (sscanf(message + 4, "%127s", target) != 1) {
      addMessage(UI_MSG_ERROR, "[!] Usage: /dm <token|nick|prefix>");
      return true;
    }
    handleDmCommand(target);
    return true;
  }
  if (strncmp(message, "/nick ", 6) == 0) {
    char target[128];
    char nick[MAX_NAME_LEN];
    if (sscanf(message + 6, "%127s %63s", target, nick) != 2) {
      addMessage(UI_MSG_ERROR, "[!] Usage: /nick <target> <name>");
      return true;
    }
    handleNickCommand(target, nick);
    return true;
  }

  if (g_dm.active) {
    if (encryptAndSendDm(message)) {
      historyAppend(g_dm.peerToken, true, message);
      addTimestamped(UI_MSG_SELF, g_username, message);
    } else {
      addMessage(UI_MSG_ERROR, "[!] Failed to send DM");
    }
    return true;
  }

  if (!g_room.active) {
    addMessage(UI_MSG_INFO, "[*] Join a room or start a DM first");
    return true;
  }

  if (encryptAndSendRoom(message))
    addTimestamped(UI_MSG_SELF, g_username, message);
  else
    addMessage(UI_MSG_ERROR, "[!] Failed to send room message");
  return true;
}

static void handleKey(KeyEvent key) {
  if (key.type == KEY_HELP) {
    g_showHelp = !g_showHelp;
    return;
  }
  if (key.type == KEY_UP) {
    g_messageScroll++;
    return;
  }
  if (key.type == KEY_DOWN) {
    g_messageScroll--;
    if (g_messageScroll < 0)
      g_messageScroll = 0;
    return;
  }
  if (key.type == KEY_PGUP) {
    g_messageScroll += 10;
    return;
  }
  if (key.type == KEY_PGDN) {
    g_messageScroll -= 10;
    if (g_messageScroll < 0)
      g_messageScroll = 0;
    return;
  }

  if (g_input.readingRoomSecret) {
    if (key.type == KEY_ENTER) {
      finalizeRoomSecretEntry();
      return;
    }
    if (key.type == KEY_BACKSPACE && g_input.roomSecretLen > 0) {
      g_input.roomSecret[--g_input.roomSecretLen] = '\0';
      return;
    }
    if (key.type == KEY_CHAR && g_input.roomSecretLen < MSG_SIZE - 1) {
      g_input.roomSecret[g_input.roomSecretLen++] = key.ch;
      g_input.roomSecret[g_input.roomSecretLen] = '\0';
    }
    return;
  }

  if (key.type == KEY_ENTER) {
    char message[MSG_SIZE];
    snprintf(message, sizeof(message), "%s", g_input.buffer);
    g_input.buffer[0] = '\0';
    g_input.length = 0;
    if (!processCommand(message))
      g_input.connected = false;
    return;
  }
  if (key.type == KEY_BACKSPACE && g_input.length > 0) {
    g_input.buffer[--g_input.length] = '\0';
    return;
  }
  if (key.type == KEY_CHAR && g_input.length < MSG_SIZE - 1) {
    g_input.buffer[g_input.length++] = key.ch;
    g_input.buffer[g_input.length] = '\0';
  }
}

static void eventLoop(void) {
  while (true) {
    pthread_mutex_lock(&g_stateMutex);
    bool connected = g_input.connected;
    renderUi();
    pthread_mutex_unlock(&g_stateMutex);
    if (!connected)
      break;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    int rc = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
    if (rc > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
      KeyEvent key = readKeyEvent();
      pthread_mutex_lock(&g_stateMutex);
      handleKey(key);
      pthread_mutex_unlock(&g_stateMutex);
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
  snprintf(g_serverLabel, sizeof(g_serverLabel), "%s", serverLabel);
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

  logOpen();
  tcgetattr(STDIN_FILENO, &g_origTermios);
  atexit(disableRawMode);
  enableRawMode();
  uiEnter();

  if (!identityLoadOrCreate(&g_identity)) {
    uiExit();
    fprintf(stderr, "Fatal: could not load or create identity\n");
    return 1;
  }

  if (!identityLoadUsername(g_username, sizeof(g_username)))
    snprintf(g_username, sizeof(g_username), "%.8s", g_identity.token);
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

  if (!connectToServer(ip, port) || !authenticate()) {
    uiExit();
    fprintf(stderr, "Failed to connect/authenticate to %s:%d\n", ip, port);
    return 1;
  }

  char nameFrame[MSG_SIZE];
  snprintf(nameFrame, sizeof(nameFrame), "SET_NAME|%s\n", g_username);
  sendRawFrame(nameFrame);
  sendRawFrame("ROOM_LIST\n");
  addMessage(UI_MSG_INFO, "[*] Connected to server");
  addMessage(UI_MSG_INFO, "[*] Type /help or press ? for commands");

  pthread_t recvTid;
  if (pthread_create(&recvTid, NULL, receiveThread, NULL) != 0) {
    uiExit();
    fprintf(stderr, "Failed to create receive thread\n");
    return 1;
  }

  eventLoop();
  if (g_socketFD != INVALID_SOCKET_HANDLE)
    platformShutdownSocket(g_socketFD);
  pthread_join(recvTid, NULL);

  uiExit();
  if (g_ssl)
    tlsFree(g_ssl);
  if (g_socketFD != INVALID_SOCKET_HANDLE)
    platformCloseSocket(g_socketFD);
  pthread_mutex_destroy(&g_stateMutex);
  if (g_logFile)
    fclose(g_logFile);
  platformCleanup();
  return 0;
}
