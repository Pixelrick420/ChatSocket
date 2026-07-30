#include "../Utils/aes.h"
#include "../Utils/contacts.h"
#include "../Utils/ecdh.h"
#include "../Utils/history.h"
#include "../Utils/identity.h"
#include "../Utils/protocol.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#include <ctype.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>

#if defined(__GNUC__) || defined(__clang__)
#define PRINTF_FMT(fmtIndex, firstArg)                                         \
  __attribute__((format(printf, fmtIndex, firstArg)))
#else
#define PRINTF_FMT(fmtIndex, firstArg)
#endif

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 2077
#define DM_SESSION_ID_BYTES 16
#define DM_SESSION_ID_HEX_LEN (DM_SESSION_ID_BYTES * 2)
#define DM_SESSION_ID_SIZE (DM_SESSION_ID_HEX_LEN + 1)
#define DM_SEEN_SESSION_COUNT 256
#define MAX_MESSAGES 1000
#define SIDEBAR_MIN_WIDTH 28
#define SIDEBAR_MAX_WIDTH 36
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
  char sessionId[DM_SESSION_ID_SIZE];
  uint64_t sendSeq;
  unsigned char key[32];
  unsigned char pendingKey[32];
} RoomState;

typedef struct {
  bool active;
  bool awaitingAck;
  char peerToken[TOKEN_STR_SIZE];
  char sessionId[DM_SESSION_ID_SIZE];
  uint64_t sendSeq;
  uint64_t recvSeq;
  unsigned char key[32];
  unsigned char pendingPriv[32];
  unsigned char pendingPub[32];
} DmSession;

typedef struct {
  char buffer[MSG_SIZE];
  size_t length;
  bool connected;
  bool readingRoomSecret;
  bool creatingRoomSecret;
  char roomSecret[MSG_SIZE];
  size_t roomSecretLen;
} InputState;

static FILE *g_logFile = NULL;
static char g_logPath[600] = {0};
static char g_serverLabel[128] = "offline";
static char g_serverFingerprint[SHA256_HEX_SIZE] = {0};
static SocketHandle g_socketFD = INVALID_SOCKET_HANDLE;
static SSL *g_ssl = NULL;
static Identity g_identity = {0};
static char g_username[MAX_NAME_LEN] = {0};
static char g_pendingUsername[MAX_NAME_LEN] = {0};
static bool g_hasConfirmedName = false;
static RoomState g_room = {0};
static DmSession g_dm = {0};
static struct termios g_origTermios;
static pthread_mutex_t g_stateMutex = PTHREAD_MUTEX_INITIALIZER;
static InputState g_input = {
    .buffer = {0},
    .length = 0,
    .connected = true,
    .readingRoomSecret = false,
    .creatingRoomSecret = false,
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
static ContactBook g_contacts = {0};
static RoomReplayTracker g_roomReplay = {0};
static char g_seenDmSessions[DM_SEEN_SESSION_COUNT][DM_SESSION_ID_SIZE] = {{0}};
static size_t g_seenDmSessionNext = 0;
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
static const UiTheme UI_THEME_ACTIVITY = {22,  26,  34,  62,  96,  136,
                                          166, 204, 255, 122, 144, 170};
static const UiTheme UI_THEME_NAV = {30,  24,  20,  129, 95,  45,
                                     239, 196, 106, 161, 139, 112};
static const UiTheme UI_THEME_INPUT = {20,  28,  28,  48,  113, 104,
                                       144, 224, 203, 122, 150, 147};
static const UiTheme UI_THEME_HELP = {30,  24,  36,  116, 92,  152,
                                      219, 198, 255, 150, 138, 172};

static void logOpen(void) {
  const char *logging = getenv("SOCKETCHAT_LOG");
  if (logging && strcmp(logging, "0") == 0)
    return;

  char configDir[512];
  if (!platformGetConfigDir(configDir, sizeof(configDir)))
    return;
  if (!platformEnsureDir(configDir))
    return;

  pid_t pid = getpid();
  snprintf(g_logPath, sizeof(g_logPath), "%s%ctui_%d.log", configDir,
           SOCKETCHAT_PATH_SEP, pid);
  int flags = O_WRONLY | O_CREAT | O_APPEND;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd = open(g_logPath, flags, 0600);
  if (fd < 0 || !platformSecureUserFileFd(fd)) {
    if (fd >= 0)
      platformCloseFd(fd);
    return;
  }
  g_logFile = fdopen(fd, "a");
  if (!g_logFile) {
    platformCloseFd(fd);
    return;
  }
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
  raw.c_lflag &= (tcflag_t) ~(ICANON | ECHO);
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

static void uiCopyFittedText(const char *text, int width, char *out,
                             size_t outSize) {
  if (!out || outSize == 0)
    return;

  out[0] = '\0';
  if (width <= 0)
    return;

  if (!text)
    text = "";

  if ((int)strlen(text) <= width) {
    snprintf(out, outSize, "%-*.*s", width, width, text);
    return;
  }

  if (width <= 3) {
    snprintf(out, outSize, "%.*s", width, "...");
    return;
  }

  snprintf(out, outSize, "%.*s...", width - 3, text);
}

static void uiDrawTextFitted(int row, int col, int width, int fgR, int fgG,
                             int fgB, int bgR, int bgG, int bgB,
                             const char *text) {
  char fitted[UI_RENDER_LINE_MAX];
  uiCopyFittedText(text, width, fitted, sizeof(fitted));
  uiDrawText(row, col, fgR, fgG, fgB, bgR, bgG, bgB, fitted);
}

static void uiFormatKeyValueLine(const char *key, const char *value, int width,
                                 char *out, size_t outSize) {
  char raw[256];
  snprintf(raw, sizeof(raw), "%-5s %s", key ? key : "", value ? value : "");
  uiCopyFittedText(raw, width, out, outSize);
}

static void uiFormatRoomLine(char marker, const char *roomName,
                             const char *roomType, int width, char *out,
                             size_t outSize) {
  if (!out || outSize == 0)
    return;

  out[0] = '\0';
  if (width <= 0)
    return;

  int tagLen = roomType ? (int)strlen(roomType) : 0;
  int nameWidth = width - 4 - tagLen;
  if (nameWidth < 6) {
    char raw[128];
    snprintf(raw, sizeof(raw), "%c %s %s", marker, roomName ? roomName : "",
             roomType ? roomType : "");
    uiCopyFittedText(raw, width, out, outSize);
    return;
  }

  char nameText[128];
  uiCopyFittedText(roomName ? roomName : "", nameWidth, nameText,
                   sizeof(nameText));
  snprintf(out, outSize, "%c %s %s", marker, nameText,
           roomType ? roomType : "");
}

static void uiFormatContactLine(const DmContact *contact, int index,
                                bool active, int width, char *out,
                                size_t outSize) {
  if (!out || outSize == 0)
    return;

  out[0] = '\0';
  if (width <= 0 || !contact)
    return;

  char prefix[16];
  int prefixLen =
      snprintf(prefix, sizeof(prefix), "%c %2d ", active ? '>' : ' ', index);
  if (prefixLen < 0)
    prefixLen = 0;

  if (contact->nickname[0]) {
    char tokenHint[8];
    snprintf(tokenHint, sizeof(tokenHint), "%.6s", contact->token);
    int tokenWidth = (int)strlen(tokenHint);
    int nameWidth = width - prefixLen - tokenWidth - 1;
    if (nameWidth < 6) {
      char raw[128];
      snprintf(raw, sizeof(raw), "%s%s", prefix, contact->nickname);
      uiCopyFittedText(raw, width, out, outSize);
      return;
    }

    char nameText[128];
    uiCopyFittedText(contact->nickname, nameWidth, nameText, sizeof(nameText));
    snprintf(out, outSize, "%s%s %s", prefix, nameText, tokenHint);
    return;
  }

  char tokenText[128];
  uiCopyFittedText(contact->token, width - prefixLen, tokenText,
                   sizeof(tokenText));
  snprintf(out, outSize, "%s%s", prefix, tokenText);
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
    memmove(&g_messages[0], &g_messages[1],
            sizeof(g_messages[0]) * (MAX_MESSAGES - 1));
    g_messageCount--;
  }

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(g_messages[g_messageCount].text,
            sizeof(g_messages[g_messageCount].text), fmt, ap);
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

static void clearRoomState(void) { OPENSSL_cleanse(&g_room, sizeof(g_room)); }

static bool startRoomSession(void) {
  unsigned char session[DM_SESSION_ID_BYTES];
  if (RAND_bytes(session, sizeof(session)) != 1)
    return false;
  bytesToHex(session, sizeof(session), g_room.sessionId);
  g_room.sendSeq = 0;
  OPENSSL_cleanse(session, sizeof(session));
  return true;
}

static void clearDmSession(void) { OPENSSL_cleanse(&g_dm, sizeof(g_dm)); }

static void reloadDmHistoryIndex(void) {
  contactsLoad(&g_contacts);
  if (g_dm.peerToken[0])
    contactsRememberToken(&g_contacts, g_dm.peerToken);
}

static void saveDmNicknames(void) { contactsSaveNicknames(&g_contacts); }

static void rememberDmToken(const char *token) {
  contactsRememberToken(&g_contacts, token);
}

static void formatDmLabel(const char *token, char *out, size_t outSize) {
  contactsFormatLabel(&g_contacts, token, out, outSize);
}

static int dmContactCount(void) { return (int)g_contacts.count; }

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

static bool splitFirstArgument(const char *input, char *first, size_t firstSize,
                               const char **restOut) {
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

static void showContactMatches(const char *query, const ContactMatch *matches,
                               size_t matchCount) {
  if (matchCount == 0) {
    addMessage(UI_MSG_ERROR, "[!] No contact matches \"%s\"", query);
    return;
  }

  addMessage(UI_MSG_INFO, "[*] Contacts matching \"%s\":", query);
  for (size_t i = 0; i < matchCount; i++) {
    char reference[128];
    contactsFormatReference(&g_contacts, matches[i].index, reference,
                            sizeof(reference));
    addMessage(UI_MSG_INFO, "    %zu. %s", matches[i].index + 1, reference);
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
      addMessage(UI_MSG_ERROR, "[!] Contact reference is empty");
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
      addMessage(UI_MSG_ERROR,
                 "[!] Multiple contacts match \"%s\". Use /search or a number.",
                 query);
      showContactMatches(query, matches, matchCount);
    }
    return false;
  }

  if (allowDirectToken && isTokenHex(query)) {
    snprintf(tokenOut, tokenOutSize, "%s", query);
    return true;
  }

  if (announceAmbiguity)
    addMessage(UI_MSG_ERROR, "[!] No contact matches \"%s\"", query);
  return false;
}

static void formatContextLabel(char *out, size_t outSize) {
  if (!out || outSize == 0)
    return;

  if (g_input.readingRoomSecret) {
    char roomName[MAX_NAME_LEN];
    snprintf(roomName, sizeof(roomName), "%s",
             g_room.pendingName[0] ? g_room.pendingName : "room");
    snprintf(out, outSize, "Unlock #%.*s", (int)(outSize - 9), roomName);
    return;
  }

  if (g_dm.active) {
    char dmLabel[64];
    formatDmLabel(g_dm.peerToken, dmLabel, sizeof(dmLabel));
    snprintf(out, outSize, "DM %.*s", (int)(outSize - 4), dmLabel);
    return;
  }

  if (g_room.active) {
    snprintf(out, outSize, "#%.*s", (int)(outSize - 2), g_room.currentName);
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

static bool sendRawFrame(const char *frame) {
  bool connected = g_input.connected;
  if (!connected)
    return false;

  clientLog("send: %.160s", frame);
  return tlsSend(g_ssl, frame, strlen(frame));
}

static bool signDmFrame(const char *frameType, const char *fromToken,
                        const char *toToken, const char *sessionId,
                        const char *initiatorPubHex,
                        const char *responderPubHex,
                        unsigned char sigOut[SIG_BYTES]) {
  char transcript[384];
  int len =
      snprintf(transcript, sizeof(transcript), "%s|%s|%s|%s|%s|%s", frameType,
               fromToken, toToken, sessionId, initiatorPubHex, responderPubHex);
  if (len <= 0 || (size_t)len >= sizeof(transcript))
    return false;
  return identitySign(&g_identity, (const unsigned char *)transcript,
                      (size_t)len, sigOut);
}

static bool verifyDmFrame(const char *frameType, const char *fromToken,
                          const char *toToken, const char *sessionId,
                          const char *initiatorPubHex,
                          const char *responderPubHex,
                          const unsigned char sig[SIG_BYTES]) {
  char transcript[384];
  int len =
      snprintf(transcript, sizeof(transcript), "%s|%s|%s|%s|%s|%s", frameType,
               fromToken, toToken, sessionId, initiatorPubHex, responderPubHex);
  if (len <= 0 || (size_t)len >= sizeof(transcript))
    return false;
  return identityVerify(fromToken, (const unsigned char *)transcript,
                        (size_t)len, sig);
}

static bool rememberDmSession(const char *sessionId) {
  for (size_t i = 0; i < DM_SEEN_SESSION_COUNT; i++) {
    if (strcmp(g_seenDmSessions[i], sessionId) == 0)
      return false;
  }

  snprintf(g_seenDmSessions[g_seenDmSessionNext], DM_SESSION_ID_SIZE, "%s",
           sessionId);
  g_seenDmSessionNext = (g_seenDmSessionNext + 1) % DM_SEEN_SESSION_COUNT;
  return true;
}

static bool encryptAndSendRoom(const char *message) {
  if (strlen(message) > MAX_MESSAGE_TEXT) {
    addMessage(UI_MSG_ERROR, "[!] Message too long");
    return false;
  }

  if (!g_room.sessionId[0] || g_room.sendSeq == UINT64_MAX) {
    addMessage(UI_MSG_ERROR, "[!] Room session unavailable");
    return false;
  }
  uint64_t sequence = g_room.sendSeq + 1;
  char payload[MSG_SIZE * 2];
  if (!g_room.protectedRoom) {
    if (!protocolEncodeText(message, payload, sizeof(payload)))
      return false;
  } else {
    char aad[512];
    size_t aadLen = 0;
    if (!protocolBuildRoomAad(g_room.currentName, g_username, g_identity.token,
                              g_room.sessionId, sequence, aad, sizeof(aad),
                              &aadLen))
      return false;
    unsigned char ciphertext[MAX_MESSAGE_TEXT + AES_GCM_OVERHEAD];
    int clen = encryptMessageWithAad(
        (const unsigned char *)message, strlen(message), g_room.key,
        (const unsigned char *)aad, aadLen, ciphertext, sizeof(ciphertext));
    if (clen <= 0)
      return false;
    if (!encodeBase64(ciphertext, (size_t)clen, payload, sizeof(payload))) {
      addMessage(UI_MSG_ERROR, "[!] Failed to encode room message");
      return false;
    }
  }

  char transcript[MSG_SIZE * 2];
  size_t transcriptLen = 0;
  unsigned char signature[SIG_BYTES];
  if (!protocolBuildRoomTranscript(
          g_room.currentName, g_username, g_identity.token, g_room.sessionId,
          sequence, payload, transcript, sizeof(transcript), &transcriptLen) ||
      !identitySign(&g_identity, (const unsigned char *)transcript,
                    transcriptLen, signature))
    return false;
  char signatureHex[SIG_HEX_SIZE];
  bytesToHex(signature, sizeof(signature), signatureHex);
  char frame[MSG_SIZE * 2 + SIG_HEX_SIZE + 96];
  snprintf(frame, sizeof(frame), "ROOM_SEND|%s|%" PRIu64 "|%s|%s\n",
           g_room.sessionId, sequence, payload, signatureHex);
  if (!sendRawFrame(frame))
    return false;
  g_room.sendSeq = sequence;
  return true;
}

static bool encryptAndSendDm(const char *message) {
  if (strlen(message) > MAX_MESSAGE_TEXT) {
    addMessage(UI_MSG_ERROR, "[!] Message too long");
    return false;
  }

  if (g_dm.sendSeq == UINT64_MAX) {
    addMessage(UI_MSG_ERROR, "[!] DM session message limit reached");
    return false;
  }
  uint64_t sequence = g_dm.sendSeq + 1;
  char aad[256];
  int aadLen =
      snprintf(aad, sizeof(aad), "DM_MSG|%s|%s|%s|%" PRIu64, g_dm.sessionId,
               g_identity.token, g_dm.peerToken, sequence);
  if (aadLen <= 0 || (size_t)aadLen >= sizeof(aad))
    return false;

  unsigned char ciphertext[MAX_MESSAGE_TEXT + AES_GCM_OVERHEAD];
  int clen =
      encryptMessageWithAad((const unsigned char *)message, strlen(message),
                            g_dm.key, (const unsigned char *)aad,
                            (size_t)aadLen, ciphertext, sizeof(ciphertext));
  if (clen <= 0)
    return false;

  char payload[MSG_SIZE * 2];
  if (!encodeBase64(ciphertext, (size_t)clen, payload, sizeof(payload))) {
    addMessage(UI_MSG_ERROR, "[!] Failed to encode DM");
    return false;
  }

  char frame[MSG_SIZE * 3 + 32];
  int written = snprintf(
      frame, sizeof(frame), "DM_SEND|%s|%s|%" PRIu64 "|%.*s\n", g_dm.peerToken,
      g_dm.sessionId, sequence, (int)(sizeof(frame) - 64), payload);
  if (written < 0 || (size_t)written >= sizeof(frame)) {
    addMessage(UI_MSG_ERROR, "[!] DM frame too large");
    return false;
  }
  if (!sendRawFrame(frame))
    return false;
  g_dm.sendSeq = sequence;
  return true;
}

static void showRoomMessage(const char *sender, const char *senderToken,
                            const char *sessionId, const char *sequenceText,
                            const char *payload, const char *signatureHex) {
  uint64_t sequence = 0;
  unsigned char signature[SIG_BYTES];
  if (!protocolIsSafeIdentifier(sender) ||
      !protocolIsHex(senderToken, TOKEN_HEX_LEN) ||
      !protocolIsHex(sessionId, DM_SESSION_ID_HEX_LEN) ||
      !protocolParseSequence(sequenceText, &sequence) ||
      !protocolIsHex(signatureHex, SIG_HEX_LEN) ||
      !hexToBytes(signatureHex, signature, sizeof(signature))) {
    addMessage(UI_MSG_ERROR, "[!] Unsafe room sender rejected");
    return;
  }

  char transcript[MSG_SIZE * 2];
  size_t transcriptLen = 0;
  if (!protocolBuildRoomTranscript(g_room.currentName, sender, senderToken,
                                   sessionId, sequence, payload, transcript,
                                   sizeof(transcript), &transcriptLen) ||
      !identityVerify(senderToken, (const unsigned char *)transcript,
                      transcriptLen, signature)) {
    addMessage(UI_MSG_ERROR, "[!] Room message signature rejected");
    return;
  }
  char text[MSG_SIZE];
  if (!g_room.protectedRoom) {
    if (!protocolDecodeText(payload, text, sizeof(text))) {
      addMessage(UI_MSG_ERROR, "[!] Failed to decode room payload");
      return;
    }
    if (!protocolIsSafeText(text, MAX_MESSAGE_TEXT)) {
      addMessage(UI_MSG_ERROR, "[!] Unsafe room message rejected");
      return;
    }
  } else {
    char aad[512];
    size_t aadLen = 0;
    if (!protocolBuildRoomAad(g_room.currentName, sender, senderToken,
                              sessionId, sequence, aad, sizeof(aad), &aadLen))
      return;
    unsigned char decoded[MSG_SIZE];
    int dlen = decodeBase64(payload, decoded, sizeof(decoded));
    if (dlen <= 0) {
      addMessage(UI_MSG_ERROR, "[!] Failed to decode encrypted room payload");
      return;
    }
    unsigned char decrypted[MSG_SIZE];
    int plen = decryptMessageWithAad(decoded, (size_t)dlen, g_room.key,
                                     (const unsigned char *)aad, aadLen,
                                     decrypted, sizeof(decrypted) - 1);
    if (plen <= 0) {
      addMessage(UI_MSG_ERROR, "[!] Failed to decrypt room payload");
      return;
    }
    decrypted[plen] = '\0';
    if (!protocolIsSafeText((char *)decrypted, MAX_MESSAGE_TEXT)) {
      addMessage(UI_MSG_ERROR, "[!] Unsafe room message rejected");
      return;
    }
    snprintf(text, sizeof(text), "%s", (char *)decrypted);
  }
  if (!protocolAcceptRoomSequence(&g_roomReplay, senderToken, sessionId,
                                  sequence)) {
    addMessage(UI_MSG_ERROR,
               "[!] Replayed or out-of-order room message rejected");
    return;
  }
  addTimestamped(UI_MSG_CHAT, sender, text);
}

static void showDmMessage(const char *senderToken, const char *sessionId,
                          const char *sequenceText, const char *payload) {
  if (!protocolIsHex(senderToken, TOKEN_HEX_LEN) ||
      !protocolIsHex(sessionId, DM_SESSION_ID_HEX_LEN)) {
    addMessage(UI_MSG_ERROR, "[!] Malformed DM rejected");
    return;
  }
  if (!g_dm.active || strcmp(g_dm.peerToken, senderToken) != 0) {
    char dmLabel[64];
    formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
    addMessage(UI_MSG_INFO, "[*] Received a DM for inactive contact %s",
               dmLabel);
    return;
  }
  if (strcmp(g_dm.sessionId, sessionId) != 0) {
    addMessage(UI_MSG_ERROR, "[!] DM from unknown session rejected");
    return;
  }

  uint64_t sequence = 0;
  if (!protocolParseSequence(sequenceText, &sequence) ||
      sequence <= g_dm.recvSeq) {
    addMessage(UI_MSG_ERROR, "[!] Replayed DM rejected");
    return;
  }
  if (g_dm.recvSeq == UINT64_MAX || sequence != g_dm.recvSeq + 1) {
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "DM_CLOSE|%s|%s\n", g_dm.peerToken,
             g_dm.sessionId);
    sendRawFrame(frame);
    clearDmSession();
    addMessage(UI_MSG_ERROR, "[!] Out-of-order DM closed; reopen the session");
    return;
  }

  char aad[256];
  int aadLen = snprintf(aad, sizeof(aad), "DM_MSG|%s|%s|%s|%" PRIu64, sessionId,
                        senderToken, g_identity.token, sequence);
  if (aadLen <= 0 || (size_t)aadLen >= sizeof(aad))
    return;

  unsigned char decoded[MSG_SIZE];
  int dlen = decodeBase64(payload, decoded, sizeof(decoded));
  if (dlen <= 0) {
    addMessage(UI_MSG_ERROR, "[!] Failed to decode DM payload");
    return;
  }

  unsigned char decrypted[MSG_SIZE];
  int plen = decryptMessageWithAad(decoded, (size_t)dlen, g_dm.key,
                                   (const unsigned char *)aad, (size_t)aadLen,
                                   decrypted, sizeof(decrypted) - 1);
  if (plen <= 0) {
    addMessage(UI_MSG_ERROR, "[!] Failed to decrypt DM payload");
    return;
  }

  decrypted[plen] = '\0';
  if (!protocolIsSafeText((char *)decrypted, MAX_MESSAGE_TEXT)) {
    addMessage(UI_MSG_ERROR, "[!] Unsafe DM rejected");
    return;
  }
  g_dm.recvSeq = sequence;
  historyAppend(senderToken, false, (char *)decrypted);
  rememberDmToken(senderToken);
  char dmLabel[64];
  formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
  addTimestamped(UI_MSG_CHAT, dmLabel, (char *)decrypted);
}

static void finalizeRoomSecretEntry(void) {
  if (g_input.creatingRoomSecret) {
    char saltHex[ROOM_SALT_HEX_SIZE];
    char verifierHex[SHA256_HEX_SIZE];
    unsigned char roomKey[32] = {0};
    if (strlen(g_input.roomSecret) < ROOM_SECRET_MIN_LEN) {
      addMessage(UI_MSG_ERROR,
                 "[!] Room secret must contain at least 12 characters");
    } else if (!createRoomSecrets(g_room.pendingName, g_input.roomSecret,
                                  saltHex, verifierHex, roomKey)) {
      addMessage(UI_MSG_ERROR, "[!] Failed to derive room secret");
    } else {
      char frame[MSG_SIZE];
      snprintf(frame, sizeof(frame), "ROOM_CREATE|%s|PROTECTED|%s|%s|%s\n",
               g_room.pendingName, ROOM_KDF_ID, saltHex, verifierHex);
      sendRawFrame(frame);
    }
    OPENSSL_cleanse(roomKey, sizeof(roomKey));
    goto cleanup;
  }

  char verifier[SHA256_HEX_SIZE];
  if (!verifyRoomSecret(g_room.pendingName, g_input.roomSecret,
                        g_room.pendingSalt, verifier, g_room.pendingKey)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to derive room secret");
  } else {
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "ROOM_PROOF|%s|%s\n", g_room.pendingName,
             verifier);
    sendRawFrame(frame);
  }

cleanup:
  OPENSSL_cleanse(g_input.roomSecret, sizeof(g_input.roomSecret));
  g_input.roomSecretLen = 0;
  g_input.readingRoomSecret = false;
  g_input.creatingRoomSecret = false;
}

static void handleDmInit(const char *senderToken, const char *sessionId,
                         const char *peerPubHex, const char *sigHex) {
  if (!protocolIsHex(senderToken, TOKEN_HEX_LEN) ||
      !protocolIsHex(sessionId, DM_SESSION_ID_HEX_LEN) ||
      !protocolIsHex(peerPubHex, 64) || !protocolIsHex(sigHex, SIG_HEX_LEN)) {
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
  if (!verifyDmFrame("DM_INIT", senderToken, g_identity.token, sessionId,
                     peerPubHex, "-", sig)) {
    addMessage(UI_MSG_ERROR, "[!] DM_INIT signature verification failed");
    return;
  }
  if (!rememberDmSession(sessionId)) {
    addMessage(UI_MSG_ERROR, "[!] Replayed DM request rejected");
    return;
  }
  if (g_dm.active || g_dm.awaitingAck) {
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "DM_REJECT|%s|%s|BUSY\n", senderToken,
             sessionId);
    sendRawFrame(frame);
    addMessage(UI_MSG_INFO, "[*] DM request rejected: session busy");
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
                            sessionId, peerPub, myPub, sessionKey)) {
    OPENSSL_cleanse(myPriv, sizeof(myPriv));
    addMessage(UI_MSG_ERROR, "[!] Failed to derive DM session key");
    return;
  }

  char myPubHex[65];
  bytesToHex(myPub, sizeof(myPub), myPubHex);
  unsigned char ackSig[SIG_BYTES];
  if (!signDmFrame("DM_ACK", g_identity.token, senderToken, sessionId,
                   peerPubHex, myPubHex, ackSig)) {
    OPENSSL_cleanse(myPriv, sizeof(myPriv));
    OPENSSL_cleanse(sessionKey, sizeof(sessionKey));
    addMessage(UI_MSG_ERROR, "[!] Failed to sign DM acknowledgment");
    return;
  }

  char ackSigHex[SIG_HEX_SIZE];
  bytesToHex(ackSig, sizeof(ackSig), ackSigHex);
  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "DM_ACK|%s|%s|%s|%s|%s\n", senderToken,
           sessionId, peerPubHex, myPubHex, ackSigHex);
  if (!sendRawFrame(frame)) {
    OPENSSL_cleanse(myPriv, sizeof(myPriv));
    OPENSSL_cleanse(sessionKey, sizeof(sessionKey));
    return;
  }

  clearDmSession();
  g_dm.active = true;
  snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", senderToken);
  snprintf(g_dm.sessionId, sizeof(g_dm.sessionId), "%s", sessionId);
  memcpy(g_dm.key, sessionKey, sizeof(sessionKey));
  OPENSSL_cleanse(myPriv, sizeof(myPriv));
  OPENSSL_cleanse(sessionKey, sizeof(sessionKey));
  rememberDmToken(senderToken);
  char dmLabel[64];
  formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
  addMessage(UI_MSG_INFO, "[*] DM session established with %s", dmLabel);
}

static void handleDmAck(const char *senderToken, const char *sessionId,
                        const char *initiatorPubHex, const char *peerPubHex,
                        const char *sigHex) {
  if (!g_dm.awaitingAck || strcmp(g_dm.peerToken, senderToken) != 0 ||
      strcmp(g_dm.sessionId, sessionId) != 0)
    return;

  unsigned char sig[SIG_BYTES];
  unsigned char peerPub[32];
  char expectedInitiatorPubHex[65];
  bytesToHex(g_dm.pendingPub, sizeof(g_dm.pendingPub), expectedInitiatorPubHex);
  if (!protocolIsHex(initiatorPubHex, 64) ||
      strcmp(initiatorPubHex, expectedInitiatorPubHex) != 0 ||
      !hexToBytes(sigHex, sig, sizeof(sig)) ||
      !hexToBytes(peerPubHex, peerPub, sizeof(peerPub))) {
    addMessage(UI_MSG_ERROR, "[!] Invalid DM_ACK encoding");
    return;
  }

  if (!verifyDmFrame("DM_ACK", senderToken, g_identity.token, sessionId,
                     initiatorPubHex, peerPubHex, sig)) {
    addMessage(UI_MSG_ERROR, "[!] DM_ACK signature verification failed");
    return;
  }

  unsigned char sessionKey[32];
  if (!ecdhDeriveSessionKey(g_dm.pendingPriv, peerPub, g_identity.token,
                            senderToken, sessionId, g_dm.pendingPub, peerPub,
                            sessionKey)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to derive DM session key");
    return;
  }

  g_dm.active = true;
  g_dm.awaitingAck = false;
  memcpy(g_dm.key, sessionKey, sizeof(sessionKey));
  OPENSSL_cleanse(sessionKey, sizeof(sessionKey));
  OPENSSL_cleanse(g_dm.pendingPriv, sizeof(g_dm.pendingPriv));
  OPENSSL_cleanse(g_dm.pendingPub, sizeof(g_dm.pendingPub));
  rememberDmToken(senderToken);
  char dmLabel[64];
  formatDmLabel(senderToken, dmLabel, sizeof(dmLabel));
  addMessage(UI_MSG_INFO, "[*] DM session ready with %s", dmLabel);
}

static void handleDmReject(const char *senderToken, const char *sessionId,
                           const char *reason) {
  if (!protocolIsHex(senderToken, TOKEN_HEX_LEN) ||
      !protocolIsHex(sessionId, DM_SESSION_ID_HEX_LEN) ||
      strcmp(reason, "BUSY") != 0 || !g_dm.awaitingAck ||
      strcmp(g_dm.peerToken, senderToken) != 0 ||
      strcmp(g_dm.sessionId, sessionId) != 0)
    return;

  clearDmSession();
  addMessage(UI_MSG_INFO, "[*] Peer is busy with another DM session");
}

static void handleDmClose(const char *senderToken, const char *sessionId) {
  if (!protocolIsHex(senderToken, TOKEN_HEX_LEN) ||
      !protocolIsHex(sessionId, DM_SESSION_ID_HEX_LEN) ||
      strcmp(g_dm.peerToken, senderToken) != 0 ||
      strcmp(g_dm.sessionId, sessionId) != 0)
    return;

  clearDmSession();
  addMessage(UI_MSG_INFO, "[*] Peer closed the DM session");
}

static void displayIncomingMessage(char *buffer) {
  char *parts[PROTOCOL_MAX_PARTS] = {0};
  size_t partCount = protocolSplitFields(buffer, parts, PROTOCOL_MAX_PARTS);
  if (partCount == 0)
    return;

  clientLog("recv: %.160s", buffer);

  if (strcmp(parts[0], "ERR") == 0 && partCount >= 2) {
    if (strcmp(parts[1], "NAME_IN_USE") == 0) {
      addMessage(UI_MSG_ERROR, "[!] Name is already in use");
      g_pendingUsername[0] = '\0';
      if (!g_hasConfirmedName) {
        snprintf(g_pendingUsername, sizeof(g_pendingUsername), "%.12s",
                 g_identity.token);
        char frame[MSG_SIZE];
        snprintf(frame, sizeof(frame), "SET_NAME|%s\n", g_pendingUsername);
        sendRawFrame(frame);
      }
    } else {
      if (protocolIsSafeText(parts[1], 256))
        addMessage(UI_MSG_ERROR, "[!] %s", parts[1]);
      else
        addMessage(UI_MSG_ERROR, "[!] Unsafe server error rejected");
    }
  } else if (strcmp(parts[0], "OK") == 0 && partCount >= 2) {
    if (strcmp(parts[1], "ROOM_ENTERED") == 0 && partCount >= 3) {
      g_room.active = true;
      snprintf(g_room.currentName, sizeof(g_room.currentName), "%s",
               g_room.pendingName);
      g_room.protectedRoom = strcmp(parts[2], "PROTECTED") == 0;
      if (g_room.protectedRoom)
        memcpy(g_room.key, g_room.pendingKey, sizeof(g_room.key));
      if (!startRoomSession()) {
        clearRoomState();
        addMessage(UI_MSG_ERROR, "[!] Failed to start room session");
        return;
      }
      addMessage(UI_MSG_INFO, "[*] Entered room %s", g_room.currentName);
    } else if (strcmp(parts[1], "ROOM_LEFT") == 0) {
      clearRoomState();
      addMessage(UI_MSG_INFO, "[*] Left room");
    } else if (strcmp(parts[1], "ROOM_CREATED") == 0) {
      addMessage(UI_MSG_INFO, "[*] Room created");
    } else if (strcmp(parts[1], "NAME_SET") == 0 && partCount >= 3 &&
               protocolIsSafeIdentifier(parts[2])) {
      snprintf(g_username, sizeof(g_username), "%s", parts[2]);
      identitySaveUsername(g_username);
      g_pendingUsername[0] = '\0';
      g_hasConfirmedName = true;
      addMessage(UI_MSG_INFO, "[*] Name updated");
    }
  } else if (strcmp(parts[0], "INFO") == 0 && partCount >= 2) {
    if (strcmp(parts[1], "ROOMS_BEGIN") == 0) {
      g_roomCount = 0;
      g_roomsLoading = true;
      addMessage(UI_MSG_INFO, "[*] Refreshing rooms");
    } else if (strcmp(parts[1], "ROOM") == 0 && partCount == 4 &&
               protocolIsSafeIdentifier(parts[2]) &&
               (strcmp(parts[3], "OPEN") == 0 ||
                strcmp(parts[3], "PROTECTED") == 0)) {
      if (g_roomCount < 50) {
        snprintf(g_rooms[g_roomCount], sizeof(g_rooms[g_roomCount]), "%s",
                 parts[2]);
        snprintf(g_roomTypes[g_roomCount], sizeof(g_roomTypes[g_roomCount]),
                 "%s", parts[3]);
        g_roomCount++;
      }
    } else if (strcmp(parts[1], "ROOMS_END") == 0) {
      g_roomsLoading = false;
    } else if (strcmp(parts[1], "MEMBERS_BEGIN") == 0 && partCount == 3 &&
               protocolIsSafeIdentifier(parts[2])) {
      addMessage(UI_MSG_INFO, "[*] Members in #%s", parts[2]);
    } else if (strcmp(parts[1], "MEMBER") == 0 && partCount >= 5 &&
               protocolIsSafeIdentifier(parts[2]) &&
               protocolIsHex(parts[3], TOKEN_HEX_LEN)) {
      addMessage(UI_MSG_INFO, "    %-18s %.12s%s", parts[2], parts[3],
                 strcmp(parts[4], "OWNER") == 0 ? " [owner]" : "");
    } else if (strcmp(parts[1], "MEMBERS_END") == 0) {
    } else if (strcmp(parts[1], "ROOM_TOPIC") == 0 && partCount >= 4) {
      if (strcmp(parts[2], "-") == 0) {
        addMessage(UI_MSG_INFO, "[*] Room topic is not set");
      } else {
        char topic[MAX_ROOM_TOPIC_LEN];
        if (!protocolDecodeText(parts[2], topic, sizeof(topic)) ||
            !protocolIsSafeText(topic, MAX_ROOM_TOPIC_LEN - 1)) {
          addMessage(UI_MSG_ERROR, "[!] Unsafe room topic rejected");
        } else if (strcmp(parts[3], "-") == 0) {
          addMessage(UI_MSG_INFO, "[*] Topic: %s", topic);
        } else if (protocolIsSafeIdentifier(parts[3])) {
          addMessage(UI_MSG_INFO, "[*] %s set topic: %s", parts[3], topic);
        }
      }
    } else if (strcmp(parts[1], "ROOM_JOINED") == 0 && partCount == 3 &&
               protocolIsSafeIdentifier(parts[2])) {
      addMessage(UI_MSG_INFO, "[*] %s joined the room", parts[2]);
    } else if (strcmp(parts[1], "ROOM_LEFT") == 0 && partCount == 3 &&
               protocolIsSafeIdentifier(parts[2])) {
      addMessage(UI_MSG_INFO, "[*] %s left the room", parts[2]);
    } else if (strcmp(parts[1], "NAME_CHANGED") == 0 && partCount == 4 &&
               protocolIsSafeIdentifier(parts[2]) &&
               protocolIsSafeIdentifier(parts[3])) {
      addMessage(UI_MSG_INFO, "[*] %s is now %s", parts[2], parts[3]);
    }
  } else if (strcmp(parts[0], "ROOM_CHALLENGE") == 0 && partCount == 4 &&
             protocolIsSafeIdentifier(parts[1]) &&
             strcmp(parts[2], ROOM_KDF_ID) == 0 &&
             protocolIsHex(parts[3], ROOM_SALT_HEX_SIZE - 1)) {
    snprintf(g_room.pendingName, sizeof(g_room.pendingName), "%s", parts[1]);
    snprintf(g_room.pendingSalt, sizeof(g_room.pendingSalt), "%s", parts[3]);
    g_input.readingRoomSecret = true;
    g_input.roomSecret[0] = '\0';
    g_input.roomSecretLen = 0;
    addMessage(UI_MSG_INFO, "[*] Enter the room secret below");
  } else if (strcmp(parts[0], "ROOM_MSG") == 0 && partCount == 7) {
    showRoomMessage(parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]);
  } else if (strcmp(parts[0], "DM_INIT") == 0 && partCount == 5) {
    handleDmInit(parts[1], parts[2], parts[3], parts[4]);
  } else if (strcmp(parts[0], "DM_ACK") == 0 && partCount == 6) {
    handleDmAck(parts[1], parts[2], parts[3], parts[4], parts[5]);
  } else if (strcmp(parts[0], "DM_REJECT") == 0 && partCount == 4) {
    handleDmReject(parts[1], parts[2], parts[3]);
  } else if (strcmp(parts[0], "DM_CLOSE") == 0 && partCount == 3) {
    handleDmClose(parts[1], parts[2]);
  } else if (strcmp(parts[0], "DM_MSG") == 0 && partCount == 5) {
    showDmMessage(parts[1], parts[2], parts[3], parts[4]);
  } else {
    addMessage(UI_MSG_ERROR, "[!] Unknown frame from server");
  }
}

static void handleDisconnect(void) {
  pthread_mutex_lock(&g_stateMutex);
  g_input.connected = false;
  addMessage(UI_MSG_ERROR, "[!] Disconnected from server");
  pthread_mutex_unlock(&g_stateMutex);
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
    int wrappedCount =
        wrapTextToWidth(g_messages[i].text, contentW, wrapped,
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
    int wrappedCount =
        wrapTextToWidth(g_messages[msg].text, contentW, wrapped,
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
      fgR = 233;
      fgG = 196;
      fgB = 106;
      break;
    case UI_MSG_ERROR:
      fgR = 239;
      fgG = 108;
      fgB = 96;
      break;
    case UI_MSG_SELF:
      fgR = 152;
      fgG = 195;
      fgB = 121;
      break;
    case UI_MSG_CHAT:
    default:
      fgR = 191;
      fgG = 203;
      fgB = 214;
      break;
    }

    char padded[UI_RENDER_LINE_MAX];
    snprintf(padded, sizeof(padded), "%-*.*s", contentW, contentW,
             rendered[row]);
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
    uiFormatKeyValueLine("you", g_username, contentW, line, sizeof(line));
    uiDrawText(row++, x + 2, 223, 228, 231, theme->panelR, theme->panelG,
               theme->panelB, line);
  }
  if (row < endRow) {
    char line[128];
    uiFormatKeyValueLine("space", context, contentW, line, sizeof(line));
    uiDrawText(row++, x + 2, 223, 228, 231, theme->panelR, theme->panelG,
               theme->panelB, line);
  }
  if (row < endRow) {
    char line[128];
    uiFormatKeyValueLine("lock", security, contentW, line, sizeof(line));
    uiDrawText(row++, x + 2, theme->accentR, theme->accentG, theme->accentB,
               theme->panelR, theme->panelG, theme->panelB, line);
  }
  if (row < endRow) {
    char line[128];
    uiFormatKeyValueLine("relay", g_input.connected ? g_serverLabel : "offline",
                         contentW, line, sizeof(line));
    uiDrawText(row++, x + 2, theme->mutedR, theme->mutedG, theme->mutedB,
               theme->panelR, theme->panelG, theme->panelB, line);
  }

  if (row < endRow)
    row++;

  char roomsCount[32];
  snprintf(roomsCount, sizeof(roomsCount), "(%d)", g_roomCount);
  if (row < endRow)
    uiDrawSectionLabel(row++, x + 2, contentW, "ROOMS", roomsCount, theme);
  if (g_roomsLoading && row < endRow) {
    uiDrawTextFitted(row++, x + 2, contentW, theme->mutedR, theme->mutedG,
                     theme->mutedB, theme->panelR, theme->panelG, theme->panelB,
                     "Refreshing room list...");
  } else if (g_roomCount == 0 && row < endRow) {
    uiDrawTextFitted(row++, x + 2, contentW, theme->mutedR, theme->mutedG,
                     theme->mutedB, theme->panelR, theme->panelG, theme->panelB,
                     "No rooms cached yet");
  }
  for (int i = 0; i < g_roomCount && row < endRow; i++) {
    char line[128];
    const char marker = strcmp(g_rooms[i], g_room.currentName) == 0 ? '>' : ' ';
    const char *roomType =
        strcmp(g_roomTypes[i], "PROTECTED") == 0 ? "e2e" : "open";
    uiFormatRoomLine(marker, g_rooms[i], roomType, contentW, line,
                     sizeof(line));
    uiDrawText(row++, x + 2, marker == '>' ? 246 : 223,
               marker == '>' ? 214 : 228, marker == '>' ? 133 : 231,
               theme->panelR, theme->panelG, theme->panelB, line);
  }

  if (row < endRow)
    row++;

  char dmCountText[32];
  snprintf(dmCountText, sizeof(dmCountText), "(%d)", dmContactCount());
  if (row < endRow)
    uiDrawSectionLabel(row++, x + 2, contentW, "DIRECT", dmCountText, theme);
  if (dmContactCount() == 0 && row < endRow) {
    uiDrawTextFitted(row++, x + 2, contentW, theme->mutedR, theme->mutedG,
                     theme->mutedB, theme->panelR, theme->panelG, theme->panelB,
                     "No DM history yet");
  }
  for (int i = 0; i < dmContactCount() && row < endRow; i++) {
    const DmContact *contact = contactsGet(&g_contacts, (size_t)i);
    if (!contact)
      continue;
    char line[128];
    uiFormatContactLine(contact, i + 1,
                        strcmp(contact->token, g_dm.peerToken) == 0, contentW,
                        line, sizeof(line));
    uiDrawText(row++, x + 2,
               strcmp(contact->token, g_dm.peerToken) == 0 ? 144 : 223,
               strcmp(contact->token, g_dm.peerToken) == 0 ? 224 : 228,
               strcmp(contact->token, g_dm.peerToken) == 0 ? 203 : 231,
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
  bool tight = contentW < 52;
  if (g_input.readingRoomSecret) {
    snprintf(prompt, sizeof(prompt), "secret for #%s",
             g_room.pendingName[0] ? g_room.pendingName : "room");
    snprintf(meta, sizeof(meta), "verifier only");
    snprintf(note, sizeof(note), "%s",
             tight ? "Masked locally while you type."
                   : "Local masking stays on while you type.");
  } else if (g_dm.active) {
    char dmLabel[64];
    formatDmLabel(g_dm.peerToken, dmLabel, sizeof(dmLabel));
    snprintf(prompt, sizeof(prompt), "direct to %s", dmLabel);
    snprintf(meta, sizeof(meta), "dm e2e");
    snprintf(note, sizeof(note), "%s",
             tight ? "/dmleave closes this session."
                   : "Handshake is live. /dmleave exits the session.");
  } else if (g_room.active) {
    snprintf(prompt, sizeof(prompt), "room #%s", g_room.currentName);
    snprintf(meta, sizeof(meta), "%s",
             g_room.protectedRoom ? "room e2e" : "relay-visible");
    snprintf(note, sizeof(note), "%s",
             g_room.protectedRoom
                 ? (tight ? "Encrypted before send."
                          : "Messages encrypt before they leave this terminal.")
                 : (tight ? "Room traffic is relay-visible."
                          : "This room is not end-to-end encrypted."));
  } else {
    snprintf(prompt, sizeof(prompt), "lobby");
    snprintf(meta, sizeof(meta), "commands");
    snprintf(note, sizeof(note), "%s",
             tight ? "/rooms /enter /create /dm /help"
                   : "Use /search, /rooms, /enter, /create, /dm, or /help.");
  }

  char countText[96];
  size_t currentLen =
      g_input.readingRoomSecret ? g_input.roomSecretLen : g_input.length;
  snprintf(countText, sizeof(countText), "%s  %zu/%d", meta, currentLen,
           MSG_SIZE - 1);

  int promptWidth = contentW;
  int countWidth = (int)strlen(countText);
  if (countWidth + 3 < contentW)
    promptWidth = contentW - countWidth - 2;
  char promptLine[UI_RENDER_LINE_MAX];
  uiCopyFittedText(prompt, promptWidth, promptLine, sizeof(promptLine));
  uiDrawText(y + 1, x + 2, theme->accentR, theme->accentG, theme->accentB,
             theme->panelR, theme->panelG, theme->panelB, promptLine);
  uiDrawTextRight(y + 1, x + w - 3, theme->mutedR, theme->mutedG, theme->mutedB,
                  theme->panelR, theme->panelG, theme->panelB, countText);

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
  const char *placeholder =
      g_input.readingRoomSecret
          ? ""
          : (tight ? "Type message or command" : "Type a message or command");
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
  uiDrawText(y + 2, x + 4, hasInput ? 233 : theme->mutedR,
             hasInput ? 237 : theme->mutedG, hasInput ? 243 : theme->mutedB,
             theme->panelR, theme->panelG, theme->panelB, inputLine);

  if (h >= 5) {
    uiDrawTextFitted(y + 3, x + 2, contentW, theme->mutedR, theme->mutedG,
                     theme->mutedB, theme->panelR, theme->panelG, theme->panelB,
                     note);
  }

  int cursorOffset =
      hasInput ? clampInt((int)currentLen - scrollStart, 0, textW) : 0;
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
  uiDrawTextFitted(y + 3, x + 2, w - 4, 233, 237, 243, theme->panelR,
                   theme->panelG, theme->panelB,
                   "/rooms   /create <room>   /create <room> -p [secret]");
  uiDrawTextFitted(y + 4, x + 2, w - 4, 233, 237, 243, theme->panelR,
                   theme->panelG, theme->panelB,
                   "/enter <room>   /leave   /members   /topic [text|-]");
  uiDrawSectionLabel(y + 6, x + 2, w - 4, "DIRECT", NULL, theme);
  uiDrawTextFitted(y + 7, x + 2, w - 4, 233, 237, 243, theme->panelR,
                   theme->panelG, theme->panelB,
                   "/dm <contact>   /dmleave   /list   /search <query>");
  uiDrawTextFitted(y + 8, x + 2, w - 4, 233, 237, 243, theme->panelR,
                   theme->panelG, theme->panelB,
                   "/nick [@|contact] <name>   /nick <contact> -   /token");
  uiDrawSectionLabel(y + 10, x + 2, w - 4, "BASICS", NULL, theme);
  uiDrawTextFitted(y + 11, x + 2, w - 4, 233, 237, 243, theme->panelR,
                   theme->panelG, theme->panelB,
                   "/name <name>   /help   /exit");
  if (h >= 15) {
    uiDrawTextFitted(y + 12, x + 2, w - 4, theme->accentR, theme->accentG,
                     theme->accentB, theme->panelR, theme->panelG,
                     theme->panelB,
                     "Enter sends. Up/Down scroll. PgUp/PgDn jumps. /help "
                     "toggles this panel.");
    uiDrawTextFitted(y + 13, x + 2, w - 4, theme->mutedR, theme->mutedG,
                     theme->mutedB, theme->panelR, theme->panelG, theme->panelB,
                     "Protected rooms and DMs stay encrypted on the client.");
  } else {
    uiDrawTextFitted(y + 12, x + 2, w - 4, theme->mutedR, theme->mutedG,
                     theme->mutedB, theme->panelR, theme->panelG, theme->panelB,
                     "Enter sends. Up/Down scroll. /help closes help.");
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

  bool showSidebar = cols >= 96 && rows >= 18;
  bool compact = !showSidebar;
  int topH = compact ? 1 : 2;
  int inputH = rows >= 21 ? 5 : 4;
  int sidebar = showSidebar
                    ? clampInt(cols / 3, SIDEBAR_MIN_WIDTH, SIDEBAR_MAX_WIDTH)
                    : 0;
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
    char compactStatus[256];
    snprintf(compactStatus, sizeof(compactStatus), "%s | %s | %s%s | /help",
             connected ? "connected" : "offline", context, security,
             g_roomsLoading ? " | syncing rooms" : "");
    bool showIdentity = cols >= 74;
    int statusWidth = cols - 16;
    if (showIdentity)
      statusWidth -= (int)strlen(identityText) + 2;
    uiDrawTextFitted(1, 15, statusWidth, connected ? 152 : 239,
                     connected ? 195 : 108, connected ? 121 : 96, 18, 23, 30,
                     compactStatus);
    if (showIdentity) {
      uiDrawTextRight(1, cols - 2, 127, 140, 156, 18, 23, 30, identityText);
    }

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
    snprintf(statusLine, sizeof(statusLine),
             "%s | relay %s | rooms %d | direct %d%s | /help",
             connected ? "connected" : "offline", g_serverLabel, g_roomCount,
             dmContactCount(), g_roomsLoading ? " | syncing" : "");
    uiDrawTextFitted(2, 2, cols - 3, 127, 140, 156, 21, 25, 31, statusLine);

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
    int wrappedCount =
        wrapTextToWidth(g_messages[i].text, messageW - 4, wrapped,
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
  KEY_PGDN
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
      if (seq[1] == '3') {
        ssize_t r = read(STDIN_FILENO, &seq[2], 1);
        (void)r;
        return (KeyEvent){KEY_BACKSPACE, 0};
      }
      if (seq[1] == '5') {
        ssize_t r = read(STDIN_FILENO, &seq[2], 1);
        (void)r;
        return (KeyEvent){KEY_PGUP, 0};
      }
      if (seq[1] == '6') {
        ssize_t r = read(STDIN_FILENO, &seq[2], 1);
        (void)r;
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
  if (dmContactCount() == 0) {
    addMessage(UI_MSG_INFO, "[*] No DM contacts yet");
    return;
  }

  addMessage(UI_MSG_INFO, "[*] Direct contacts:");
  for (int i = 0; i < dmContactCount(); i++) {
    char reference[128];
    contactsFormatReference(&g_contacts, (size_t)i, reference,
                            sizeof(reference));
    addMessage(UI_MSG_INFO, "    %d. %s", i + 1, reference);
  }
}

static void handleNickCommand(const char *target, const char *nick) {
  reloadDmHistoryIndex();

  char token[TOKEN_STR_SIZE] = {0};
  if (!target || !target[0] || strcmp(target, "@") == 0) {
    if (!g_dm.active) {
      addMessage(UI_MSG_ERROR,
                 "[!] Start a DM first or pass a contact reference");
      return;
    }
    snprintf(token, sizeof(token), "%s", g_dm.peerToken);
  } else if (!resolveDmReference(target, token, sizeof(token), true, true)) {
    return;
  }

  if (strcmp(nick, "-") == 0) {
    if (!contactsClearNickname(&g_contacts, token)) {
      addMessage(UI_MSG_ERROR, "[!] No nickname is set for that contact");
      return;
    }
    saveDmNicknames();
    addMessage(UI_MSG_INFO, "[*] Nickname cleared");
    return;
  }

  char error[128];
  if (!contactsSetNickname(&g_contacts, token, nick, error, sizeof(error))) {
    addMessage(UI_MSG_ERROR, "[!] %s", error);
    return;
  }
  saveDmNicknames();
  addMessage(UI_MSG_INFO, "[*] Nickname saved");
}

static void handleSearchCommand(const char *query) {
  reloadDmHistoryIndex();

  ContactMatch matches[8];
  size_t matchCount = contactsSearch(&g_contacts, query, matches, 8);
  showContactMatches(query, matches, matchCount);
}

static void handleDmCommand(const char *input) {
  reloadDmHistoryIndex();

  if (g_dm.active || g_dm.awaitingAck) {
    addMessage(UI_MSG_ERROR, "[!] Close current DM with /dmleave first");
    return;
  }

  char token[TOKEN_STR_SIZE] = {0};
  if (!resolveDmReference(input, token, sizeof(token), true, true))
    return;

  unsigned char myPub[32];
  unsigned char myPriv[32];
  if (!x25519GenerateKeypair(myPub, myPriv)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to generate DM session keys");
    return;
  }

  char myPubHex[65];
  bytesToHex(myPub, sizeof(myPub), myPubHex);

  unsigned char sessionBytes[DM_SESSION_ID_BYTES];
  char sessionId[DM_SESSION_ID_SIZE];
  if (RAND_bytes(sessionBytes, sizeof(sessionBytes)) != 1) {
    addMessage(UI_MSG_ERROR, "[!] Failed to create DM session ID");
    OPENSSL_cleanse(myPriv, sizeof(myPriv));
    return;
  }
  bytesToHex(sessionBytes, sizeof(sessionBytes), sessionId);

  unsigned char sig[SIG_BYTES];
  if (!signDmFrame("DM_INIT", g_identity.token, token, sessionId, myPubHex, "-",
                   sig)) {
    addMessage(UI_MSG_ERROR, "[!] Failed to sign DM request");
    memset(myPriv, 0, sizeof(myPriv));
    return;
  }

  char sigHex[SIG_HEX_SIZE];
  bytesToHex(sig, sizeof(sig), sigHex);
  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "DM_INIT|%s|%s|%s|%s\n", token, sessionId,
           myPubHex, sigHex);
  if (!sendRawFrame(frame)) {
    memset(myPriv, 0, sizeof(myPriv));
    addMessage(UI_MSG_ERROR, "[!] Failed to send DM request");
    return;
  }

  clearDmSession();
  g_dm.awaitingAck = true;
  snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", token);
  snprintf(g_dm.sessionId, sizeof(g_dm.sessionId), "%s", sessionId);
  memcpy(g_dm.pendingPriv, myPriv, sizeof(g_dm.pendingPriv));
  memcpy(g_dm.pendingPub, myPub, sizeof(g_dm.pendingPub));
  OPENSSL_cleanse(myPriv, sizeof(myPriv));
  rememberDmToken(token);
  char dmLabel[64];
  formatDmLabel(token, dmLabel, sizeof(dmLabel));
  addMessage(UI_MSG_INFO, "[*] DM request sent to %s", dmLabel);
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
    if (sscanf(message + 6, "%63s", name) != 1 ||
        !protocolIsSafeIdentifier(name)) {
      addMessage(UI_MSG_ERROR, "[!] Invalid name");
      return true;
    }
    snprintf(g_pendingUsername, sizeof(g_pendingUsername), "%s", name);
    char frame[MSG_SIZE];
    snprintf(frame, sizeof(frame), "SET_NAME|%s\n", name);
    sendRawFrame(frame);
    return true;
  }
  if (strcmp(message, "/rooms") == 0) {
    sendRawFrame("ROOM_LIST\n");
    return true;
  }
  if (strcmp(message, "/members") == 0) {
    sendRawFrame("ROOM_MEMBERS\n");
    return true;
  }
  if (strcmp(message, "/topic") == 0) {
    sendRawFrame("ROOM_TOPIC_GET\n");
    return true;
  }
  if (strncmp(message, "/topic ", 7) == 0) {
    char topic[MAX_ROOM_TOPIC_LEN];
    copyTrimmed(message + 7, topic, sizeof(topic));
    if (!topic[0] || !protocolIsSafeText(topic, MAX_ROOM_TOPIC_LEN - 1)) {
      addMessage(UI_MSG_ERROR, "[!] Invalid room topic");
      return true;
    }

    char encoded[MSG_SIZE];
    if (strcmp(topic, "-") == 0) {
      snprintf(encoded, sizeof(encoded), "-");
    } else if (!protocolEncodeText(topic, encoded, sizeof(encoded))) {
      addMessage(UI_MSG_ERROR, "[!] Room topic is too long");
      return true;
    }

    char frame[MSG_SIZE + 32];
    snprintf(frame, sizeof(frame), "ROOM_TOPIC_SET|%s\n", encoded);
    sendRawFrame(frame);
    return true;
  }
  if (strcmp(message, "/create") == 0 || strncmp(message, "/create ", 8) == 0) {
    char room[MAX_NAME_LEN];
    const char *inlineSecret = NULL;
    ProtocolRoomCreateMode mode = protocolParseRoomCreateArgs(
        message + 7, room, sizeof(room), &inlineSecret);
    if (mode == PROTOCOL_ROOM_CREATE_INVALID) {
      addMessage(UI_MSG_ERROR, "[!] Usage: /create <room> [-p [secret]]");
      return true;
    }
    if (mode != PROTOCOL_ROOM_CREATE_OPEN) {
      snprintf(g_room.pendingName, sizeof(g_room.pendingName), "%s", room);
      g_input.readingRoomSecret = true;
      g_input.creatingRoomSecret = true;
      if (mode == PROTOCOL_ROOM_CREATE_INLINE) {
        snprintf(g_input.roomSecret, sizeof(g_input.roomSecret), "%s",
                 inlineSecret);
        g_input.roomSecretLen = strlen(g_input.roomSecret);
        finalizeRoomSecretEntry();
      } else {
        g_input.roomSecret[0] = '\0';
        g_input.roomSecretLen = 0;
        addMessage(UI_MSG_INFO, "[*] Enter new room secret below");
      }
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
  if (strncmp(message, "/search ", 8) == 0) {
    char query[128];
    copyTrimmed(message + 8, query, sizeof(query));
    if (!query[0]) {
      addMessage(UI_MSG_ERROR, "[!] Usage: /search <query>");
      return true;
    }
    handleSearchCommand(query);
    return true;
  }
  if (strcmp(message, "/token") == 0) {
    handleTokenCommand();
    return true;
  }
  if (strcmp(message, "/dmleave") == 0) {
    if (g_dm.peerToken[0] && g_dm.sessionId[0]) {
      char frame[MSG_SIZE];
      snprintf(frame, sizeof(frame), "DM_CLOSE|%s|%s\n", g_dm.peerToken,
               g_dm.sessionId);
      sendRawFrame(frame);
    }
    clearDmSession();
    addMessage(UI_MSG_INFO, "[*] DM session closed");
    return true;
  }
  if (strncmp(message, "/dm ", 4) == 0) {
    char target[128];
    copyTrimmed(message + 4, target, sizeof(target));
    if (!target[0]) {
      addMessage(UI_MSG_ERROR, "[!] Usage: /dm <contact>");
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
      addMessage(UI_MSG_ERROR, "[!] Usage: /nick [@|contact] <name>");
      return true;
    }

    if (strcmp(first, "@") == 0) {
      char nick[MAX_NAME_LEN];
      copyTrimmed(rest, nick, sizeof(nick));
      if (!nick[0]) {
        addMessage(UI_MSG_ERROR, "[!] Usage: /nick @ <name>");
        return true;
      }
      handleNickCommand("@", nick);
      return true;
    }

    if (!g_dm.active) {
      if (!rest || !rest[0]) {
        addMessage(UI_MSG_ERROR, "[!] Usage: /nick <contact> <name>");
        return true;
      }

      char nick[MAX_NAME_LEN];
      copyTrimmed(rest, nick, sizeof(nick));
      if (!nick[0]) {
        addMessage(UI_MSG_ERROR, "[!] Usage: /nick <contact> <name>");
        return true;
      }
      handleNickCommand(first, nick);
      return true;
    }

    if (rest && rest[0] && (isNumericReference(first) || isTokenHex(first))) {
      char probeToken[TOKEN_STR_SIZE];
      if (resolveDmReference(first, probeToken, sizeof(probeToken), true,
                             false)) {
        char nick[MAX_NAME_LEN];
        copyTrimmed(rest, nick, sizeof(nick));
        if (!nick[0]) {
          addMessage(UI_MSG_ERROR, "[!] Usage: /nick <contact> <name>");
          return true;
        }
        handleNickCommand(first, nick);
        return true;
      }
    }

    char nick[MAX_NAME_LEN];
    copyTrimmed(args, nick, sizeof(nick));
    if (!nick[0]) {
      addMessage(UI_MSG_ERROR, "[!] Usage: /nick [@|contact] <name>");
      return true;
    }
    handleNickCommand("@", nick);
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
    OPENSSL_cleanse(g_input.buffer, sizeof(g_input.buffer));
    g_input.length = 0;
    bool keepRunning = processCommand(message);
    OPENSSL_cleanse(message, sizeof(message));
    if (!keepRunning)
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
  bool redraw = true;
  int previousRows = 0;
  int previousCols = 0;
  while (true) {
    int rows = 0;
    int cols = 0;
    uiGetSize(&rows, &cols);
    if (rows != previousRows || cols != previousCols)
      redraw = true;

    pthread_mutex_lock(&g_stateMutex);
    bool connected = g_input.connected;
    if (redraw) {
      renderUi();
      previousRows = rows;
      previousCols = cols;
    }
    pthread_mutex_unlock(&g_stateMutex);
    if (!connected)
      break;
    redraw = false;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    FD_SET(g_socketFD, &rfds);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    bool networkReady = SSL_pending(g_ssl) > 0;
    int rc =
        networkReady ? 1 : select((int)g_socketFD + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0 && errno == EINTR)
      continue;
    if (rc < 0) {
      handleDisconnect();
      redraw = true;
      continue;
    }
    if (networkReady || FD_ISSET(g_socketFD, &rfds)) {
      char incoming[MSG_SIZE];
      ssize_t received =
          tlsRecvDeadline(g_ssl, incoming, sizeof(incoming), 5000);
      if (received <= 0) {
        handleDisconnect();
        continue;
      }
      pthread_mutex_lock(&g_stateMutex);
      displayIncomingMessage(incoming);
      pthread_mutex_unlock(&g_stateMutex);
      redraw = true;
      if (networkReady)
        continue;
    }
    if (rc > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
      KeyEvent key = readKeyEvent();
      pthread_mutex_lock(&g_stateMutex);
      handleKey(key);
      pthread_mutex_unlock(&g_stateMutex);
      redraw = true;
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
  g_ssl = tlsClientConnect(ctx, g_socketFD, 5000);
  SSL_CTX_free(ctx);
  if (!g_ssl)
    return false;

  char serverLabel[128];
  snprintf(serverLabel, sizeof(serverLabel), "%s:%d", ip, port);
  snprintf(g_serverLabel, sizeof(g_serverLabel), "%s", serverLabel);
  if (!tlsGetPeerFingerprint(g_ssl, g_serverFingerprint) ||
      !tlsTrustOnFirstUse(g_ssl, serverLabel)) {
    tlsFree(g_ssl);
    g_ssl = NULL;
    return false;
  }

  return true;
}

static bool authenticate(void) {
  char challengeBuf[MSG_SIZE];
  ssize_t n = tlsRecvDeadline(g_ssl, challengeBuf, sizeof(challengeBuf), 5000);
  if (n <= 0)
    return false;

  char *parts[PROTOCOL_MAX_PARTS] = {0};
  size_t partCount =
      protocolSplitFields(challengeBuf, parts, PROTOCOL_MAX_PARTS);
  if (partCount != 4 || strcmp(parts[0], "CHALLENGE") != 0 ||
      strcmp(parts[1], PROTOCOL_VERSION) != 0 ||
      strlen(parts[2]) != CHALLENGE_HEX_LEN ||
      strcmp(parts[3], g_serverFingerprint) != 0)
    return false;

  unsigned char nonce[CHALLENGE_BYTES];
  if (!hexToBytes(parts[2], nonce, sizeof(nonce)))
    return false;

  unsigned char transcript[160];
  size_t transcriptLen = 0;
  if (!protocolBuildAuthTranscript(nonce, sizeof(nonce), g_serverFingerprint,
                                   transcript, sizeof(transcript),
                                   &transcriptLen))
    return false;

  unsigned char sig[SIG_BYTES];
  if (!identitySign(&g_identity, transcript, transcriptLen, sig))
    return false;

  char sigHex[SIG_HEX_SIZE];
  bytesToHex(sig, sizeof(sig), sigHex);
  char frame[MSG_SIZE];
  snprintf(frame, sizeof(frame), "AUTH|%s|%s|%s\n", PROTOCOL_VERSION,
           g_identity.token, sigHex);
  if (!sendRawFrame(frame))
    return false;

  char ackBuf[MSG_SIZE];
  n = tlsRecvDeadline(g_ssl, ackBuf, sizeof(ackBuf), 5000);
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

  snprintf(g_username, sizeof(g_username), "%.12s", g_identity.token);
  if (!identityLoadUsername(g_pendingUsername, sizeof(g_pendingUsername)))
    snprintf(g_pendingUsername, sizeof(g_pendingUsername), "%s", g_username);
  reloadDmHistoryIndex();

  const char *ip = DEFAULT_IP;
  int port = DEFAULT_PORT;
  if (argc > 1) {
    char *arg = argv[1];
    char *colon = strchr(arg, ':');
    if (colon) {
      *colon = '\0';
      ip = arg;
      if (!protocolParsePort(colon + 1, &port)) {
        uiExit();
        fprintf(stderr, "Invalid port; expected 1-65535\n");
        return 1;
      }
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
  snprintf(nameFrame, sizeof(nameFrame), "SET_NAME|%s\n", g_pendingUsername);
  sendRawFrame(nameFrame);
  sendRawFrame("ROOM_LIST\n");
  addMessage(UI_MSG_INFO, "[*] Connected to server");
  addMessage(UI_MSG_INFO, "[*] Type /help for commands");

  eventLoop();
  if (g_socketFD != INVALID_SOCKET_HANDLE)
    platformShutdownSocket(g_socketFD);

  uiExit();
  if (g_ssl)
    tlsFree(g_ssl);
  if (g_socketFD != INVALID_SOCKET_HANDLE)
    platformCloseSocket(g_socketFD);
  g_socketFD = INVALID_SOCKET_HANDLE;
  pthread_mutex_destroy(&g_stateMutex);
  if (g_logFile)
    fclose(g_logFile);
  platformCleanup();
  return 0;
}
