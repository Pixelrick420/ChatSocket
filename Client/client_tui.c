#include "../Utils/aes.h"
#include "../Utils/ecdh.h"
#include "../Utils/history.h"
#include "../Utils/identity.h"
#include "../Utils/socketUtil.h"
#include "../Utils/tls.h"

#include <curses.h>
#include <menu.h>
#include <panel.h>
#include <pthread.h>
#include <time.h>

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 2077

#define COLOR_PAIR_MSG     1
#define COLOR_PAIR_NOTIF  2
#define COLOR_PAIR_ERROR  3
#define COLOR_PAIR_PROMPT 4
#define COLOR_PAIR_ROOM   5
#define COLOR_PAIR_DM     6
#define COLOR_PAIR_ACTIVE 7

static FILE *g_logFile = NULL;
static char g_logPath[256] = {0};

static void logOpen(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    pid_t pid = getpid();
    snprintf(g_logPath, sizeof(g_logPath), "%s/.socketchat/tui_%d.log", home, pid);
    g_logFile = fopen(g_logPath, "a");
    if (!g_logFile) {
        perror("log: fopen");
        return;
    }
    setvbuf(g_logFile, NULL, _IOLBF, 0);
}

static void clientLog(const char *fmt, ...) {
    if (!g_logFile) return;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32] = "?";
    if (t) strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", t);
    fprintf(g_logFile, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logFile, fmt, ap);
    va_end(ap);
    if (fmt[strlen(fmt) - 1] != '\n') fputc('\n', g_logFile);
}

static int g_socketFD = -1;
static SSL *g_ssl = NULL;
static Identity g_identity = {0};
static char g_username[MAX_NAME_LEN] = {0};

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

static bool g_readingPassword = false;
static char g_passwordBuffer[MSG_SIZE] = {0};
static size_t g_passwordLen = 0;
static bool g_waitingForRoomJoin = false;
static bool g_expectServerResponse = false;

static pthread_mutex_t g_inputMutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_connected = true;

typedef struct {
    char buffer[MSG_SIZE];
    size_t length;
} InputState;
static InputState g_inputState = {{0}, 0};

static WINDOW *g_msgWin = NULL;
static WINDOW *g_sidebarWin = NULL;
static WINDOW *g_inputWin = NULL;
static WINDOW *g_helpWin = NULL;

static int g_maxY = 0, g_maxX = 0;
static int g_sidebarX = 0;

static char g_rooms[50][MAX_NAME_LEN] = {{0}};
static int g_roomCount = 0;
static int g_selectedRoom = -1;

static char g_dmList[50][TOKEN_STR_SIZE] = {{0}};
static char g_dmNick[50][MAX_NAME_LEN] = {{0}};
static int g_dmCount = 0;
static int g_selectedDm = -1;

static bool g_showHelp = false;

typedef struct MessageNode {
    char text[MSG_SIZE * 2];
    struct MessageNode *next;
} MessageNode;
static MessageNode *g_msgHead = NULL;
static MessageNode *g_msgTail = NULL;
static int g_msgCount = 0;
static int g_msgScroll = 0;

static bool sendToServer(const char *message);

static void addMessage(const char *text) {
    MessageNode *node = calloc(1, sizeof(MessageNode));
    if (!node) return;
    snprintf(node->text, sizeof(node->text), "%s", text);
    node->next = NULL;
    if (g_msgTail) {
        g_msgTail->next = node;
        g_msgTail = node;
    } else {
        g_msgHead = g_msgTail = node;
    }
    g_msgCount++;
    while (g_msgCount > 1000 && g_msgHead) {
        MessageNode *tmp = g_msgHead;
        g_msgHead = g_msgHead->next;
        free(tmp);
        g_msgCount--;
    }
}

static void clearMessages(void) {
    while (g_msgHead) {
        MessageNode *tmp = g_msgHead;
        g_msgHead = g_msgHead->next;
        free(tmp);
    }
    g_msgTail = NULL;
    g_msgCount = 0;
}



static void commitRoomEntry(void) {
    clientLog("commitRoomEntry: entering room '%s'", g_pendingRoom.roomName);
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
    g_selectedRoom = -1;
    for (int i = 0; i < g_roomCount; i++) {
        if (strcmp(g_rooms[i], g_currentRoom) == 0) {
            g_selectedRoom = i;
            break;
        }
    }
    if (g_selectedRoom == -1 && g_roomCount < 50) {
        snprintf(g_rooms[g_roomCount++], MAX_NAME_LEN, "%s", g_currentRoom);
        g_selectedRoom = g_roomCount - 1;
    }
    memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
    clearMessages();
}

static void clearRoomState(void) {
    clientLog("clearRoomState: leaving room '%s'", g_currentRoom);
    memset(&g_encryption, 0, sizeof(g_encryption));
    memset(g_currentRoom, 0, sizeof(g_currentRoom));
    g_inRoom = false;
    g_selectedRoom = -1;
    memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
    clearMessages();
}

static void clearDmSession(void) {
    clientLog("clearDmSession");
    memset(&g_dm, 0, sizeof(g_dm));
    g_selectedDm = -1;
}

static bool encryptAndSendDm(const char *message, size_t msgLen) {
    unsigned char ciphertext[MSG_SIZE];
    int clen = encryptMessage((const unsigned char *)message, msgLen, g_dm.key, ciphertext);
    if (clen <= 0) return false;
    char encoded[MSG_SIZE * 2];
    encodeBase64(ciphertext, (size_t)clen, encoded);
    char toSend[MSG_SIZE * 2 + TOKEN_STR_SIZE + 16];
    snprintf(toSend, sizeof(toSend), "DM:%s:ENC:%s\n", g_dm.peerToken, encoded);
    return sendToServer(toSend);
}

static bool encryptAndSendRoom(const char *message, size_t msgLen) {
    unsigned char ciphertext[MSG_SIZE];
    int clen = encryptMessage((const unsigned char *)message, msgLen, g_encryption.key, ciphertext);
    if (clen <= 0) return false;
    char encoded[MSG_SIZE * 2];
    encodeBase64(ciphertext, (size_t)clen, encoded);
    char toSend[MSG_SIZE * 2 + 10];
    snprintf(toSend, sizeof(toSend), "ENC:%s\n", encoded);
    return sendToServer(toSend);
}

static void handleIncomingDm(const char *frame) {
    const char *p = frame + 3;
    if (strlen(p) < TOKEN_HEX_LEN + 1) return;
    char senderToken[TOKEN_STR_SIZE];
    memcpy(senderToken, p, TOKEN_HEX_LEN);
    senderToken[TOKEN_HEX_LEN] = '\0';
    const char *payload = p + TOKEN_HEX_LEN + 1;

    if (strncmp(payload, "DM_REQ:", 7) == 0) {
        const char *peerPubHex = payload + 7;
        char trimmed[TOKEN_STR_SIZE];
        snprintf(trimmed, sizeof(trimmed), "%.*s", TOKEN_HEX_LEN, peerPubHex);
        unsigned char peerPubX25519[32];
        if (!tokenToX25519PublicKey(trimmed, peerPubX25519)) return;
        unsigned char myPrivX25519[32];
        if (!identityEd25519PrivToX25519(g_identity.priv, myPrivX25519)) return;
        unsigned char sharedKey[32];
        bool ok = ecdhDeriveKey(myPrivX25519, peerPubX25519, sharedKey);
        memset(myPrivX25519, 0, sizeof(myPrivX25519));
        if (!ok) return;
        g_dm.pending = true;
        snprintf(g_dm.pendingToken, sizeof(g_dm.pendingToken), "%s", senderToken);
        memcpy(g_dm.pendingKey, sharedKey, 32);
        char shortToken[13];
        snprintf(shortToken, sizeof(shortToken), "%.10s", senderToken);
        char msg[MSG_SIZE];
        snprintf(msg, sizeof(msg), "[*] DM from %.16s... (use /dm %.64s to reply)\n",
                 shortToken, senderToken);
        addMessage(msg);
        bool found = false;
        for (int i = 0; i < g_dmCount; i++) {
            if (strcmp(g_dmList[i], senderToken) == 0) {
                found = true;
                break;
            }
        }
        if (!found && g_dmCount < 50) {
            snprintf(g_dmList[g_dmCount++], TOKEN_STR_SIZE, "%s", senderToken);
        }
        return;
    }

    if (strncmp(payload, "ENC:", 4) == 0) {
        if (g_dm.active && strncmp(g_dm.peerToken, senderToken, TOKEN_HEX_LEN) == 0) {
            unsigned char decoded[MSG_SIZE];
            int dlen = decodeBase64(payload + 4, decoded);
            if (dlen <= 0) return;
            unsigned char decrypted[MSG_SIZE];
            int plen = decryptMessage(decoded, (size_t)dlen, g_dm.key, decrypted);
            if (plen <= 0) return;
            decrypted[plen] = '\0';
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[16] = "00:00";
            if (tm_info) strftime(ts, sizeof(ts), "%H:%M", tm_info);
            char msg[MSG_SIZE * 2];
            snprintf(msg, sizeof(msg), "[%s] %s", ts, (char *)decrypted);
            addMessage(msg);
            return;
        }
        if (g_dm.pending && strncmp(g_dm.pendingToken, senderToken, TOKEN_HEX_LEN) == 0) {
            g_dm.active = true;
            g_dm.pending = false;
            snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", g_dm.pendingToken);
            memcpy(g_dm.key, g_dm.pendingKey, 32);
            memset(g_dm.pendingKey, 0, sizeof(g_dm.pendingKey));
            addMessage("[*] DM session resumed");
            unsigned char decoded[MSG_SIZE];
            int dlen = decodeBase64(payload + 4, decoded);
            if (dlen <= 0) return;
            unsigned char decrypted[MSG_SIZE];
            int plen = decryptMessage(decoded, (size_t)dlen, g_dm.key, decrypted);
            if (plen <= 0) return;
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[16] = "00:00";
            if (tm_info) strftime(ts, sizeof(ts), "%H:%M", tm_info);
            int truncLen = plen;
            if (truncLen > MSG_SIZE - 20) truncLen = MSG_SIZE - 20;
            decrypted[truncLen] = '\0';
            #pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
            char msg[MSG_SIZE];
            snprintf(msg, sizeof(msg), "[%s] %s", ts, (char *)decrypted);
#pragma GCC diagnostic pop
            addMessage(msg);
            return;
        }
        addMessage("[!] Encrypted DM from unknown session");
    }
}

static bool handleRoomResponse(const char *text) {
    if (g_pendingRoom.pending) {
        pthread_mutex_lock(&g_inputMutex);
        g_waitingForRoomJoin = false;
        pthread_mutex_unlock(&g_inputMutex);

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
            (strncmp(text, "Room '", 6) == 0 && strstr(text, "' does not exist") != NULL)) {
            memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
            g_expectServerResponse = false;
            return false;
        }
    }

    if (strncmp(text, "Room '", 6) == 0 && strstr(text, "' created") != NULL) {
        g_expectServerResponse = false;
        return false;
    }

    return false;
}

static void finalizePasswordEntry(void) {
    char passwordHash[SHA256_HEX_SIZE];
    sha256Hex(g_passwordBuffer, g_passwordLen, passwordHash);

    char toSend[MSG_SIZE];
    memcpy(toSend, passwordHash, SHA256_HEX_SIZE - 1);
    toSend[SHA256_HEX_SIZE - 1] = '\n';
    toSend[SHA256_HEX_SIZE] = '\0';
    clientLog("Sending hashed password to server for room '%s'", g_pendingRoom.roomName);
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
    pthread_mutex_lock(&g_inputMutex);
    g_readingPassword = false;
    pthread_mutex_unlock(&g_inputMutex);

    pthread_mutex_lock(&g_inputMutex);
    g_inputState.buffer[0] = '\0';
    g_inputState.length = 0;
    pthread_mutex_unlock(&g_inputMutex);
}

static void displayIncomingMessage(char *buffer) {
    bool isMsg = (buffer[0] == 'M' && buffer[1] == 'S' && buffer[2] == 'G');
    bool isErr = (buffer[0] == 'E' && buffer[1] == 'R' && buffer[2] == 'R');
    bool isRes = (buffer[0] == 'R' && buffer[1] == 'E' && buffer[2] == 'S');
    bool isPas = (buffer[0] == 'P' && buffer[1] == 'A' && buffer[2] == 'S');
    bool isDm = (buffer[0] == 'D' && buffer[1] == 'M' && buffer[2] == ':');

    clientLog("recv: %.80s", buffer);

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

        if (strcmp(username, g_username) == 0) {
            return;
        }
        if (isEncryptedMessage(messageStart) && g_encryption.hasKey) {
            unsigned char decoded[MSG_SIZE];
            int dlen = decodeBase64(messageStart + 4, decoded);
            if (dlen <= 0) {
                addMessage("[!] Failed to decrypt message");
                return;
            }
            unsigned char decrypted[MSG_SIZE];
            int plen = decryptMessage(decoded, (size_t)dlen, g_encryption.key, decrypted);
            if (plen <= 0) {
                addMessage("[!] Failed to decrypt message");
                return;
            }
            decrypted[plen] = '\0';
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[16] = "00:00";
            if (tm_info) strftime(ts, sizeof(ts), "%H:%M", tm_info);
            char msg[MSG_SIZE * 2];
            if (username[0])
                snprintf(msg, sizeof(msg), "[%s] %s: %s", ts, username, (char *)decrypted);
            else
                snprintf(msg, sizeof(msg), "[%s] %s", ts, (char *)decrypted);
            addMessage(msg);
        } else if (isEncryptedMessage(messageStart) && !g_encryption.hasKey) {
            addMessage("[!] Encrypted message (not in encrypted room)");
        } else {
            char text[MSG_SIZE];
            snprintf(text, sizeof(text), "%s", messageStart);
            size_t tlen = strlen(text);
            while (tlen > 0 && (text[tlen - 1] == '\n' || text[tlen - 1] == '\r'))
                text[--tlen] = '\0';
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[16] = "00:00";
            if (tm_info) strftime(ts, sizeof(ts), "%H:%M", tm_info);
            char msg[MSG_SIZE * 2];
            if (username[0])
                snprintf(msg, sizeof(msg), "[%s] %s: %s", ts, username, text);
            else
                snprintf(msg, sizeof(msg), "[%s] %s", ts, text);
            addMessage(msg);
        }
    } else if (isErr) {
        char msg[MSG_SIZE];
        snprintf(msg, sizeof(msg), "[!] %s", buffer + 3);
        addMessage(msg);
    } else if (isRes) {
        const char *text = buffer + 3;
        if (strncmp(text, "Available rooms:", 15) == 0) {
            g_roomCount = 0;
            const char *p = text;
            while ((p = strstr(p, "  ")) != NULL) {
                p += 2;
                char roomName[MAX_NAME_LEN] = {0};
                if (sscanf(p, "%63s", roomName) == 1 && roomName[0] != '[') {
                    if (g_roomCount < 50) {
                        snprintf(g_rooms[g_roomCount++], MAX_NAME_LEN, "%s", roomName);
                    }
                    while (*p && *p != '\n') p++;
                } else {
                    break;
                }
            }
            char msg[MSG_SIZE];
            snprintf(msg, sizeof(msg), "[*] Rooms updated");
            addMessage(msg);
            return;
        }

        bool success = handleRoomResponse(text);
        if (!success) {
            if (strncmp(text, "Incorrect password", 18) == 0) {
                addMessage("[!] Incorrect password");
            } else if (strncmp(text, "Room '", 6) == 0 && strstr(text, "' does not exist") != NULL) {
                char err[MSG_SIZE];
                snprintf(err, sizeof(err), "[!] %s", text);
                addMessage(err);
            } else {
                char msg[MSG_SIZE];
                snprintf(msg, sizeof(msg), "[*] %s", text);
                addMessage(msg);
            }
        }
    } else if (isPas) {
        pthread_mutex_lock(&g_inputMutex);
        g_readingPassword = true;
        memset(g_passwordBuffer, 0, sizeof(g_passwordBuffer));
        g_passwordLen = 0;
        g_waitingForRoomJoin = false;
        pthread_mutex_unlock(&g_inputMutex);
        addMessage("[*] Enter password: ");
    }
}

static void handleDisconnect(void) {
    pthread_mutex_lock(&g_inputMutex);
    g_connected = false;
    pthread_mutex_unlock(&g_inputMutex);
    addMessage("[!] Disconnected from server");
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
    pthread_mutex_lock(&g_inputMutex);
    bool connected = g_connected;
    pthread_mutex_unlock(&g_inputMutex);
    if (!connected) return false;
    size_t len = strlen(message);
    if (len >= MSG_SIZE) return false;
    clientLog("send: %.120s", message);
    if (!tlsSend(g_ssl, message, len)) {
        handleDisconnect();
        return false;
    }
    return true;
}

static bool connectToServer(const char *ip, int port) {
    g_socketFD = createTCPSocket();
    if (g_socketFD < 0) return false;
    struct addrinfo hints = {0};
    struct addrinfo *servinfo = NULL;
    char portStr[16];
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portStr, sizeof(portStr), "%d", port);
    if (getaddrinfo(ip, portStr, &hints, &servinfo) != 0 || !servinfo) {
        close(g_socketFD);
        return false;
    }
    char resolvedIP[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
    inet_ntop(AF_INET, &ipv4->sin_addr, resolvedIP, sizeof(resolvedIP));
    freeaddrinfo(servinfo);
    SocketAddress *address = createSocketAddress(resolvedIP, port, true);
    if (!address) {
        close(g_socketFD);
        return false;
    }
    if (connectSocket(g_socketFD, address) != 0) {
        close(g_socketFD);
        free(address);
        return false;
    }
    free(address);
    SSL_CTX *ctx = tlsClientCtxCreate();
    if (!ctx) {
        close(g_socketFD);
        return false;
    }
    g_ssl = tlsClientConnect(ctx, g_socketFD);
    SSL_CTX_free(ctx);
    if (!g_ssl) {
        close(g_socketFD);
        return false;
    }
    clientLog("connectToServer: TLS connected to %s:%d", ip, port);
    return true;
}

static bool authenticate(void) {
    char challengeBuf[MSG_SIZE];
    ssize_t n = tlsRecv(g_ssl, challengeBuf, sizeof(challengeBuf));
    if (n <= 0 || strncmp(challengeBuf, "CHALLENGE:", 10) != 0 ||
        strlen(challengeBuf) < 10 + CHALLENGE_HEX_LEN) {
        return false;
    }
    const char *hexNonce = challengeBuf + 10;
    unsigned char nonce[CHALLENGE_BYTES];
    bool ok = true;
    for (int i = 0; i < CHALLENGE_BYTES && ok; i++) {
        int hi = -1, lo = -1;
        char hc = hexNonce[i * 2], lc = hexNonce[i * 2 + 1];
        if (hc >= '0' && hc <= '9') hi = hc - '0';
        else if (hc >= 'a' && hc <= 'f') hi = hc - 'a' + 10;
        else if (hc >= 'A' && hc <= 'F') hi = hc - 'A' + 10;
        else ok = false;
        if (lc >= '0' && lc <= '9') lo = lc - '0';
        else if (lc >= 'a' && lc <= 'f') lo = lc - 'a' + 10;
        else if (lc >= 'A' && lc <= 'F') lo = lc - 'A' + 10;
        else ok = false;
        if (ok) nonce[i] = (unsigned char)((hi << 4) | lo);
    }
    if (!ok) return false;
    unsigned char sig[SIG_BYTES];
    if (!identitySign(&g_identity, nonce, CHALLENGE_BYTES, sig)) return false;
    static const char hx[] = "0123456789abcdef";
    char sigHex[SIG_HEX_SIZE];
    for (int i = 0; i < SIG_BYTES; i++) {
        sigHex[i * 2] = hx[sig[i] >> 4];
        sigHex[i * 2 + 1] = hx[sig[i] & 0xf];
    }
    sigHex[SIG_HEX_LEN] = '\0';
    char authMsg[MSG_SIZE];
    snprintf(authMsg, sizeof(authMsg), "AUTH:%s:%s\n", g_identity.token, sigHex);
    if (!tlsSend(g_ssl, authMsg, strlen(authMsg))) return false;
    char ackBuf[MSG_SIZE];
    n = tlsRecv(g_ssl, ackBuf, sizeof(ackBuf));
    if (n <= 0 || strncmp(ackBuf, "RESAuthenticated", 16) != 0) return false;
    clientLog("auth: authenticated successfully");
    return true;
}

static void drawSidebar(void) {
    if (!g_sidebarWin) return;
    werase(g_sidebarWin);

    box(g_sidebarWin, 0, 0);

    mvwaddstr(g_sidebarWin, 1, 2, "Rooms:");
    for (int i = 0; i < g_roomCount; i++) {
        int y = 3 + i;
        if (y >= getmaxy(g_sidebarWin) - 1) break;
        if (i == g_selectedRoom)
            wattron(g_sidebarWin, A_REVERSE | COLOR_PAIR(COLOR_PAIR_ACTIVE));
        if (strcmp(g_rooms[i], g_currentRoom) == 0) {
            wattron(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_ROOM));
        }
        mvwaddstr(g_sidebarWin, y, 4, g_rooms[i]);
        if (strcmp(g_rooms[i], g_currentRoom) == 0)
            wattroff(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_ROOM));
        if (i == g_selectedRoom)
            wattroff(g_sidebarWin, A_REVERSE | COLOR_PAIR(COLOR_PAIR_ACTIVE));
    }

    int dmStart = 3 + g_roomCount + 1;
    if (dmStart < getmaxy(g_sidebarWin) - 2) {
        mvwaddstr(g_sidebarWin, dmStart, 2, "DMs:");
        for (int i = 0; i < g_dmCount; i++) {
            int y = dmStart + 2 + i;
            if (y >= getmaxy(g_sidebarWin) - 1) break;
            if (i == g_selectedDm)
                wattron(g_sidebarWin, A_REVERSE | COLOR_PAIR(COLOR_PAIR_ACTIVE));
            if (g_dm.active && strcmp(g_dmList[i], g_dm.peerToken) == 0) {
                wattron(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_DM));
            }
            char dmDisplay[MAX_NAME_LEN];
            if (g_dmNick[i][0]) {
                snprintf(dmDisplay, sizeof(dmDisplay), "%s", g_dmNick[i]);
            } else {
                snprintf(dmDisplay, sizeof(dmDisplay), "%.10s", g_dmList[i]);
            }
            mvwaddstr(g_sidebarWin, y, 4, dmDisplay);
            if (g_dm.active && strcmp(g_dmList[i], g_dm.peerToken) == 0)
                wattroff(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_DM));
            if (i == g_selectedDm)
                wattroff(g_sidebarWin, A_REVERSE | COLOR_PAIR(COLOR_PAIR_ACTIVE));
        }
    }

    wattroff(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_ROOM));
    wattroff(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_DM));
    wattroff(g_sidebarWin, A_REVERSE);
    wattroff(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_ACTIVE));

    wnoutrefresh(g_sidebarWin);
}

static void drawMessages(void) {
    if (!g_msgWin) return;
    werase(g_msgWin);

    int winH = getmaxy(g_msgWin);

    int visibleLines = winH - 2;
    int maxScroll = g_msgCount > visibleLines ? g_msgCount - visibleLines : 0;
    if (g_msgScroll > maxScroll) g_msgScroll = maxScroll;
    if (g_msgScroll < 0) g_msgScroll = 0;

    int startIdx = g_msgScroll;
    int idx = 0;

    MessageNode *node = g_msgHead;
    while (node && idx < startIdx) {
        node = node->next;
        idx++;
    }

    int y = 1;
    while (node && y < winH - 1) {
        char *line = node->text;
        char *token = NULL;
        if (strncmp(line, "[!] ", 4) == 0) {
            wattron(g_msgWin, COLOR_PAIR(COLOR_PAIR_ERROR));
            token = "[!] ";
        } else if (strncmp(line, "[*] ", 4) == 0) {
            wattron(g_msgWin, COLOR_PAIR(COLOR_PAIR_NOTIF));
            token = "[*] ";
        } else if (line[0] == '[' && (line[1] >= '0' && line[1] <= '9')) {
            wattron(g_msgWin, COLOR_PAIR(COLOR_PAIR_MSG));
        }

        if (token) {
            mvwaddstr(g_msgWin, y, 1, token);
            mvwaddstr(g_msgWin, y, 4, line + 4);
        } else {
            mvwaddstr(g_msgWin, y, 1, line);
        }

        if (strncmp(line, "[!] ", 4) == 0)
            wattroff(g_msgWin, COLOR_PAIR(COLOR_PAIR_ERROR));
        else if (strncmp(line, "[*] ", 4) == 0)
            wattroff(g_msgWin, COLOR_PAIR(COLOR_PAIR_NOTIF));
        else if (line[0] == '[' && (line[1] >= '0' && line[1] <= '9'))
            wattroff(g_msgWin, COLOR_PAIR(COLOR_PAIR_MSG));

        node = node->next;
        y++;
    }

    wnoutrefresh(g_msgWin);
}

static void drawInput(void) {
    if (!g_inputWin) return;
    werase(g_inputWin);
    box(g_inputWin, ACS_VLINE, ACS_HLINE);

    pthread_mutex_lock(&g_inputMutex);
    int winW = getmaxx(g_inputWin) - 4;
    if (winW > 0) {
        size_t printLen = g_inputState.length;
        if (printLen > (size_t)winW) printLen = (size_t)winW;
        char clipped[MSG_SIZE];
        memcpy(clipped, g_inputState.buffer, printLen);
        clipped[printLen] = '\0';
        mvwaddstr(g_inputWin, 1, 2, clipped);
        wmove(g_inputWin, 1, 2 + printLen);
    }
    pthread_mutex_unlock(&g_inputMutex);

    wnoutrefresh(g_inputWin);
}

static void drawTopBar(void) {
    int titleY = 0;
    mvaddstr(titleY, 0, "SocketChat E2E");
    attron(COLOR_PAIR(COLOR_PAIR_NOTIF));
    mvaddstr(titleY, g_maxX - 12, "[?/help]");
    attroff(COLOR_PAIR(COLOR_PAIR_NOTIF));

    char tokenStr[32];
    snprintf(tokenStr, sizeof(tokenStr), "Token: %.8s...", g_identity.token);
    mvaddstr(titleY, g_maxX - 28, tokenStr);

    if (g_msgCount > 0) {
        int winH = getmaxy(g_msgWin) - 2;
        int maxScroll = g_msgCount > winH ? g_msgCount - winH : 0;
        int pct = maxScroll > 0 ? (g_msgScroll * 100) / maxScroll : 100;
        char scrollStr[16];
        if (g_msgScroll == 0)
            snprintf(scrollStr, sizeof(scrollStr), "bot");
        else if (g_msgScroll >= maxScroll)
            snprintf(scrollStr, sizeof(scrollStr), "top");
        else
            snprintf(scrollStr, sizeof(scrollStr), "%d%%", pct);
        attron(COLOR_PAIR(COLOR_PAIR_PROMPT));
        mvaddstr(titleY, g_sidebarX + 2, scrollStr);
        attroff(COLOR_PAIR(COLOR_PAIR_PROMPT));
    }

    mvaddch(titleY, g_sidebarX - 1, ACS_VLINE);
    for (int y = 1; y < g_maxY - 1; y++)
        mvaddch(y, g_sidebarX - 1, ACS_VLINE);

    refresh();
}

static void drawHelp(void) {
    if (!g_showHelp) return;
    if (g_helpWin) {
        delwin(g_helpWin);
    }

    int helpH = 18;
    int helpW = 55;
    int helpY = (g_maxY - helpH) / 2;
    int helpX = (g_maxX - helpW) / 2;

    g_helpWin = newwin(helpH, helpW, helpY, helpX);
    wbkgd(g_helpWin, COLOR_PAIR(COLOR_PAIR_NOTIF));
    box(g_helpWin, 0, 0);

    wattron(g_helpWin, A_BOLD);
    mvwaddstr(g_helpWin, 1, 2, "Commands");
    wattroff(g_helpWin, A_BOLD);

    mvwaddstr(g_helpWin, 3, 2, "/help              - Show this help");
    mvwaddstr(g_helpWin, 4, 2, "/name <username>   - Set your display name");
    mvwaddstr(g_helpWin, 5, 2, "/create <room>    - Create a room");
    mvwaddstr(g_helpWin, 6, 2, "/create <room> -p <pass> - Create encrypted room");
    mvwaddstr(g_helpWin, 7, 2, "/enter <room>    - Enter a room");
    mvwaddstr(g_helpWin, 8, 2, "/leave           - Leave current room");
    mvwaddstr(g_helpWin, 9, 2, "/rooms           - List available rooms");
    mvwaddstr(g_helpWin, 10, 2, "/dm <1|token>   - Start a DM");
    mvwaddstr(g_helpWin, 11, 2, "/dmleave        - Leave DM session");
    mvwaddstr(g_helpWin, 12, 2, "/list           - List DM conversations");
    mvwaddstr(g_helpWin, 13, 2, "/nick <n|token> <name> - Rename a DM");
    mvwaddstr(g_helpWin, 14, 2, "/token          - Show your token");
    mvwaddstr(g_helpWin, 14, 2, "/clear          - Clear messages");
    mvwaddstr(g_helpWin, 15, 2, "/exit           - Disconnect and quit");
    mvwaddstr(g_helpWin, 16, 2, "Esc              - Close this help");

    wnoutrefresh(g_helpWin);
}

static void refreshAll(void) {
    drawTopBar();
    drawMessages();
    drawSidebar();
    drawInput();
    drawHelp();
    doupdate();
}

static void resizeWindows(void) {
    endwin();
    refresh();
    clear();
    getmaxyx(stdscr, g_maxY, g_maxX);
    g_sidebarX = g_maxX - 40;
    if (g_sidebarX < 15) g_sidebarX = 15;

    if (g_inputWin) {
        delwin(g_inputWin);
        g_inputWin = NULL;
    }
    if (g_msgWin) {
        delwin(g_msgWin);
        g_msgWin = NULL;
    }
    if (g_sidebarWin) {
        delwin(g_sidebarWin);
        g_sidebarWin = NULL;
    }
    if (g_helpWin) {
        delwin(g_helpWin);
        g_helpWin = NULL;
    }

    g_inputWin = newwin(5, g_sidebarX - 1, g_maxY - 5, 0);
    g_msgWin = newwin(g_maxY - 5 - 1, g_sidebarX - 1, 1, 0);
    g_sidebarWin = newwin(g_maxY - 5, g_maxX - g_sidebarX, 1, g_sidebarX);

    if (g_inputWin) {
        wbkgd(g_inputWin, COLOR_PAIR(COLOR_PAIR_PROMPT));
    }
    if (g_msgWin) {
        wbkgd(g_msgWin, COLOR_PAIR(COLOR_PAIR_MSG));
    }
    if (g_sidebarWin) {
        wbkgd(g_sidebarWin, COLOR_PAIR(COLOR_PAIR_MSG));
    }
}

static void handleKeyInput(int key) {
    pthread_mutex_lock(&g_inputMutex);
    bool readingPw = g_readingPassword;
    pthread_mutex_unlock(&g_inputMutex);

    if (readingPw) {
        if (key == '\n' || key == '\r') {
            finalizePasswordEntry();
        } else if (key == 127 || key == 8) {
            if (g_passwordLen > 0) {
                g_passwordLen--;
                g_passwordBuffer[g_passwordLen] = '\0';
            }
        } else if (isprint(key) && g_passwordLen < MSG_SIZE - 1) {
            g_passwordBuffer[g_passwordLen++] = key;
            g_passwordBuffer[g_passwordLen] = '\0';
        }
        return;
    }

    if (g_showHelp) {
        curs_set(0);
        if (key == 27 || key == KEY_F(1)) {
            g_showHelp = false;
            curs_set(1);
            if (g_helpWin) {
                delwin(g_helpWin);
                g_helpWin = NULL;
            }
            return;
        }
        return;
    }

    if (key == 27) {
        g_showHelp = false;
        return;
    }

    if (key == KEY_F(1) || (g_inputState.length > 0 && g_inputState.buffer[0] == '?' &&
        (g_inputState.length == 1 ||
         (g_inputState.length == 1 && g_inputState.buffer[0] == '/' &&
          (g_inputState.length > 1 || key == 'h'))))) {
        if (key == KEY_F(1) || (g_inputState.length >= 1 && g_inputState.buffer[0] == '?')) {
            g_showHelp = true;
            return;
        }
    }

    if (key == '\n' || key == '\r') {
        g_inputState.buffer[g_inputState.length] = '\0';
        char msg[MSG_SIZE];
        snprintf(msg, sizeof(msg), "%s", g_inputState.buffer);

        pthread_mutex_lock(&g_inputMutex);
        g_inputState.buffer[0] = '\0';
        g_inputState.length = 0;
        pthread_mutex_unlock(&g_inputMutex);

        if (strcmp(msg, "/exit") == 0) {
            sendToServer("/exit\n");
            pthread_mutex_lock(&g_inputMutex);
            g_connected = false;
            pthread_mutex_unlock(&g_inputMutex);
            return;
        }

        if (strncmp(msg, "/name ", 6) == 0) {
            char newName[MAX_NAME_LEN] = {0};
            sscanf(msg + 6, "%63s", newName);
            if (newName[0] == '\0') {
                addMessage("[*] Usage: /name <username>");
                return;
            }
            snprintf(g_username, sizeof(g_username), "%s", newName);
            identitySaveUsername(newName);
            char toSend[MSG_SIZE];
            size_t toSendLen = strlen(msg);
            if (toSendLen >= MSG_SIZE - 1) toSendLen = MSG_SIZE - 2;
            memcpy(toSend, msg, toSendLen);
            toSend[toSendLen] = '\n';
            toSend[toSendLen + 1] = '\0';
            sendToServer(toSend);
            return;
        }

        if (strncmp(msg, "/create ", 8) == 0) {
            if (g_dm.active) {
                clearDmSession();
            }
            char toSend[MSG_SIZE];
            size_t toSendLen = strlen(msg);
            if (toSendLen >= MSG_SIZE - 1) toSendLen = MSG_SIZE - 2;
            memcpy(toSend, msg, toSendLen);
            toSend[toSendLen] = '\n';
            toSend[toSendLen + 1] = '\0';
            sendToServer(toSend);
            g_expectServerResponse = true;
            return;
        }

        if (strncmp(msg, "/enter ", 7) == 0) {
            if (g_dm.active) {
                clearDmSession();
            }
            char roomName[MAX_NAME_LEN] = {0};
            sscanf(msg + 7, "%63s", roomName);
            memset(&g_pendingRoom, 0, sizeof(g_pendingRoom));
            snprintf(g_pendingRoom.roomName, sizeof(g_pendingRoom.roomName), "%s", roomName);
            g_pendingRoom.pending = true;
            pthread_mutex_lock(&g_inputMutex);
            g_waitingForRoomJoin = true;
            pthread_mutex_unlock(&g_inputMutex);
            char toSend[MSG_SIZE];
            size_t toSendLen = strlen(msg);
            if (toSendLen >= MSG_SIZE - 1) toSendLen = MSG_SIZE - 2;
            memcpy(toSend, msg, toSendLen);
            toSend[toSendLen] = '\n';
            toSend[toSendLen + 1] = '\0';
            sendToServer(toSend);
            g_expectServerResponse = true;
            return;
        }

        if (strcmp(msg, "/leave") == 0) {
            if (g_dm.active) {
                clearDmSession();
                addMessage("[*] DM session closed");
                return;
            }
            if (g_inRoom) {
                clearRoomState();
                sendToServer("/leave\n");
            } else {
                addMessage("[*] Not in a room");
            }
            return;
        }

        if (strcmp(msg, "/dmleave") == 0) {
            if (!g_dm.active) {
                addMessage("[*] Not in a DM session");
                return;
            }
            clearDmSession();
            addMessage("[*] DM session closed");
            return;
        }

        if (strncmp(msg, "/nick ", 6) == 0) {
            char tokenOrNum[TOKEN_STR_SIZE] = {0};
            char nick[MAX_NAME_LEN] = {0};
            sscanf(msg + 6, "%64s %63s", tokenOrNum, nick);
            size_t toknLen = strlen(tokenOrNum);

            if (toknLen == 0 || nick[0] == '\0') {
                addMessage("[*] Usage: /nick <token|number> <name>");
                return;
            }

            for (int i = 0; nick[i]; i++) {
                if (!isalnum((unsigned char)nick[i]) && nick[i] != '_' && nick[i] != '-') {
                    addMessage("[!] Name can only contain letters, numbers, _ and -");
                    return;
                }
            }

            int targetIdx = -1;
            if (toknLen >= 2 && tokenOrNum[0] == '<' && tokenOrNum[toknLen-1] == '>') {
                int idx = tokenOrNum[1] - '1';
                if (toknLen == 3) {
                    idx = tokenOrNum[1] - '1';
                } else if (toknLen == 4 && isdigit(tokenOrNum[2])) {
                    idx = (tokenOrNum[1] - '1') * 10 + (tokenOrNum[2] - '1');
                    if (idx >= 9) idx = tokenOrNum[1] - '1';
                }
                if (idx >= 0 && idx < g_dmCount) {
                    targetIdx = idx;
                }
            } else if (toknLen >= 1 && toknLen <= 2 && tokenOrNum[0] >= '1' && tokenOrNum[0] <= '9') {
                targetIdx = tokenOrNum[0] - '1';
                if (targetIdx >= g_dmCount) targetIdx = -1;
            } else {
                for (int i = 0; i < g_dmCount; i++) {
                    if (strncmp(g_dmList[i], tokenOrNum, toknLen) == 0) {
                        targetIdx = i;
                        break;
                    }
                }
            }

            if (targetIdx == -1) {
                addMessage("[!] DM not found");
                return;
            }

            snprintf(g_dmNick[targetIdx], MAX_NAME_LEN, "%s", nick);
            identitySaveDmNicks(g_dmNick, g_dmCount);
            addMessage("[*] DM renamed");
            return;
        }

        if (strncmp(msg, "/dm ", 4) == 0) {
            char input[TOKEN_STR_SIZE] = {0};
            sscanf(msg + 4, "%64s", input);
            size_t inputLen = strlen(input);

            if (inputLen >= 2 && input[0] == '<' && input[inputLen-1] == '>') {
                int idx = input[1] - '1';
                if (inputLen == 3) {
                    idx = input[1] - '1';
                } else if (inputLen == 4 && isdigit(input[2])) {
                    idx = (input[1] - '1') * 10 + (input[2] - '1');
                    if (idx >= 9) idx = input[1] - '1';
                }
                if (idx >= 0 && idx < g_dmCount) {
                    snprintf(input, sizeof(input), "%s", g_dmList[idx]);
                    inputLen = strlen(input);
                } else {
                    addMessage("[!] Invalid DM number");
                    return;
                }
            }

            if (inputLen < 10) {
                int foundIdx = -1;
                for (int i = 0; i < g_dmCount; i++) {
                    if (g_dmNick[i][0] && strcmp(g_dmNick[i], input) == 0) {
                        foundIdx = i;
                        break;
                    }
                }
                if (foundIdx == -1) {
                    for (int i = 0; i < g_dmCount; i++) {
                        if (strncmp(g_dmList[i], input, inputLen) == 0) {
                            foundIdx = i;
                            break;
                        }
                    }
                }
                if (foundIdx == -1) {
                    addMessage("[!] Token/nickname must be at least 10 chars or a nickname");
                    return;
                }
                snprintf(input, sizeof(input), "%s", g_dmList[foundIdx]);
                inputLen = strlen(input);
            }

            char fullToken[TOKEN_STR_SIZE] = {0};
            bool foundToken = false;
            if (inputLen == TOKEN_HEX_LEN) {
                snprintf(fullToken, sizeof(fullToken), "%s", input);
                foundToken = true;
            } else {
                for (int i = 0; i < g_dmCount; i++) {
                    if (strncmp(g_dmList[i], input, inputLen) == 0) {
                        snprintf(fullToken, sizeof(fullToken), "%s", g_dmList[i]);
                        foundToken = true;
                        break;
                    }
                }
            }
            if (!foundToken) {
                for (int i = 0; i < g_dmCount; i++) {
                    if (g_dmNick[i][0] && strcmp(g_dmNick[i], input) == 0) {
                        snprintf(fullToken, sizeof(fullToken), "%s", g_dmList[i]);
                        foundToken = true;
                        break;
                    }
                }
            }
            if (!foundToken) {
                snprintf(fullToken, sizeof(fullToken), "%s", input);
            }

            unsigned char peerPubX25519[32];
            if (!tokenToX25519PublicKey(fullToken, peerPubX25519)) {
                addMessage("[!] Token contains invalid hex");
                return;
            }
            unsigned char myPrivX25519[32];
            if (!identityEd25519PrivToX25519(g_identity.priv, myPrivX25519)) {
                addMessage("[!] Key conversion failed");
                return;
            }
            unsigned char sharedKey[32];
            bool ecdhOk = ecdhDeriveKey(myPrivX25519, peerPubX25519, sharedKey);
            memset(myPrivX25519, 0, sizeof(myPrivX25519));
            if (!ecdhOk) {
                addMessage("[!] ECDH failed");
                return;
            }
            clearRoomState();
            clearDmSession();
            g_dm.active = true;
            snprintf(g_dm.peerToken, sizeof(g_dm.peerToken), "%s", fullToken);
            memcpy(g_dm.key, sharedKey, 32);
            char dmReq[MSG_SIZE];
            snprintf(dmReq, sizeof(dmReq), "DM:%s:DM_REQ:%s\n", fullToken, g_identity.token);
            sendToServer(dmReq);
            g_selectedDm = -1;
            for (int i = 0; i < g_dmCount; i++) {
                if (strcmp(g_dmList[i], fullToken) == 0) {
                    g_selectedDm = i;
                    break;
                }
            }
            if (g_selectedDm == -1 && g_dmCount < 50) {
                snprintf(g_dmList[g_dmCount++], TOKEN_STR_SIZE, "%s", fullToken);
                g_selectedDm = g_dmCount - 1;
            }
            addMessage("[*] DM session started");
            return;
        }

        if (strcmp(msg, "/help") == 0) {
            g_showHelp = true;
            return;
        }

        if (strcmp(msg, "/rooms") == 0) {
            sendToServer("/rooms\n");
            return;
        }

        if (strcmp(msg, "/list") == 0) {
            g_dmCount = historyGetAll(g_dmList);
    identityLoadDmNicks(g_dmNick);
            char out[MSG_SIZE];
            snprintf(out, sizeof(out), "[*] Found %d DMs", g_dmCount);
            addMessage(out);
            return;
        }

        if (strcmp(msg, "/token") == 0) {
            char tokenMsg[MSG_SIZE];
            snprintf(tokenMsg, sizeof(tokenMsg), "[*] Your token: %s", g_identity.token);
            addMessage(tokenMsg);
            return;
        }

        if (strcmp(msg, "/clear") == 0) {
            clearMessages();
            return;
        }

        if (g_dm.active) {
            if (msg[0] == '/') {
                char toSend[MSG_SIZE];
                size_t msgLen = strlen(msg);
                size_t toSendLen = msgLen < MSG_SIZE - 2 ? msgLen : MSG_SIZE - 2;
                memcpy(toSend, msg, toSendLen);
                toSend[toSendLen] = '\n';
                toSend[toSendLen + 1] = '\0';
                sendToServer(toSend);
                return;
            }
            if (!encryptAndSendDm(msg, strlen(msg))) {
                addMessage("[!] Failed to encrypt DM");
                return;
            }
            historyAppend(g_dm.peerToken, true, msg);
            g_expectServerResponse = true;
            return;
        }

        if (!g_inRoom) {
            addMessage("[*] Not in a room - use /enter <room>");
            return;
        }

        if (g_encryption.hasKey) {
            encryptAndSendRoom(msg, strlen(msg));
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[16] = "00:00";
            if (tm_info) strftime(ts, sizeof(ts), "%H:%M", tm_info);
            char userMsg[MSG_SIZE * 2];
            snprintf(userMsg, sizeof(userMsg), "[%s] %s: %s", ts, g_username, msg);
            addMessage(userMsg);
        } else {
            char toSend[MSG_SIZE];
            size_t toSendLen = strlen(msg);
            if (toSendLen >= MSG_SIZE - 1) toSendLen = MSG_SIZE - 2;
            memcpy(toSend, msg, toSendLen);
            toSend[toSendLen] = '\n';
            toSend[toSendLen + 1] = '\0';
            sendToServer(toSend);
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[16] = "00:00";
            if (tm_info) strftime(ts, sizeof(ts), "%H:%M", tm_info);
            char userMsg[MSG_SIZE * 2];
            snprintf(userMsg, sizeof(userMsg), "[%s] %s: %s", ts, g_username, msg);
            addMessage(userMsg);
        }

        g_expectServerResponse = true;
        return;
    }

if (key == 127 || key == 8 || key == KEY_BACKSPACE || key == 0x7F) {
        if (g_inputState.length > 0) {
            g_inputState.length--;
            g_inputState.buffer[g_inputState.length] = '\0';
        }
    } else if (isprint(key) && g_inputState.length < MSG_SIZE - 1) {
        g_inputState.buffer[g_inputState.length++] = key;
        g_inputState.buffer[g_inputState.length] = '\0';
    }
}

static void initNcurses(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(1);

    start_color();
    use_default_colors();
    init_pair(COLOR_PAIR_MSG, COLOR_CYAN, -1);
    init_pair(COLOR_PAIR_NOTIF, COLOR_YELLOW, -1);
    init_pair(COLOR_PAIR_ERROR, COLOR_RED, -1);
    init_pair(COLOR_PAIR_PROMPT, COLOR_GREEN, -1);
    init_pair(COLOR_PAIR_ROOM, COLOR_CYAN, -1);
    init_pair(COLOR_PAIR_DM, COLOR_MAGENTA, -1);
    init_pair(COLOR_PAIR_ACTIVE, COLOR_BLACK, COLOR_CYAN);

    resizeWindows();
}

static void cleanupNcurses(void) {
    if (g_helpWin) delwin(g_helpWin);
    if (g_inputWin) delwin(g_inputWin);
    if (g_msgWin) delwin(g_msgWin);
    if (g_sidebarWin) delwin(g_sidebarWin);
    endwin();
}

static void inputLoop(void) {
    while (true) {
        pthread_mutex_lock(&g_inputMutex);
        bool connected = g_connected;
        pthread_mutex_unlock(&g_inputMutex);
        if (!connected) break;

        int key = getch();

        if (key == ERR) {
            usleep(10000);
            refreshAll();
            continue;
        }

        if (key == KEY_RESIZE) {
            resizeWindows();
            refreshAll();
            continue;
        }

        if (key == KEY_UP || key == 'K') {
            g_msgScroll -= 3;
            refreshAll();
            continue;
        }
        if (key == KEY_DOWN || key == 'J') {
            g_msgScroll += 3;
            refreshAll();
            continue;
        }
        if (key == KEY_PPAGE) {
            g_msgScroll -= getmaxy(g_msgWin) - 2;
            refreshAll();
            continue;
        }
        if (key == KEY_NPAGE) {
            g_msgScroll += getmaxy(g_msgWin) - 2;
            refreshAll();
            continue;
        }
        if (key == KEY_HOME || key == 'g') {
            g_msgScroll = 0;
            refreshAll();
            continue;
        }
        if (key == 'G') {
            g_msgScroll = g_msgCount;
            refreshAll();
            continue;
        }

        handleKeyInput(key);
        refreshAll();
    }
}

int main(int argc, char *argv[]) {
    logOpen();
    clientLog("=== client_tui starting ===");

    initNcurses();

    if (!identityLoadOrCreate(&g_identity)) {
        cleanupNcurses();
        fprintf(stderr, "Fatal: could not load or create identity\n");
        return 1;
    }
    char savedName[MAX_NAME_LEN];
    if (identityLoadUsername(savedName, sizeof(savedName))) {
        snprintf(g_username, sizeof(g_username), "%s", savedName);
    } else {
        snprintf(g_username, sizeof(g_username), "%.8s", g_identity.token);
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

    if (!connectToServer(ip, port)) {
        cleanupNcurses();
        fprintf(stderr, "Failed to connect to %s:%d\n", ip, port);
        return 1;
    }

    if (!authenticate()) {
        cleanupNcurses();
        fprintf(stderr, "Authentication failed\n");
        tlsFree(g_ssl);
        close(g_socketFD);
        return 1;
    }

    pthread_t recvTid;
    if (pthread_create(&recvTid, NULL, receiveThread, NULL) != 0) {
        cleanupNcurses();
        fprintf(stderr, "Failed to create receive thread\n");
        tlsFree(g_ssl);
        close(g_socketFD);
        return 1;
    }

    addMessage("[*] Connected to server");
    addMessage("[*] Use /enter <room> to join a room");
    addMessage("[*] Use /help for commands");

    sendToServer("/rooms\n");
    g_dmCount = historyGetAll(g_dmList);
    identityLoadDmNicks(g_dmNick);

    char nameCmd[MSG_SIZE];
    snprintf(nameCmd, sizeof(nameCmd), "/name %s\n", g_username);
    sendToServer(nameCmd);

    inputLoop();

    pthread_join(recvTid, NULL);
    clientLog("=== client_tui shutting down ===");
    tlsFree(g_ssl);
    close(g_socketFD);
    pthread_mutex_destroy(&g_inputMutex);
    cleanupNcurses();
    clearMessages();
    if (g_logFile) fclose(g_logFile);
    return 0;
}