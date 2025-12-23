#include "../Utils/aes.h"
#include "../Utils/sha256.h"
#include "../Utils/socketUtil.h"

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 2077

static int g_socketFD = -1;
static RoomEncryption g_encryption = {0};
static struct termios g_origTermios;

typedef struct
{
    char buffer[MSG_SIZE];
    size_t length;
    pthread_mutex_t mutex;
    bool connected;
} InputState;

static InputState g_input = {.buffer = {0}, .length = 0, .mutex = PTHREAD_MUTEX_INITIALIZER, .connected = true};
static bool sendToServer(const char* message);

static void disableRawMode(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_origTermios);
}

static void enableRawMode(void)
{
    tcgetattr(STDIN_FILENO, &g_origTermios);
    atexit(disableRawMode);

    struct termios raw = g_origTermios;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static void clearScreen(void)
{
    print("\033[2J\033[H");
}

static void clearInputLine(void)
{
    pthread_mutex_lock(&g_input.mutex);
    print("\r\033[K");
    fflush(stdout);
    pthread_mutex_unlock(&g_input.mutex);
}

static void showInputLine(void)
{
    pthread_mutex_lock(&g_input.mutex);
    printf(COLOR_GREEN ">>> " COLOR_RESET "%s", g_input.buffer);
    fflush(stdout);
    pthread_mutex_unlock(&g_input.mutex);
}

static void printMessage(const char* color, const char* prefix, const char* message)
{
    char formatted[MSG_SIZE * 2];
    snprintf(formatted, sizeof(formatted), "%s%s%s%s", color, prefix, message, COLOR_RESET);
    print(formatted);
}

static bool decryptAndDisplay(const char* encryptedData, const char* username)
{
    unsigned char decoded[MSG_SIZE];
    int decodedLen = decodeBase64(encryptedData, decoded);

    if (decodedLen <= 0)
        return false;

    unsigned char decrypted[MSG_SIZE];
    int decryptedLen = decryptMessage(decoded, decodedLen, g_encryption.key, decrypted);

    if (decryptedLen <= 0)
        return false;

    decrypted[decryptedLen] = '\0';

    char formatted[MSG_SIZE * 2];
    if (username[0])
    {
        snprintf(formatted, sizeof(formatted), "%s<< %s: %s%s\n", COLOR_CYAN, username, decrypted, COLOR_RESET);
    }
    else
    {
        snprintf(formatted, sizeof(formatted), "%s<< %s%s\n", COLOR_CYAN, decrypted, COLOR_RESET);
    }
    print(formatted);

    return true;
}

static void displayIncomingMessage(char* buffer)
{

    char username[64] = {0};
    char* messageStart = buffer;
    char* colon = strchr(buffer, ':');

    if (colon && colon != buffer)
    {
        size_t usernameLen = colon - buffer - 3;
        if (usernameLen < sizeof(username))
        {
            memcpy(username, buffer + 3, usernameLen);
            username[usernameLen] = '\0';
            messageStart = colon + 2;
        }
    }

    clearInputLine();

    if (isEncryptedMessage(messageStart) && g_encryption.hasKey)
    {
        if (decryptAndDisplay(messageStart + 4, username))
        {
            showInputLine();
            return;
        }
        printMessage(COLOR_RED, "[!] ", "Failed to decrypt message\n");
        showInputLine();
        return;
    }
    if (buffer[0] == 'M' && buffer[1] == 'S' && buffer[2] == 'G')
    {
        printMessage(COLOR_CYAN, "<< ", buffer + 3);
    }
    else if (buffer[0] == 'E' && buffer[1] == 'R' && buffer[2] == 'R')
    {
        printMessage(COLOR_RED, "[!] ", buffer + 3);
    }
    else if (buffer[0] == 'R' && buffer[1] == 'E' && buffer[2] == 'S')
    {
        printMessage(COLOR_YELLOW, "[*] ", buffer + 3);
    }
    else if (buffer[0] == 'P' && buffer[1] == 'A' && buffer[2] == 'S')
    {
        printMessage(COLOR_YELLOW, "[*] ", buffer + 3);
        char password[MAX_NAME_LEN];
        printMessage(COLOR_GREEN, ">>> ", "");
        fflush(stdout);

        size_t passLen = 0;
        while (passLen < MAX_NAME_LEN - 1)
        {
            char c;
            if (read(STDIN_FILENO, &c, 1) != 1)
                continue;

            if (c == '\n' || c == '\r')
                break;

            if (c == 127 || c == 8)
            {
                if (passLen > 0)
                {
                    passLen--;
                    printf("\b \b");
                    fflush(stdout);
                }
            }
            else if (isprint(c))
            {
                password[passLen++] = c;
                printf("%c", c);
                fflush(stdout);
            }
        }
        password[passLen] = '\0';
        printf("\n");
        deriveKeyFromPassword(password, g_encryption.key);
        g_encryption.hasKey = true;

        char toSend[MSG_SIZE];
        snprintf(toSend, MSG_SIZE, "%s\n", password);
        sendToServer(toSend);

        showInputLine();
        return;
    }
    else
    {
        printMessage(COLOR_RED, "[!] ", "Invalid message type Recieved from Server\n");
        printMessage(COLOR_GREEN, "recieved: ", buffer);
    }

    showInputLine();
}

static void handleDisconnect(void)
{
    pthread_mutex_lock(&g_input.mutex);
    g_input.connected = false;
    pthread_mutex_unlock(&g_input.mutex);

    clearInputLine();
    printMessage(COLOR_RED, "\n[!] ", "Disconnected from server\n");
    printMessage(COLOR_YELLOW, "[*] ", "Connection lost. Press Enter to exit.\n");
    fflush(stdout);

    close(g_socketFD);
}

static void* receiveThread(void* arg)
{
    char buffer[MSG_SIZE];

    while (true)
    {
        ssize_t received = recv(g_socketFD, buffer, MSG_SIZE - 1, 0);
        if (received <= 0)
        {
            handleDisconnect();
            break;
        }
        else if (errno == ECONNRESET || errno == EPIPE)
        {
            handleDisconnect();
            break;
        }
        else
        {
            buffer[received] = '\0';
            displayIncomingMessage(buffer);
        }
    }

    return NULL;
}

static bool sendToServer(const char* message)
{
    pthread_mutex_lock(&g_input.mutex);
    bool connected = g_input.connected;
    pthread_mutex_unlock(&g_input.mutex);

    if (!connected)
    {
        printMessage(COLOR_RED, "[!] ", "Cannot send: Not connected to server\n");
        return false;
    }

    int length = strlen(message) + 1;
    if (length >= MSG_SIZE)
    {
        printMessage(COLOR_RED, "[!] ", "Failed to send message: Message too long\n");
        return false;
    }

    ssize_t sent = send(g_socketFD, message, length, 0);

    if (sent < 0)
    {
        if (errno == EPIPE || errno == ECONNRESET)
        {
            handleDisconnect();
        }
        else
        {
            printMessage(COLOR_RED, "[!] ", "Failed to send message: Connection error\n");
        }
        return false;
    }

    return true;
}

static void clearEncryption(void)
{
    memset(&g_encryption, 0, sizeof(g_encryption));
}

static void handleLeaveCommand(void)
{
    clearEncryption();
    sendToServer("/leave\n");
}

static bool encryptAndSend(const char* message, size_t msgLen)
{
    unsigned char ciphertext[MSG_SIZE];
    int ciphertextLen = encryptMessage((unsigned char*) message, msgLen, g_encryption.key, ciphertext);

    if (ciphertextLen <= 0)
    {
        printMessage(COLOR_RED, "[!] ", "Failed to encrypt message\n");
        return false;
    }

    char encoded[MSG_SIZE * 2];
    encodeBase64(ciphertext, ciphertextLen, encoded);

    char toSend[MSG_SIZE * 2 + 10];
    snprintf(toSend, sizeof(toSend), "ENC:%s\n", encoded);

    return sendToServer(toSend);
}

static bool processInput(char* message, size_t msgLen)
{
    if (msgLen == 0)
        return true;

    if (strcmp(message, "/exit") == 0)
    {
        sendToServer("/exit\n");
        return false;
    }

    if (strcmp(message, "/clear") == 0)
    {
        clearScreen();
        print("SocketChat CLI (E2E Encrypted)\n\n");
        return true;
    }

    if (strcmp(message, "/leave") == 0)
    {
        handleLeaveCommand();
        return true;
    }

    if (strncmp(message, "/enter ", 7) == 0)
    {
        char roomName[64] = {0};
        sscanf(message + 7, "%63s", roomName);
        strncpy(g_encryption.roomName, roomName, sizeof(g_encryption.roomName) - 1);

        char toSend[MSG_SIZE];
        snprintf(toSend, MSG_SIZE, "%s\n", message);
        sendToServer(toSend);
        return true;
    }

    if (message[0] == '/')
    {
        char toSend[MSG_SIZE];
        snprintf(toSend, MSG_SIZE, "%s\n", message);
        sendToServer(toSend);
        return true;
    }

    if (g_encryption.hasKey)
    {
        encryptAndSend(message, msgLen);
    }
    else
    {
        char toSend[MSG_SIZE];
        snprintf(toSend, MSG_SIZE, "%s\n", message);
        sendToServer(toSend);
    }

    return true;
}

static void updateInputBuffer(const char* message, size_t msgLen)
{
    pthread_mutex_lock(&g_input.mutex);
    strncpy(g_input.buffer, message, MSG_SIZE - 1);
    g_input.buffer[msgLen] = '\0';
    g_input.length = msgLen;
    pthread_mutex_unlock(&g_input.mutex);
}

static void clearInputBuffer(void)
{
    pthread_mutex_lock(&g_input.mutex);
    g_input.buffer[0] = '\0';
    g_input.length = 0;
    pthread_mutex_unlock(&g_input.mutex);
}

static void inputLoop(void)
{
    char message[MSG_SIZE] = {0};
    size_t msgLen = 0;

    printf(COLOR_GREEN ">>> " COLOR_RESET);
    fflush(stdout);

    while (true)
    {

        pthread_mutex_lock(&g_input.mutex);
        bool connected = g_input.connected;
        pthread_mutex_unlock(&g_input.mutex);

        if (!connected)
            break;

        char c;
        if (read(STDIN_FILENO, &c, 1) != 1)
            continue;

        if (c == '\n' || c == '\r')
        {
            message[msgLen] = '\0';
            printf("\n");

            if (!processInput(message, msgLen))
            {
                break;
            }

            msgLen = 0;
            message[0] = '\0';
            clearInputBuffer();

            printf(COLOR_GREEN ">>> " COLOR_RESET);
            fflush(stdout);
        }

        else if (c == 127 || c == 8)
        {
            if (msgLen > 0)
            {
                msgLen--;
                message[msgLen] = '\0';
                printf("\b \b");
                fflush(stdout);
                updateInputBuffer(message, msgLen);
            }
        }

        else if (isprint(c) && msgLen < MSG_SIZE - 1)
        {
            message[msgLen++] = c;
            message[msgLen] = '\0';
            printf("%c", c);
            fflush(stdout);
            updateInputBuffer(message, msgLen);
        }
    }
}

static bool connectToServer(const char* ip, int port)
{
    g_socketFD = createTCPSocket();
    if (g_socketFD < 0)
    {
        printMessage(COLOR_RED, "[!] ", "Failed to create socket\n");
        return false;
    }

    struct addrinfo hints, *servinfo;
    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ip, portStr, &hints, &servinfo) != 0)
    {
        printMessage(COLOR_RED, "[!] ", "Failed to resolve hostname\n");
        close(g_socketFD);
        return false;
    }

    char resolvedIP[INET_ADDRSTRLEN];
    struct sockaddr_in* ipv4 = (struct sockaddr_in*) servinfo->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), resolvedIP, INET_ADDRSTRLEN);

    SocketAddress* address = createSocketAddress(resolvedIP, port, true);
    freeaddrinfo(servinfo);

    if (!address)
    {
        printMessage(COLOR_RED, "[!] ", "Failed to get socket address\n");
        close(g_socketFD);
        return false;
    }

    if (connectSocket(g_socketFD, address) != 0)
    {
        printf(COLOR_RED "[!] Failed to connect to server at " COLOR_RESET "%s:%d\n", ip, port);
        printMessage(COLOR_YELLOW, "[*] ", "Please check if the server is running and the address is correct\n");
        close(g_socketFD);
        free(address);
        return false;
    }

    free(address);
    return true;
}

int main(int argc, char* argv[])
{
    char* ip = DEFAULT_IP;
    int port = DEFAULT_PORT;

    if (argc > 1)
    {
        char* address = argv[1];
        char* colon = strchr(address, ':');

        if (colon)
        {
            *colon = '\0';
            ip = address;
            port = atoi(colon + 1);
        }
        else
        {
            ip = address;
        }
    }

    if (!connectToServer(ip, port))
    {
        return 1;
    }

    pthread_t recvTid;
    if (pthread_create(&recvTid, NULL, receiveThread, NULL) != 0)
    {
        printMessage(COLOR_RED, "[!] ", "Failed to create receive thread\n");
        close(g_socketFD);
        return 1;
    }
    pthread_detach(recvTid);

    clearScreen();
    print("SocketChat CLI (E2E Encrypted)\n");
    printf("Connected to " COLOR_GREEN "%s:%d\n" COLOR_RESET, ip, port);
    print("Type '/exit' to quit | Type '/clear' to clear screen\n\n");

    enableRawMode();
    inputLoop();
    disableRawMode();

    printMessage(COLOR_YELLOW, "\n[*] ", "Shutting down...\n");
    close(g_socketFD);
    pthread_mutex_destroy(&g_input.mutex);

    return 0;
}
