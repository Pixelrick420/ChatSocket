#include "../Utils/socketUtil.h"
#include "../Utils/sha256.h"
#include "../Utils/aes.h"
#include <signal.h>
#include <errno.h>

char *IP = "127.0.0.1";

RoomEncryption currentEncryption = {0};

typedef struct
{
    char buffer[MSG_SIZE];
    size_t length;
    pthread_mutex_t mutex;
    bool connected;
} InputState;

InputState inputState = {
    .buffer = {0},
    .length = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .connected = true};

void clearScreen()
{
    print("\033[2J\033[H");
}

void saveAndClearInputLine()
{
    pthread_mutex_lock(&inputState.mutex);

    print("\r\033[K");
    fflush(stdout);

    pthread_mutex_unlock(&inputState.mutex);
}

void restoreInputLine()
{
    pthread_mutex_lock(&inputState.mutex);

    printf(COLOR_GREEN ">>> " COLOR_RESET "%s", inputState.buffer);
    fflush(stdout);

    pthread_mutex_unlock(&inputState.mutex);
}

void processIncomingMessage(char *buffer, size_t received)
{
    char formatted[MSG_SIZE * 2];

    char *colon = strchr(buffer, ':');
    char username[64] = {0};
    char *messageStart = buffer;

    if (colon && colon != buffer)
    {
        size_t usernameLen = colon - buffer;
        if (usernameLen < sizeof(username))
        {
            memcpy(username, buffer, usernameLen);
            username[usernameLen] = '\0';
            messageStart = colon + 2;
        }
    }

    saveAndClearInputLine();

    if (isEncryptedMessage(messageStart) && currentEncryption.hasKey)
    {
        const char *encryptedData = messageStart + 4;

        unsigned char decoded[MSG_SIZE];
        int decodedLen = decodeBase64(encryptedData, decoded);

        if (decodedLen > 0)
        {
            unsigned char decrypted[MSG_SIZE];
            int decryptedLen = decryptMessage(decoded, decodedLen, currentEncryption.key, decrypted);

            if (decryptedLen > 0)
            {
                decrypted[decryptedLen] = '\0';

                if (username[0])
                {
                    snprintf(formatted, sizeof(formatted), "%s<< %s: %s%s\n",
                             COLOR_CYAN, username, decrypted, COLOR_RESET);
                }
                else
                {
                    snprintf(formatted, sizeof(formatted), "%s<< %s%s\n",
                             COLOR_CYAN, decrypted, COLOR_RESET);
                }
                print(formatted);
                restoreInputLine();
                return;
            }
        }

        snprintf(formatted, sizeof(formatted), "%s[!] Failed to decrypt message%s\n",
                 COLOR_RED, COLOR_RESET);
        print(formatted);
        restoreInputLine();
        return;
    }

    if (strstr(buffer, "Error") || strstr(buffer, "error") ||
        strstr(buffer, "Failed") || strstr(buffer, "failed"))
    {
        snprintf(formatted, sizeof(formatted), "%s[!] %s%s\n", COLOR_RED, buffer, COLOR_RESET);
        print(formatted);
    }
    else if (strstr(buffer, "joined") || strstr(buffer, "left") ||
             strstr(buffer, "Room") || strstr(buffer, "Welcome") ||
             strstr(buffer, "Commands:") || strstr(buffer, "created") ||
             strstr(buffer, "Entered") || strstr(buffer, "Name set") ||
             strstr(buffer, "Incorrect") || strstr(buffer, "Left"))
    {
        snprintf(formatted, sizeof(formatted), "%s[*] %s%s\n", COLOR_YELLOW, buffer, COLOR_RESET);
        print(formatted);
    }
    else if (strstr(buffer, "Password"))
    {
        snprintf(formatted, sizeof(formatted), "%s[*] %s%s\n", COLOR_YELLOW, buffer, COLOR_RESET);
        print(formatted);

        return;
    }
    else
    {
        snprintf(formatted, sizeof(formatted), "%s<< %s%s\n", COLOR_CYAN, buffer, COLOR_RESET);
        print(formatted);
    }

    restoreInputLine();
}

void handleDisconnect(int socketFD)
{
    pthread_mutex_lock(&inputState.mutex);
    inputState.connected = false;
    pthread_mutex_unlock(&inputState.mutex);

    saveAndClearInputLine();
    print(COLOR_RED "\n[!] Disconnected from server\n" COLOR_RESET);
    print(COLOR_YELLOW "[*] Connection lost. Press Enter to exit.\n" COLOR_RESET);
    fflush(stdout);

    close(socketFD);
}

void *receiveThread(void *arg)
{
    int socketFD = *(int *)arg;
    char *buffer = (char *)malloc(sizeof(char) * MSG_SIZE);

    if (!buffer)
    {
        print(COLOR_RED "[!] Memory allocation failed in receive thread\n" COLOR_RESET);
        return NULL;
    }

    while (true)
    {
        ssize_t received = recv(socketFD, buffer, MSG_SIZE - 1, 0);

        if (received > 0)
        {
            buffer[received] = '\0';
            processIncomingMessage(buffer, received);
        }
        else if (received == 0)
        {

            handleDisconnect(socketFD);
            break;
        }
        else
        {

            if (errno == ECONNRESET || errno == EPIPE)
            {
                handleDisconnect(socketFD);
            }
            else if (errno != EINTR)
            {
                saveAndClearInputLine();
                print(COLOR_RED "[!] Receive error: Connection terminated\n" COLOR_RESET);
                restoreInputLine();
            }
            break;
        }
    }

    free(buffer);
    return NULL;
}

void handleLeaveCommand(int socketFD)
{
    memset(&currentEncryption, 0, sizeof(currentEncryption));
    ssize_t sent = send(socketFD, "/leave\n", 7, 0);

    if (sent < 0)
    {
        print(COLOR_RED "[!] Failed to send leave command: Connection error\n" COLOR_RESET);
    }
}

bool sendToServer(int socketFD, const char *message)
{
    pthread_mutex_lock(&inputState.mutex);
    bool connected = inputState.connected;
    pthread_mutex_unlock(&inputState.mutex);

    if (!connected)
    {
        print(COLOR_RED "[!] Cannot send: Not connected to server\n" COLOR_RESET);
        return false;
    }

    ssize_t sent = send(socketFD, message, strlen(message), 0);

    if (sent < 0)
    {
        if (errno == EPIPE || errno == ECONNRESET)
        {
            handleDisconnect(socketFD);
            return false;
        }
        print(COLOR_RED "[!] Failed to send message: Connection error\n" COLOR_RESET);
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    char *serverIP = IP;
    int serverPort = PORT;

    if (argc >= 2)
    {
        char *arg = argv[1];
        char *colon = strchr(arg, ':');

        if (colon)
        {
            *colon = '\0';
            serverIP = arg;
            serverPort = atoi(colon + 1);
        }
        else if (strchr(arg, '.') || !isdigit(arg[0]))
        {
            serverIP = arg;
        }
        else
        {
            serverPort = atoi(arg);
        }
    }

    if (argc >= 3)
    {
        serverPort = atoi(argv[2]);
    }

    SocketAddress *address = getSocketAddress(serverIP, serverPort, true);
    int socketFD = createTCPIPv4Socket();

    if (socketFD < 0)
    {
        print(COLOR_RED "[!] Failed to create socket\n" COLOR_RESET);
        return 1;
    }

    SocketAddress *address = getSocketAddress(IP, PORT, true);

    if (!address)
    {
        print(COLOR_RED "[!] Failed to get socket address\n" COLOR_RESET);
        close(socketFD);
        return 1;
    }

    int result = connectToSocket(socketFD, address, sizeof(*address));

    if (result != 0)
    {
        print(COLOR_RED "[!] Failed to connect to server at " COLOR_RESET);
        printf("%s:%d\n", IP, PORT);
        print(COLOR_YELLOW "[*] Please check if the server is running and the address is correct\n" COLOR_RESET);
        close(socketFD);
        free(address);
        return 1;
    }

    pthread_t pid;
    if (pthread_create(&pid, NULL, receiveThread, &socketFD) != 0)
    {
        print(COLOR_RED "[!] Failed to create receive thread\n" COLOR_RESET);
        close(socketFD);
        free(address);
        return 1;
    }
    pthread_detach(pid);

    char *message = NULL;
    size_t msgSize = 0;
    bool awaitingPassword = false;

    clearScreen();
    print("SocketChat CLI (E2E Encrypted)\n");
    print("Connected to " COLOR_GREEN);
    printf("%s:%d\n", serverIP, serverPort);
    print(COLOR_RESET "Type '/exit' to quit | Type '/clear' to clear screen\n\n");

    while (true)
    {

        pthread_mutex_lock(&inputState.mutex);
        bool connected = inputState.connected;
        pthread_mutex_unlock(&inputState.mutex);

        if (!connected)
        {
            break;
        }

        printf(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);

        ssize_t charCount = getline(&message, &msgSize, stdin);

        if (charCount <= 0)
        {
            if (feof(stdin))
            {
                print("\n");
                break;
            }
            continue;
        }

        if (message[charCount - 1] == '\n')
        {
            message[charCount - 1] = '\0';
            charCount--;
        }

        pthread_mutex_lock(&inputState.mutex);
        strncpy(inputState.buffer, message, MSG_SIZE - 1);
        inputState.length = charCount;
        pthread_mutex_unlock(&inputState.mutex);

        if (awaitingPassword && message[0] != '/')
        {
            awaitingPassword = false;
            deriveKeyFromPassword(message, currentEncryption.key);
            currentEncryption.hasKey = true;

            char toSend[MSG_SIZE];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            sendToServer(socketFD, toSend);

            memset(message, 0, strlen(message));

            pthread_mutex_lock(&inputState.mutex);
            inputState.buffer[0] = '\0';
            inputState.length = 0;
            pthread_mutex_unlock(&inputState.mutex);

            continue;
        }

        if (strcmp(message, "/exit") == 0)
        {
            sendToServer(socketFD, "/exit\n");
            break;
        }

        if (strcmp(message, "/clear") == 0)
        {
            clearScreen();
            print("SocketChat CLI (E2E Encrypted)\n\n");

            pthread_mutex_lock(&inputState.mutex);
            inputState.buffer[0] = '\0';
            inputState.length = 0;
            pthread_mutex_unlock(&inputState.mutex);

            continue;
        }

        if (strcmp(message, "/leave") == 0)
        {
            handleLeaveCommand(socketFD);

            pthread_mutex_lock(&inputState.mutex);
            inputState.buffer[0] = '\0';
            inputState.length = 0;
            pthread_mutex_unlock(&inputState.mutex);

            continue;
        }

        if (strncmp(message, "/enter ", 7) == 0)
        {
            char roomName[64] = {0};
            sscanf(message + 7, "%63s", roomName);
            strncpy(currentEncryption.roomName, roomName, sizeof(currentEncryption.roomName) - 1);
            awaitingPassword = true;

            char toSend[MSG_SIZE];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            sendToServer(socketFD, toSend);

            pthread_mutex_lock(&inputState.mutex);
            inputState.buffer[0] = '\0';
            inputState.length = 0;
            pthread_mutex_unlock(&inputState.mutex);

            continue;
        }

        if (message[0] == '/')
        {
            char toSend[MSG_SIZE];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            sendToServer(socketFD, toSend);

            pthread_mutex_lock(&inputState.mutex);
            inputState.buffer[0] = '\0';
            inputState.length = 0;
            pthread_mutex_unlock(&inputState.mutex);

            continue;
        }

        if (currentEncryption.hasKey)
        {
            unsigned char ciphertext[MSG_SIZE];
            int ciphertextLen = encryptMessage((unsigned char *)message, strlen(message), currentEncryption.key, ciphertext);

            if (ciphertextLen > 0)
            {
                char encoded[MSG_SIZE * 2];
                encodeBase64(ciphertext, ciphertextLen, encoded);

                char toSend[MSG_SIZE * 2 + 10];
                snprintf(toSend, MSG_SIZE * 2, "ENC:%s\n", encoded);
                sendToServer(socketFD, toSend);
            }
            else
            {
                print(COLOR_RED "[!] Failed to encrypt message\n" COLOR_RESET);
            }
        }
        else
        {
            char toSend[MSG_SIZE];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            sendToServer(socketFD, toSend);
        }

        pthread_mutex_lock(&inputState.mutex);
        inputState.buffer[0] = '\0';
        inputState.length = 0;
        pthread_mutex_unlock(&inputState.mutex);
    }

    print(COLOR_YELLOW "\n[*] Shutting down...\n" COLOR_RESET);
    close(socketFD);
    free(message);
    free(address);
    pthread_mutex_destroy(&inputState.mutex);

    return 0;
}