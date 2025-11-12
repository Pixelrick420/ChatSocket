#include "../Utils/socketUtil.h"
#include "../Utils/sha256.h"
#include "../Utils/aes.h"
#include <errno.h>
char *IP = "127.0.0.1";

RoomEncryption currentEncryption = {0};
#define MAX_BUFFERED_MESSAGES 100
typedef struct
{
    char messages[MAX_BUFFERED_MESSAGES][MSG_SIZE * 2];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
} MessageBuffer;

MessageBuffer msgBuffer = {0};

void initMessageBuffer()
{
    msgBuffer.head = 0;
    msgBuffer.tail = 0;
    msgBuffer.count = 0;
    pthread_mutex_init(&msgBuffer.lock, NULL);
}

void addToBuffer(const char *message)
{
    pthread_mutex_lock(&msgBuffer.lock);

    if (msgBuffer.count < MAX_BUFFERED_MESSAGES)
    {
        strncpy(msgBuffer.messages[msgBuffer.tail], message, MSG_SIZE * 2 - 1);
        msgBuffer.messages[msgBuffer.tail][MSG_SIZE * 2 - 1] = '\0';
        msgBuffer.tail = (msgBuffer.tail + 1) % MAX_BUFFERED_MESSAGES;
        msgBuffer.count++;
    }
    else
    {
        strncpy(msgBuffer.messages[msgBuffer.tail], message, MSG_SIZE * 2 - 1);
        msgBuffer.messages[msgBuffer.tail][MSG_SIZE * 2 - 1] = '\0';
        msgBuffer.tail = (msgBuffer.tail + 1) % MAX_BUFFERED_MESSAGES;
        msgBuffer.head = (msgBuffer.head + 1) % MAX_BUFFERED_MESSAGES;
    }

    pthread_mutex_unlock(&msgBuffer.lock);
}

void clearScreen()
{
    print("\033[2J\033[H");
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
                addToBuffer(formatted);
                printf("\r\033[K%s" COLOR_GREEN ">>> " COLOR_RESET, formatted);
                fflush(stdout);
                return;
            }
        }

        snprintf(formatted, sizeof(formatted), "%s[!] Failed to decrypt message%s\n",
                 COLOR_RED, COLOR_RESET);
        addToBuffer(formatted);
        printf("\r\033[K%s" COLOR_GREEN ">>> " COLOR_RESET, formatted);
        fflush(stdout);
        return;
    }

    if (strstr(buffer, "Error") || strstr(buffer, "error") ||
        strstr(buffer, "Failed") || strstr(buffer, "failed"))
    {
        snprintf(formatted, sizeof(formatted), "%s[!] %s%s\n", COLOR_RED, buffer, COLOR_RESET);
    }
    else if (strstr(buffer, "joined") || strstr(buffer, "left") ||
             strstr(buffer, "Room") || strstr(buffer, "Welcome") ||
             strstr(buffer, "Commands:") || strstr(buffer, "created") ||
             strstr(buffer, "Entered") || strstr(buffer, "Name set") ||
             strstr(buffer, "Incorrect") || strstr(buffer, "Left"))
    {
        snprintf(formatted, sizeof(formatted), "%s[*] %s%s\n", COLOR_YELLOW, buffer, COLOR_RESET);
    }
    else if (strstr(buffer, "Password"))
    {
        snprintf(formatted, sizeof(formatted), "%s[*] %s%s", COLOR_YELLOW, buffer, COLOR_RESET);
        addToBuffer(formatted);
        printf("\r\033[K%s", formatted);
        fflush(stdout);
        return;
    }
    else
    {
        snprintf(formatted, sizeof(formatted), "%s<< %s%s\n", COLOR_CYAN, buffer, COLOR_RESET);
    }

    addToBuffer(formatted);

    printf("\r\033[K%s" COLOR_GREEN ">>> " COLOR_RESET, formatted);
    fflush(stdout);
}

void *receiveThread(void *arg)
{
    int socketFD = *(int *)arg;
    char buffer[MSG_SIZE];

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
            printf("\r\033[K" COLOR_RED "[!] Connection closed by server\n" COLOR_RESET);
            break;
        }
        else
        {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                printf("\r\033[K" COLOR_RED "[!] Connection lost\n" COLOR_RESET);
                break;
            }
        }
    }

    return NULL;
}

void handleLeaveCommand(int socketFD)
{
    memset(&currentEncryption, 0, sizeof(currentEncryption));
    send(socketFD, "/leave\n", 7, 0);
}

int main(int argc, char *argv[])
{
    char *IP = "127.0.0.1";
    int port = PORT;

    if (argc >= 2)
    {
        IP = argv[1];
    }
    if (argc >= 3)
    {
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535)
        {
            fprintf(stderr, "Invalid port number: %s\n", argv[2]);
            fprintf(stderr, "Usage: %s [host/IP] [port]\n", argv[0]);
            return 1;
        }
    }

    if (argc > 3)
    {
        fprintf(stderr, "Usage: %s [host/IP] [port]\n", argv[0]);
        fprintf(stderr, "Example: %s 0.tcp.ngrok.io 12345\n", argv[0]);
        return 1;
    }
    initMessageBuffer();

    int socketFD = createTCPIPv4Socket();
    SocketAddress *address = getSocketAddress(IP, port, true);
    int result = connectToSocket(socketFD, address, sizeof(*address));

    pthread_t pid;
    pthread_create(&pid, NULL, receiveThread, &socketFD);
    pthread_detach(pid);

    char message[MSG_SIZE];
    bool awaitingPassword = false;

    clearScreen();
    print("SocketChat CLI \n");
    print("Type '/exit' to quit | Type '/clear' to clear screen\n\n");

    while (true)
    {
        printf(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);

        if (!fgets(message, MSG_SIZE, stdin))
        {
            break;
        }

        size_t charCount = strlen(message);
        if (charCount == 0)
            continue;

        if (message[charCount - 1] == '\n')
        {
            message[charCount - 1] = '\0';
            charCount--;
        }

        if (charCount == 0)
            continue;

        if (awaitingPassword && message[0] != '/')
        {
            awaitingPassword = false;
            deriveKeyFromPassword(message, currentEncryption.key);
            currentEncryption.hasKey = true;

            char toSend[MSG_SIZE + 1];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            send(socketFD, toSend, strlen(toSend), 0);

            memset(message, 0, strlen(message));
            continue;
        }

        if (strcmp(message, "/exit") == 0)
        {
            send(socketFD, "/exit\n", 6, 0);
            break;
        }

        if (strcmp(message, "/clear") == 0)
        {
            clearScreen();
            print("SocketChat CLI (E2E Encrypted)\n\n");
            continue;
        }

        if (strcmp(message, "/leave") == 0)
        {
            handleLeaveCommand(socketFD);
            continue;
        }

        if (strncmp(message, "/enter ", 7) == 0)
        {
            char roomName[64] = {0};
            sscanf(message + 7, "%63s", roomName);
            strncpy(currentEncryption.roomName, roomName, sizeof(currentEncryption.roomName) - 1);
            awaitingPassword = true;

            char toSend[MSG_SIZE + 1];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            send(socketFD, toSend, strlen(toSend), 0);
            continue;
        }

        if (message[0] == '/')
        {
            char toSend[MSG_SIZE + 1];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            send(socketFD, toSend, strlen(toSend), 0);
            continue;
        }

        if (currentEncryption.hasKey)
        {
            unsigned char ciphertext[MSG_SIZE];
            int ciphertextLen = encryptMessage((unsigned char *)message, strlen(message),
                                               currentEncryption.key, ciphertext);

            if (ciphertextLen > 0)
            {
                char encoded[MSG_SIZE * 2];
                encodeBase64(ciphertext, ciphertextLen, encoded);

                char toSend[MSG_SIZE * 2 + 10];
                int len = snprintf(toSend, sizeof(toSend), "ENC:%s\n", encoded);
                send(socketFD, toSend, len, 0);
            }
            else
            {
                print(COLOR_RED "[!] Failed to encrypt message\n" COLOR_RESET);
            }
        }
        else
        {
            char toSend[MSG_SIZE + 1];
            int len = snprintf(toSend, MSG_SIZE, "%s\n", message);
            send(socketFD, toSend, len, 0);
        }
    }

    close(socketFD);
    free(address);
    pthread_mutex_destroy(&msgBuffer.lock);
    return 0;
}