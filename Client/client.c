#include "../Utils/socketUtil.h"
#include "../Utils/sha256.h"
#include "../Utils/aes.h"

char *IP = "216.24.57.251";

RoomEncryption currentEncryption = {0};

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
                    snprintf(formatted, sizeof(formatted), "\r%s<< %s: %s%s",
                             COLOR_CYAN, username, decrypted, COLOR_RESET);
                }
                else
                {
                    snprintf(formatted, sizeof(formatted), "\r%s<< %s%s",
                             COLOR_CYAN, decrypted, COLOR_RESET);
                }
                print(formatted);
                print(COLOR_GREEN "\n>>> " COLOR_RESET);
                fflush(stdout);
                return;
            }
        }

        snprintf(formatted, sizeof(formatted), "\r%s[!] Failed to decrypt message%s",
                 COLOR_RED, COLOR_RESET);
        print(formatted);
        print(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);
        return;
    }

    if (strstr(buffer, "Error") || strstr(buffer, "error") ||
        strstr(buffer, "Failed") || strstr(buffer, "failed"))
    {
        snprintf(formatted, sizeof(formatted), "\r%s[!] %s%s", COLOR_RED, buffer, COLOR_RESET);
        print(formatted);
        print(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);
    }
    else if (strstr(buffer, "joined") || strstr(buffer, "left") ||
             strstr(buffer, "Room") || strstr(buffer, "Welcome") ||
             strstr(buffer, "Commands:") || strstr(buffer, "created") ||
             strstr(buffer, "Entered") || strstr(buffer, "Name set") ||
             strstr(buffer, "Incorrect") || strstr(buffer, "Left"))
    {
        snprintf(formatted, sizeof(formatted), "\r%s[*] %s%s", COLOR_YELLOW, buffer, COLOR_RESET);
        print(formatted);
        print(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);
    }
    else if (strstr(buffer, "Password"))
    {
        snprintf(formatted, sizeof(formatted), "\r%s[*] %s%s", COLOR_YELLOW, buffer, COLOR_RESET);
        print(formatted);
        fflush(stdout);
    }
    else
    {
        snprintf(formatted, sizeof(formatted), "\r%s<< %s%s", COLOR_CYAN, buffer, COLOR_RESET);
        print(formatted);
        print(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);
    }
}

void *receiveThread(void *arg)
{
    int socketFD = *(int *)arg;
    char *buffer = (char *)malloc(sizeof(char) * MSG_SIZE);

    while (true)
    {
        size_t received = recv(socketFD, buffer, MSG_SIZE, 0);
        if (received > 0)
        {
            buffer[received] = 0;
            processIncomingMessage(buffer, received);
        }
        else
        {
            print(COLOR_RED "[!] Connection lost\n" COLOR_RESET);
            break;
        }
    }

    free(buffer);
    return NULL;
}

void handleLeaveCommand(int socketFD)
{
    memset(&currentEncryption, 0, sizeof(currentEncryption));
    send(socketFD, "/leave\n", 7, 0);
}

int main()
{
    int socketFD = createTCPIPv4Socket();
    SocketAddress *address = getSocketAddress(IP, PORT, true);
    int result = connectToSocket(socketFD, address, sizeof(*address));

    pthread_t pid;
    pthread_create(&pid, NULL, receiveThread, &socketFD);
    pthread_detach(pid);

    char *message = NULL;
    size_t msgSize = 0;
    bool awaitingPassword = false;

    clearScreen();
    print("SocketChat CLI \n");
    print("Type '/exit' to quit | Type '/clear' to clear screen\n\n");

    while (true)
    {
        printf(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);

        size_t charCount = getline(&message, &msgSize, stdin);
        if (charCount <= 0)
            continue;

        if (message[charCount - 1] == '\n')
        {
            message[charCount - 1] = '\0';
            charCount--;
        }

        if (awaitingPassword && message[0] != '/')
        {
            awaitingPassword = false;
            deriveKeyFromPassword(message, currentEncryption.key);
            currentEncryption.hasKey = true;

            char toSend[MSG_SIZE];
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

            char toSend[MSG_SIZE];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            send(socketFD, toSend, strlen(toSend), 0);
            continue;
        }

        if (message[0] == '/')
        {
            char toSend[MSG_SIZE];
            snprintf(toSend, MSG_SIZE, "%s\n", message);
            send(socketFD, toSend, strlen(toSend), 0);
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
                send(socketFD, toSend, strlen(toSend), 0);
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
            send(socketFD, toSend, strlen(toSend), 0);
        }
    }

    close(socketFD);
    free(message);
    free(address);
    return 0;
}