#include "../Utils/socketUtil.h"

char *IP = "127.0.0.1";

void clearScreen()
{
    print("\033[2J\033[H");
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

            char formatted[MSG_SIZE + 20];

            if (strstr(buffer, "Error") || strstr(buffer, "error") ||
                strstr(buffer, "Failed") || strstr(buffer, "failed"))
            {
                snprintf(formatted, sizeof(formatted), "\r%s[!] %s%s", COLOR_RED, buffer, COLOR_RESET);
            }
            else if (strstr(buffer, "joined") || strstr(buffer, "left") ||
                     strstr(buffer, "Room") || strstr(buffer, "Welcome") ||
                     strstr(buffer, "Commands:") || strstr(buffer, "created") ||
                     strstr(buffer, "Entered") || strstr(buffer, "Name set") ||
                     strstr(buffer, "Password") || strstr(buffer, "Incorrect"))
            {
                snprintf(formatted, sizeof(formatted), "\r%s[*] %s%s", COLOR_YELLOW, buffer, COLOR_RESET);
            }
            else
            {
                snprintf(formatted, sizeof(formatted), "\r%s<< %s%s", COLOR_CYAN, buffer, COLOR_RESET);
            }

            print(formatted);
            print(COLOR_GREEN ">>> " COLOR_RESET);
            fflush(stdout);
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

    clearScreen();
    print("SocketChat CLI\n");
    print("Type '/exit' to quit | Type '/clear' to clear screen\n\n");

    while (true)
    {
        printf(COLOR_GREEN ">>> " COLOR_RESET);
        fflush(stdout);

        size_t charCount = getline(&message, &msgSize, stdin);
        if ((charCount > 0) && strcmp(message, "/exit\n") == 0)
        {
            break;
        }

        if ((charCount > 0) && strcmp(message, "/clear\n") == 0)
        {
            clearScreen();
            print("SocketChat CLI\n\n");
            continue;
        }

        size_t amountSent = send(socketFD, message, charCount, 0);
        if (amountSent <= 0)
        {
            print(COLOR_RED "[!] Failed to send message\n" COLOR_RESET);
        }
    }

    close(socketFD);
    free(message);
    free(address);
    return 0;
}