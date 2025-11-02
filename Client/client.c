#include "../Utils/socketUtil.h"

char *IP = "127.0.0.1";

void *receiveThread(void *arg)
{
    int socketFD = *(int *)arg;
    recieveMessages(socketFD);
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

    printf("SocketChat CLI\n");
    while (true)
    {
        size_t charCount = getline(&message, &msgSize, stdin);
        if ((charCount > 0) && strcmp(message, "exit\n") == 0)
        {
            break;
        }
        size_t amountSent = send(socketFD, message, charCount, 0);
    }

    close(socketFD);
    free(message);
    free(address);
    return 0;
}