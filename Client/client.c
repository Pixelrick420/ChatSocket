#include "../Utils/socketUtil.h"

char *IP = "127.0.0.1";

int main()
{
    int socketFD = createTCPIPv4Socket();
    SocketAddress *address = getSocketAddress(IP, PORT, true);
    int result = connectToSocket(socketFD, address, sizeof(*address));

    char *message = NULL;
    size_t msgSize = 0;
    char *buffer = (char *)malloc(sizeof(char) * MSG_SIZE);

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