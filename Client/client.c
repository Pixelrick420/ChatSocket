#include "../Utils/socketUtil.h"

char *IP = "127.0.0.1";
int PORT = 2077;

int main()
{
    int socketFD = createTCPIPv4Socket();
    SocketAddress *address = getSocketAddress(IP, PORT, true);
    int result = connectToSocket(socketFD, address, sizeof(*address));

    char *message = "Hello from the client\n";
    char buffer[4096];

    send(socketFD, message, strlen(message), 0);
    recv(socketFD, buffer, 4096, 0);

    printf("Response: \n%s\n", buffer);
    free(address);
    return 0;
}