#include "../Utils/socketUtil.h"

char *LOCALHOST = "127.0.0.1";
int PORT = 2077;
int BACKLOG = 10;
int main()
{
    int socketFD = createTCPIPv4Socket();
    SocketAddress *address = getSocketAddress(LOCALHOST, PORT, false);
    bindServerToSocket(socketFD, address, sizeof(*address));
    SocketAddress clientAddr;
    int clientSocketFD = listenToClient(socketFD, BACKLOG, &clientAddr);

    char buffer[1024];
    recv(clientSocketFD, buffer, 1024, 0);
    printf("Response: \n%s\n", buffer);
    free(address);
    return 0;
}