#include "../Utils/socketUtil.h"

char *IP = "74.125.200.101";
int PORT = 80;

int main()
{
    int socketFD = createTCPIPv4Socket();
    SocketAddress *address = getSocketAddress(IP, PORT);
    int result = connectToSocket(socketFD, address, sizeof(*address));

    char *message = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    char buffer[4096];

    send(socketFD, message, strlen(message), 0);
    recv(socketFD, buffer, 4096, 0);

    printf("Response: \n%s\n", buffer);
    free(address);
    return 0;
}