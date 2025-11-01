#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main()
{
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        printf("Error creating socket\n");
        exit(1);
    }

    char *ip = "74.125.200.101"; // google ip address for now
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(80);
    inet_pton(AF_INET, ip, &address.sin_addr.s_addr);
    int result = connect(socketFD, (struct sockaddr *)&address, sizeof(address));
    if (result == 0)
    {
        printf("Connection Succesfull\n");
    }
    return 0;
}