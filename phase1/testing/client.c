#include "microtcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    int n, len;
    char buffer[1000];
    microtcp_sock_t socket;
    char *hello = "Hello from client";
    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8080);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    socket.address =(struct sockaddr *)&servaddr;
    socket.address_len = sizeof(servaddr);

    microtcp_send(&socket,(const char *)hello,strlen(hello),0);
    printf("Hello message sent.\n");

    n = microtcp_recv(&socket, (char *)buffer, 1000,MSG_WAITALL); 

    buffer[n] = '\0';
    printf("Server : %s\n", buffer);

    //close(socket.sd);
    return 0;
}