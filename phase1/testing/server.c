#include "microtcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    int len, n;
    microtcp_sock_t micro_socket;
    char buffer[1000];
    char *hello = "Hello from server";
    struct sockaddr_in servaddr, cliaddr;

    micro_socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(8080);

    if((microtcp_bind(&micro_socket,(const struct sockaddr *)&servaddr,sizeof(servaddr)))<0){
        perror("bind failed");
        exit(EXIT_FAILURE); 
    }

    len = sizeof(cliaddr);

    n = microtcp_recv(&micro_socket, (char *)buffer, 1000,MSG_WAITALL); 
	buffer[n] = '\0'; 
	printf("Client : %s\n", buffer); 
	microtcp_send(&micro_socket,(const char *)hello,strlen(hello),0); 
	printf("Hello message sent.\n");
}
