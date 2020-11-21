/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */

/**
 * @file test_microtcp_server.c
 * @author Manos Chatzakis (chatzakis@ics.forth.gr)
 * @author George Kokolakis (kokol@ics.forth.gr)
 * @brief An example of micro tcp implementation following client-server model.
 * @version 0.1
 * @date 2020-11-18
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#include "../lib/microtcp.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAXSIZE 1000
#define PORT 8080

int
main(int argc, char **argv)
{
    int len, n;
    
    char * str1 = "Server 1";
    char * str2 = "Server 2";
    char * str3 = "Server 3";

    char buffer[MAXSIZE];

    microtcp_sock_t socket;
    struct sockaddr_in servaddr;

    printf("Server running...\n");

    socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);
    if(socket.state == INVALID)
    {
        printf("Socket error");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if((microtcp_bind(&socket,(const struct sockaddr *)&servaddr,sizeof(servaddr)))<0){
        printf("bind failed");
        exit(EXIT_FAILURE); 
    }

    if((microtcp_accept(&socket,(struct sockaddr *)&servaddr,sizeof(servaddr)))<0)
    {
        printf("Could not accept connection\n");
        return -1;
    }

    /*n = microtcp_send(&socket,(const char *)str1, 9,0);
    printf("Send message to client of %d bytes.\n",n);
    n = microtcp_recv(&socket,(char *)buffer,MAXSIZE,MSG_WAITALL);
    buffer[n] = '\0';
    printf("First message recieved: %s\n",buffer);
    n = microtcp_send(&socket,(const char *)str2, 9,0);
    printf("Send message to client of %d bytes.\n",n);
    n = microtcp_recv(&socket,(char *)buffer,MAXSIZE,MSG_WAITALL);
    buffer[n] = '\0';
    printf("Second message recieved: %s\n",buffer);
    n = microtcp_send(&socket,(const char *)str3, 9,0);
    printf("Send message to client of %d bytes.\n",n)
    n = microtcp_recv(&socket,(char *)buffer,MAXSIZE,MSG_WAITALL);
    buffer[n] = '\0';
    printf("Third message recieved: %s\n",buffer);*/

    while((microtcp_recv(&socket,(char *)buffer,MAXSIZE,MSG_WAITALL))>0){
        printf("Message received: %s",buffer);
    }
    
    if(microtcp_shutdown(&socket,0)<0){
        printf("Error shuting down connection\n");
        return -1;
    }

    if(socket.state == CLOSED){
        printf("Shutdown succeed\n");
    }

    return 0;
}
