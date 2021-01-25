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
 * @author George Kokolakis (gkokol@ics.forth.gr)
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

#define MAXSIZE 500000
#define PORT 8080

int main(int argc, char **argv)
{
    int len, n, count;
    char buffer[MAXSIZE];
    int db = 1;

    microtcp_sock_t socket;
    struct sockaddr_in servaddr, cliaddr;

    DEBUG = db;
    DEBUG_DATA = db;
    DEBUG_TCP_FLOW = 0;

    printf("Server running...\n");

    socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);
    if (socket.state == INVALID)
    {
        perror("Microtcp socket");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    /*Filling server information*/
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if ((microtcp_bind(&socket, (const struct sockaddr *)&servaddr, sizeof(servaddr))) < 0)
    {
        perror("Bind");
        exit(EXIT_FAILURE);
    }

    if ((microtcp_accept(&socket, (struct sockaddr *)&cliaddr, sizeof(cliaddr))) < 0)
    {
        perror("Accept\n");
        exit(EXIT_FAILURE);
    }

    while ((n = microtcp_recv(&socket, (char *)buffer, MAXSIZE, MSG_WAITALL)) > 0)
    {
        count += n;
        buffer[count] = '\0';
        //printf("Data: %s\n", buffer);
        printf("Data received: %d\n", n);
    }

    printf("Total data recieved: %d\n", count);

    if (microtcp_shutdown(&socket, 0) < 0)
    {
        perror("Shut down\n");
        exit(EXIT_FAILURE);
    }

    if (socket.state == CLOSED)
    {
        printf("Shutdown succeed\n");
    }

    print_server_statistics(socket);

    return 0;
}
