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

int
main(int argc, char **argv)
{
    int len, n;
    microtcp_sock_t micro_socket;
    struct sockaddr_in servaddr;

    micro_socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

    if(micro_socket.state == INVALID)
    {
        printf("Socket error");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(8080);

    if((microtcp_bind(&micro_socket,(const struct sockaddr *)&servaddr,sizeof(servaddr)))<0){
        printf("bind failed");
        exit(EXIT_FAILURE); 
    }

    if((microtcp_accept(&micro_socket,(struct sockaddr *)&servaddr,sizeof(servaddr)))<0)
    {
        printf("Could not accept connection\n");
    }

    char str[] = "Message from server to client!";
    microtcp_send(&micro_socket,(const char *)str, 31,0);

    return 0;
}
