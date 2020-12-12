/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2017  Manolis Surligas <surligas@gmail.com>
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include "../lib/microtcp.h"
#include "../utils/log.h"

#define MAXSIZE 1000
static char running = 1;

static void
print_statistics (ssize_t received, struct timespec start, struct timespec end)
{
  double elapsed = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) * 1e-9;
  double megabytes = received / (1024.0 * 1024.0);

  printf ("Data received: %f MB\n", megabytes);
  printf ("Transfer time: %f seconds\n", elapsed);
  printf ("Throughput achieved: %f MB/s\n", megabytes / elapsed);
}

static void
sig_handler(int signal)
{
  if (signal == SIGINT)
  {
    LOG_INFO("Stopping traffic generator client...");
    running = 0;
  }
}

int main(int argc, char **argv)
{
  uint16_t port = 8080;
  struct timespec start_time;
  struct timespec end_time;
  int n,count = 0;
  char buffer[MAXSIZE];

  /*
   * Register a signal handler so we can terminate the client with
   * Ctrl+C
   */
  signal(SIGINT, sig_handler);

  LOG_INFO("Start receiving traffic from port %u", port);
  /*TODO: Connect using microtcp_connect() */

  microtcp_sock_t socket;
  struct sockaddr_in servaddr;

  printf("Client running...\n");

  socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);
  if (socket.state == INVALID)
  {
    perror("Microtcp socket\n");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));

  /*Filling server information*/
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  servaddr.sin_addr.s_addr = INADDR_ANY;

  if ((microtcp_connect(&socket, (const struct sockaddr *)&servaddr, sizeof(servaddr))) < 0)
  {
    perror("Connect\n");
    exit(EXIT_FAILURE);
  }

  clock_gettime (CLOCK_MONOTONIC_RAW, &start_time);
  while (running)
  {

    if((n = microtcp_recv(&socket, (char *)buffer, MAXSIZE, MSG_WAITALL)) > 0){
      printf("Message received: %s (%d bytes)\n", buffer, n);
      count += n;
    }

  }
  clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
  
  //socket.state = CLOSING_BY_HOST;
  microtcp_shutdown(&socket,0);

  print_statistics(count, start_time, end_time);
}
