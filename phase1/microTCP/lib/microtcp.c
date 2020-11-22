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

/**
 * @file microtcp.c 
 * @author Manos Chatzakis (chatzakis@ics.forth.gr)
 * @author George Kokolakis (kokol@ics.forth.gr)
 * @brief microTCP implementation for the undergraduate course cs335a
 * @version 0.1
 * @date 2020-11-18
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "microtcp.h"
#include "common.h"
#include "../utils/crc32.h"

#define DEBUG 0

/*
*
* TODO: Validate all headers recieve to cover error checking.
*
*
*
*/

microtcp_sock_t
microtcp_socket(int domain, int type, int protocol)
{
  microtcp_sock_t new_socket;
  memset(&new_socket, 0, sizeof(new_socket));
  protocol = 0;
  type = SOCK_DGRAM;
  if ((new_socket.sd = socket(domain, type, protocol)) < 0)
  {
    perror("Socket Failed.");
    new_socket.state = INVALID;
    return new_socket;
  }
  new_socket.state = CREATED;
  return new_socket;
}

int
microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  /*Errno and error handling is done inside bind*/
  int ret_val = bind(socket->sd, address, address_len);
  if(ret_val < 0){
    socket->state = INVALID;
    return -1;
  }
  socket->state = LISTEN;
  return ret_val;
}

int
microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3;

  socket->address = (struct sockaddr *)address;
  socket->address_len = address_len;

  /*Sending first packet with appropriate fields*/
  memset(&header_1, 0, sizeof(header_1));
  header_1.seq_number = get_random_int(1, 49);
  header_1.control = set_control_bits(0, 0, 1, 0);
  header_ptr = &header_1;
  microtcp_raw_send(socket, header_ptr, sizeof(header_1), 0);
  if (DEBUG)
  {
    printf("Packet 1:\n");
    print_header(header_1);
  }

  /*Recieving SYN packet*/
  header_ptr = &header_2;
  microtcp_raw_recv(socket, header_ptr, sizeof(header_2), MSG_WAITALL);
  if (DEBUG)
  {
    printf("Packet 2:\n");
    print_header(header_2);
  }

  /*Sending the third packet*/
  memset(&header_3, 0, sizeof(header_3));
  header_3.ack_number = header_2.seq_number + 1;
  header_3.control = set_control_bits(1, 0, 0, 0);
  header_3.seq_number = header_2.ack_number;
  header_ptr = &header_3;
  microtcp_raw_send(socket, header_ptr, sizeof(header_3), 0);
  if (DEBUG)
  {
    printf("Packet 3:\n");
    print_header(header_3);
  }

  /*If no error occured, connection is established*/
  socket->state = ESTABLISHED;
  socket->ack_number = header_3.ack_number;
  socket->seq_number = header_3.seq_number;

  return 0; //may return 1 on success, 0 on failure?
}

int
microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3;

  socket->address = address;
  socket->address_len = address_len;

  /*Waiting the first packet to arrive*/
  header_ptr = &header_1;
  microtcp_raw_recv(socket, header_ptr, sizeof(header_1), MSG_WAITALL);
  if (DEBUG)
  {
    printf("Packet 1:\n");
    print_header(header_1);
  }
  /*Sending the second packet*/
  memset(&header_2, 0, sizeof(header_2));
  header_2.ack_number = header_1.seq_number + 1;
  header_2.seq_number = get_random_int(50, 100);
  header_2.control = set_control_bits(1, 0, 1, 0);
  header_ptr = &header_2;
  microtcp_raw_send(socket, header_ptr, sizeof(header_2), 0);
  if (DEBUG)
  {
    printf("Packet 2:\n");
    print_header(header_2);
  }

  /*Waiting the third packet*/
  header_ptr = &header_3;
  microtcp_raw_recv(socket, header_ptr, sizeof(header_3), MSG_WAITALL);
  if (DEBUG)
  {
    printf("Packet 3:\n");
    print_header(header_3);
  }

  socket->state = ESTABLISHED;

  //check again
  socket->seq_number = header_2.seq_number;
  socket->ack_number = header_2.ack_number;

  return 0;
}

int
microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3, header_4;

  if(socket->state == CLOSING_BY_HOST){
    memset(&header_2, 0, sizeof(header_2));
    header_2.seq_number = 0;//get_random_int(101, 150);
    header_2.ack_number = header_1.seq_number + 1;
    header_2.control = set_control_bits(1, 0, 0, 0);
    header_ptr = &header_2;
    if (DEBUG)
    {
      printf("Header 2:\n");
      print_header(header_2);
    }
    microtcp_raw_send(socket, header_ptr, sizeof(header_2), 0);

    memset(&header_3, 0, sizeof(header_3));
    header_3.seq_number = get_random_int(101, 150);
    header_3.ack_number = 0; //tmp
    header_3.control = set_control_bits(1, 0, 0, 1);
    header_ptr = &header_3;
    if (DEBUG)
    {
      printf("Header 3:\n");
      print_header(header_3);
    }
    microtcp_raw_send(socket, header_ptr, sizeof(header_3), 0);
    
    header_ptr = &header_4;
    microtcp_raw_recv(socket, header_ptr, sizeof(header_4), MSG_WAITALL);
    //headervalidation
    if (DEBUG)
    {
      printf("Header 4:\n");
      print_header(header_4);
    }

    socket->ack_number = header_4.ack_number;//??
    socket->seq_number = header_4.seq_number;//??
    socket->state = CLOSED;
    close(socket->sd);
  }
  else{
    socket->state = CLOSING_BY_PEER;
    memset(&header_1, 0, sizeof(header_1));
    header_1.ack_number = socket->ack_number;
    header_1.seq_number = socket->seq_number;
    header_1.control = set_control_bits(1, 0, 0, 1); //ACK FIN
    header_ptr = &header_1;
    if(DEBUG){
      printf("Header 1:\n");
      print_header(header_1);
    }
    microtcp_raw_send(socket, header_ptr, sizeof(header_1), 0);

    header_ptr = &header_2;
    microtcp_raw_recv(socket, header_ptr, sizeof(header_2), MSG_WAITALL);
    if(DEBUG){
      printf("Header 2:\n");
      print_header(header_2);
    }  

    header_ptr = &header_3;
    microtcp_raw_recv(socket, header_ptr, sizeof(header_3), MSG_WAITALL);
    if(DEBUG){
      printf("Header 3:\n");
      print_header(header_3);
    }

    memset(&header_4, 0, sizeof(header_4));
    header_4.ack_number = header_3.seq_number + 1;
    header_4.seq_number = header_3.ack_number;
    header_4.control = set_control_bits(1, 0, 0, 0);
    header_ptr = &header_4;
    if(DEBUG)
    {
      printf("Client header sent:\n");
      print_header(header_4);
    }
    microtcp_raw_send(socket, header_ptr, sizeof(header_4), 0);

    socket->seq_number = header_4.seq_number;
    socket->ack_number = header_4.ack_number;
    socket->state = CLOSED;
    close(socket->sd);
  }

  return 0;
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,
              int flags)
{
  microtcp_header_t header;
  void *packet = malloc((length + sizeof(header)) * sizeof(char));
  memset(&header, 0, sizeof(header));
  microtcp_header_t *header_ptr = &header;
  initiliaze_default_header(&header, *socket, length);

  memcpy((packet + sizeof(header)), buffer, length);
  memcpy(packet, header_ptr, sizeof(header));

  ssize_t bytes_sent = sendto(socket->sd, packet, length + sizeof(header), flags, (socket->address), socket->address_len);

  if(bytes_sent == -1)
  {
    return -1;
  }

  if(bytes_sent == length + sizeof(header))
  {
    socket->seq_number = socket->seq_number + length;
    socket->ack_number = header.ack_number;
  }
  
  free(packet);
  return bytes_sent - sizeof(header);
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  microtcp_header_t header,ack_header;
  memset(&header, 0, sizeof(header));
  microtcp_header_t *header_ptr = &header;

  void *tmp = malloc((length + sizeof(header)) * sizeof(char));

  ssize_t bytes_recieved = recvfrom(socket->sd, tmp, length + sizeof(header), flags, (socket->address), &socket->address_len);

  if(bytes_recieved == -1){
    free(tmp);
    return -1;
  }

  memcpy(&header, tmp, sizeof(header));
  memcpy(buffer, tmp + (sizeof(header) * sizeof(char)), length);

  socket->ack_number = header.ack_number;
  socket->seq_number = header.seq_number;

  if(get_bit(header.control,15) && get_bit(header.control,12)){
    socket->state = CLOSING_BY_HOST;
    if(DEBUG){
      printf("Header 1:\n");
      print_header(header);
    }
    return 0;
  }

  free(tmp);
  return bytes_recieved - sizeof(header);
}

ssize_t
microtcp_raw_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  return recvfrom(socket->sd, buffer, length, flags, (socket->address), &socket->address_len);
}

ssize_t
microtcp_raw_send(microtcp_sock_t *socket, const void *buffer, size_t length,
                  int flags)
{
  return sendto(socket->sd, buffer, length, flags, (socket->address), socket->address_len);
}
