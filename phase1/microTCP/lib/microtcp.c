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
 * @version 0.1 - Phase 1
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
  NOTE: This file implements the handshake and shutdown. 
  We do not support TCP flow mechanisms yet. (Phase 1)
*/

microtcp_sock_t
microtcp_socket(int domain, int type, int protocol)
{
  microtcp_sock_t new_socket;
  memset(&new_socket, 0, sizeof(new_socket));

  /*MicroTCP library only uses UDP and IPv4*/
  protocol = 0;
  type = SOCK_DGRAM;
  
  if((new_socket.sd = socket(domain, type, protocol))< 0){
    //perror("Socket Failed");
    new_socket.state = INVALID;
    return new_socket;
  }

  new_socket.state = CREATED;
  return new_socket;
}

int
microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  int ret_val = bind(socket->sd, address, address_len);
  if(ret_val < 0){
    socket->state = INVALID;
    return -1;
  }
  socket->state = LISTEN; /*Check again*/
  return ret_val;
}

int
microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3;

  socket->address = (struct sockaddr *)address;
  socket->address_len = address_len;

  /*Sending first packet with appropriate fields*/
  memset(&header_1, 0, sizeof(header_1));
  header_1.seq_number = (get_random_int(1, 49));
  header_1.control = (set_control_bits(0, 0, 1, 0));
  header_ptr = &header_1;
  /*TODO: Error check for valid {?} send and use htons*/
  microtcp_raw_send(socket, header_ptr, sizeof(header_1), 0);
  if(DEBUG){
    printf("Packet 1:\n");
    print_header(header_1);
  }

  /*Recieving SYN packet*/
  header_ptr = &header_2;
  /*TODO: Error check for header validation*/
  microtcp_raw_recv(socket, header_ptr, sizeof(header_2), MSG_WAITALL);
  if (DEBUG){
    printf("Packet 2:\n");
    print_header(header_2);
  }

  /*Sending the third packet*/
  memset(&header_3, 0, sizeof(header_3));
  header_3.ack_number = header_2.seq_number + 1;
  header_3.control = set_control_bits(1, 0, 0, 0);
  header_3.seq_number = header_2.ack_number;
  header_ptr = &header_3;
  /*TODO: Error check for valid {?} send*/
  microtcp_raw_send(socket, header_ptr, sizeof(header_3), 0);
  if(DEBUG){
    printf("Packet 3:\n");
    print_header(header_3);
  }

  /*If no error occured, connection is established*/
  /*TODO: Add the rest of the fields*/
  socket->state = ESTABLISHED;
  socket->ack_number = header_3.ack_number;
  socket->seq_number = header_3.seq_number;
  socket->recvbuf = malloc(sizeof(uint8_t)*MICROTCP_RECVBUF_LEN); 
  return 0;
}

int
microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3;

  socket->address = address;
  socket->address_len = address_len;

  /*Waiting the first packet to arrive*/
  header_ptr = &header_1;
  microtcp_raw_recv(socket, header_ptr, sizeof(header_1), MSG_WAITALL);
  if(DEBUG){
    printf("Packet 1:\n");
    print_header(header_1);
  }
  /*Sending the second packet*/
  memset(&header_2, 0, sizeof(header_2));
  header_2.ack_number =  ( header_1.seq_number + 1 ) ;
  header_2.seq_number =  ( get_random_int(50, 100) ) ;
  header_2.control =  ( set_control_bits(1, 0, 1, 0) );
  header_ptr = &header_2;
  microtcp_raw_send(socket, header_ptr, sizeof(header_2), 0);
  if(DEBUG){
    printf("Packet 2:\n");
    print_header(header_2);
  }

  /*Waiting the third packet*/
  header_ptr = &header_3;
  microtcp_raw_recv(socket, header_ptr, sizeof(header_3), MSG_WAITALL);
  if (DEBUG){
    printf("Packet 3:\n");
    print_header(header_3);
  }

  socket->state = ESTABLISHED;

  //check again
  socket->seq_number =  ( header_2.seq_number ) ;
  socket->ack_number = (  header_2.ack_number ) ;
  socket->recvbuf = malloc(sizeof(uint8_t)*MICROTCP_RECVBUF_LEN);

  return 0;
}

int
microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3, header_4;

  /*Server side*/
  if(socket->state == CLOSING_BY_HOST){
    memset(&header_2, 0, sizeof(header_2));
    header_2.seq_number = (0);//get_random_int(101, 150);
    header_2.ack_number = (header_1.seq_number + 1);
    header_2.control = (set_control_bits(1, 0, 0, 0));
    header_ptr = &header_2;
    if (DEBUG){
      printf("Header 2:\n");
      print_header(header_2);
    }
    microtcp_raw_send(socket, header_ptr, sizeof(header_2), 0);

    memset(&header_3, 0, sizeof(header_3));
    header_3.seq_number = (get_random_int(101, 150));
    header_3.ack_number = (0); //tmp
    header_3.control = (set_control_bits(1, 0, 0, 1));
    header_ptr = &header_3;
    if(DEBUG){
      printf("Header 3:\n");
      print_header(header_3);
    }
    microtcp_raw_send(socket, header_ptr, sizeof(header_3), 0);
    
    header_ptr = &header_4;
    microtcp_raw_recv(socket, header_ptr, sizeof(header_4), MSG_WAITALL);
    //headervalidation
    if(DEBUG){
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
    header_1.ack_number = (socket->ack_number);
    header_1.seq_number = (socket->seq_number);
    header_1.control = (set_control_bits(1, 0, 0, 1)); //ACK FIN
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
    header_4.ack_number =  (  header_3.seq_number + 1 ) ;
    header_4.seq_number =  ( header_3.ack_number ) ;
    header_4.control =  ( set_control_bits(1, 0, 0, 0) ) ;
    header_ptr = &header_4;
    if(DEBUG){
      printf("Client header sent:\n");
      print_header(header_4);
    }
    microtcp_raw_send(socket, header_ptr, sizeof(header_4), 0);

    socket->seq_number =  (  header_4.seq_number ) ;
    socket->ack_number = (  header_4.ack_number ) ;
    socket->state = CLOSED;
    close(socket->sd);
  }
  free(socket->recvbuf);
  return 0;
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  ssize_t bytes_sent,data_sent; /*bytes_sent is data+header*/
  microtcp_header_t header;
  microtcp_header_t *header_ptr;
  void *packet;

  memset(&header, 0, sizeof(header));
  header_ptr = &header;

  packet = malloc((length + sizeof(header)) * sizeof(char));

  /*TODO: Discuss what the default header should have*/
  initiliaze_default_header(&header, *socket, length);
  memcpy(packet, header_ptr, sizeof(header));
  memcpy((packet + sizeof(header)), buffer, length);

  bytes_sent = sendto(socket->sd, packet, length + sizeof(header), flags, socket->address, socket->address_len);

  /*Generic error check*/
  if(bytes_sent == -1)
  {
    free(packet);
    return -1;
  }

  data_sent = bytes_sent - sizeof(header);

  /*Optional error check.
    NOTE: This does not catch every wrong recvfrom execution
    TODO: Discuss if we need this and what else should we do inside here*/
  if(data_sent < 0 ){
    free(packet);
    return -1;
  }
  
  /*TODO: Discuss this one.. maybe remove..*/
  if(data_sent == length){
    socket->seq_number =  ( socket->seq_number + length ) ;
    socket->ack_number =  header.ack_number;
  }

  free(packet);
  return data_sent;
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  ssize_t bytes_recieved, data_size;
  microtcp_header_t header,ack_header;
  microtcp_header_t *header_ptr;
  void *packet;

  memset(&header, 0, sizeof(header));
  header_ptr = &header;

  packet = malloc((length + sizeof(header)) * sizeof(char));
  bytes_recieved = recvfrom(socket->sd, packet, length + sizeof(header), flags, (socket->address), &socket->address_len);

  /*Generic error check*/
  if(bytes_recieved == -1){
    free(packet);
    return -1;
  }

  data_size = bytes_recieved - sizeof(header);

  /*Optional error check.
    NOTE: This does not catch every wrong recvfrom execution
    TODO: Discuss if we need this and what else should we do inside here*/
  if(data_size < 0){
    free(packet);
    return -1;
  }

  /*The above code executes in case recvfrom works successfully*/
  /*TODO: Print this header to see if we get the corresponding one of sendto*/
  memcpy(&header, packet, sizeof(header));
  memcpy(buffer, packet + (sizeof(header) * sizeof(char)), data_size); /*Check is "data_size is enough"*/

  socket->ack_number = header.ack_number; /*Check again*/
  socket->seq_number = header.seq_number; /*Check again*/

  /*If the recieved packet is connection termination packet (ACK-FIN),
    0 is returned and the socket gets into closing mode*/
  if(get_bit(header.control,0) && get_bit(header.control,3)){ 
    socket->state = CLOSING_BY_HOST;
    if(DEBUG){
      printf("Header 1:\n");
      print_header(header);
    }
    free(packet);
    return 0;
  }

  /*If this mode is a generic packet recieval, the data are written in the buffer*/
  /*if(bytes_recieved + socket->buf_fill_level <= MICROTCP_RECVBUF_LEN){
    memcpy((socket->recvbuf) + (socket->buf_fill_level),buffer,data_size);
    socket->buf_fill_level += data_size;
  }*/

  memset(socket->recvbuf, 0, MICROTCP_RECVBUF_LEN);
  if(bytes_recieved <= MICROTCP_RECVBUF_LEN){
    memcpy(socket->recvbuf, buffer, data_size);
    socket->buf_fill_level = data_size;
    socket->recvbuf[MICROTCP_RECVBUF_LEN-1] = '\0'; 
  }

  free(packet);
  /*Return the data size
  NOTE: This could return negative number uppon error on recvfrom
  TODO: Check if this is good practice*/
  return data_size; 
}

ssize_t
microtcp_raw_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  return recvfrom(socket->sd, buffer, length, flags, (socket->address), &socket->address_len);
}

ssize_t
microtcp_raw_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  return sendto(socket->sd, buffer, length, flags, (socket->address), socket->address_len);
}
