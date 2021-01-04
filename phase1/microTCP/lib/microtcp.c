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
 * @author George Kokolakis (gkokol@ics.forth.gr)
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

#define DEBUG 1
#define DEBUG_DATA 1

microtcp_sock_t
microtcp_socket(int domain, int type, int protocol)
{
  microtcp_sock_t new_socket;
  memset(&new_socket, 0, sizeof(new_socket));

  //new_socket.state =
  /*MicroTCP library only uses UDP and IPv4*/
  protocol = 0;
  type = SOCK_DGRAM;
  domain = AF_INET;

  if ((new_socket.sd = socket(domain, type, protocol)) < 0)
  {
    new_socket.state = INVALID;
    return new_socket;
  }

  new_socket.state = CREATED;
  return new_socket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  int ret_val;

  if (socket == NULL)
    return -1;

  ret_val = bind(socket->sd, address, address_len);
  if (ret_val < 0)
  {
    socket->state = INVALID;
    return -1;
  }

  socket->state = LISTEN;
  return ret_val;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3;

  if (socket == NULL)
    return -1;

  socket->address = (struct sockaddr *)address;
  socket->address_len = address_len;

  /*Sending first packet with appropriate fields*/
  memset(&header_1, 0, sizeof(microtcp_header_t));
  header_1.seq_number = get_random_int(1, 49);
  header_1.control = set_control_bits(0, 0, 1, 0);
  header_1.window = MICROTCP_WIN_SIZE;
  header_1.checksum = crc32(&header_1, sizeof(microtcp_header_t));

  convert_to_network_header(&header_1);
  microtcp_raw_send(socket, &header_1, sizeof(header_1), 0);
  convert_to_local_header(&header_1);

  if (DEBUG)
  {
    printf("Packet 1:\n");
    print_header(header_1);
  }

  /*Recieving SYN ACK packet*/
  microtcp_raw_recv(socket, &header_2, sizeof(header_2), MSG_WAITALL);
  convert_to_local_header(&header_2);

  if (DEBUG)
  {
    printf("Packet 2:\n");
    print_header(header_2);
  }

  if (!validate_header(&header_2, header_1.seq_number, 0))
    return -1;

  /*Sending the third packet*/
  memset(&header_3, 0, sizeof(header_3));
  header_3.ack_number = header_2.seq_number + 1;
  header_3.control = set_control_bits(1, 0, 0, 0);
  header_3.seq_number = header_2.ack_number;
  header_3.window = MICROTCP_WIN_SIZE;
  header_3.checksum = crc32(&header_3, sizeof(microtcp_header_t));

  convert_to_network_header(&header_3);
  microtcp_raw_send(socket, &header_3, sizeof(header_3), 0);
  convert_to_local_header(&header_3);

  if (DEBUG)
  {
    printf("Packet 3:\n");
    print_header(header_3);
  }

  /*If no error occured, connection is established*/
  socket->state = ESTABLISHED;

  socket->ack_number = header_3.ack_number;
  socket->seq_number = header_3.seq_number + 1;

  socket->init_win_size = header_2.window;
  socket->curr_win_size = header_2.window;

  socket->recvbuf = malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level = 0;

  return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3;

  if (socket == NULL)
    return -1;

  socket->address = address;
  socket->address_len = address_len;

  /*Waiting the first packet to arrive*/
  microtcp_raw_recv(socket, &header_1, sizeof(header_1), MSG_WAITALL);
  convert_to_local_header(&header_1);

  if (DEBUG)
  {
    printf("Packet 1:\n");
    print_header(header_1);
  }

  if (!validate_header(&header_1, 0, 1))
  {
    return -1;
  }

  /*Sending the second packet*/
  memset(&header_2, 0, sizeof(header_2));
  header_2.ack_number = header_1.seq_number + 1;
  header_2.seq_number = get_random_int(50, 99);
  header_2.control = set_control_bits(1, 0, 1, 0);
  header_2.window = MICROTCP_WIN_SIZE;
  header_2.checksum = crc32(&header_2, sizeof(microtcp_header_t));

  convert_to_network_header(&header_2);
  microtcp_raw_send(socket, &header_2, sizeof(header_2), 0);
  convert_to_local_header(&header_2);

  if (DEBUG)
  {
    printf("Packet 2:\n");
    print_header(header_2);
  }

  /*Waiting the third packet*/
  microtcp_raw_recv(socket, &header_3, sizeof(header_3), MSG_WAITALL);
  convert_to_local_header(&header_3);

  if (DEBUG)
  {
    printf("Packet 3:\n");
    print_header(header_3);
  }

  if (!validate_header(&header_3, header_2.seq_number, 0))
    return -1;

  socket->state = ESTABLISHED;

  socket->seq_number = header_3.ack_number;
  socket->ack_number = header_3.seq_number + 1;

  socket->init_win_size = header_3.window;
  socket->curr_win_size = header_3.window;

  socket->recvbuf = malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level = 0;

  return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  int ret_val;

  microtcp_header_t *header_ptr;
  microtcp_header_t header_1, header_2, header_3, header_4;

  /*Server side*/
  if (socket->state == CLOSING_BY_PEER)
  {
    socket->seq_number += 1;
    memset(&header_3, 0, sizeof(header_3));
    header_3.seq_number = socket->seq_number;
    header_3.ack_number = socket->ack_number;
    header_3.control = set_control_bits(1, 0, 0, 1);
    header_3.checksum = crc32(&header_3, sizeof(microtcp_header_t));

    convert_to_network_header(&header_3);
    microtcp_raw_send(socket, &header_3, sizeof(header_3), 0);
    convert_to_local_header(&header_3);

    if (DEBUG)
    {
      printf("Header 3:\n");
      print_header(header_3);
    }
    microtcp_raw_recv(socket, &header_4, sizeof(header_4), MSG_WAITALL);
    convert_to_local_header(&header_4);

    if (DEBUG)
    {
      printf("Header 4:\n");
      print_header(header_4);
    }

    if (!validate_header(&header_4, header_3.seq_number, 0))
      return -1;

    socket->seq_number = header_4.ack_number;
    socket->ack_number = header_4.seq_number + 1;

    socket->state = CLOSED;
    close(socket->sd);
  }
  else
  { //client

    socket->ack_number += 1;

    memset(&header_1, 0, sizeof(header_1));
    header_1.ack_number = (socket->ack_number);
    header_1.seq_number = (socket->seq_number);
    header_1.control = (set_control_bits(1, 0, 0, 1));
    header_1.checksum = crc32(&header_1, sizeof(microtcp_header_t));

    convert_to_network_header(&header_1);
    microtcp_raw_send(socket, &header_1, sizeof(header_1), 0);
    convert_to_local_header(&header_1);

    if (DEBUG)
    {
      printf("Header 1:\n");
      print_header(header_1);
    }

    microtcp_raw_recv(socket, &header_2, sizeof(header_2), MSG_WAITALL);
    convert_to_local_header(&header_2);

    if (DEBUG)
    {
      printf("Header 2:\n");
      print_header(header_2);
    }

    if (!validate_header(&header_2, header_1.seq_number, 1))
      return -1;

    socket->state = CLOSING_BY_HOST;

    microtcp_raw_recv(socket, &header_3, sizeof(header_3), MSG_WAITALL);
    convert_to_local_header(&header_3);

    if (DEBUG)
    {
      printf("Header 3:\n");
      print_header(header_3);
    }

    if (!validate_header(&header_3, header_1.seq_number, 0))
      return -1;

    memset(&header_4, 0, sizeof(header_4));
    header_4.ack_number = header_3.seq_number + 1;
    header_4.seq_number = header_3.ack_number;
    header_4.control = set_control_bits(1, 0, 0, 0);
    header_4.checksum = crc32(&header_4, sizeof(microtcp_header_t));

    convert_to_network_header(&header_4);
    microtcp_raw_send(socket, &header_4, sizeof(header_4), 0);
    convert_to_local_header(&header_4);

    if (DEBUG)
    {
      printf("Header 4:\n");
      print_header(header_4);
    }

    socket->seq_number = header_4.seq_number + 1;
    socket->ack_number = header_4.ack_number;

    socket->state = CLOSED;
    close(socket->sd);
  }

  free(socket->recvbuf);
  return 0;
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  ssize_t bytes_sent, data_sent; /*bytes_sent is data+header*/
  microtcp_header_t header, ack_header;
  void *packet;

  if (socket == NULL)
    return -1;

  memset(&header, 0, sizeof(header));
  packet = malloc((length + sizeof(header)) * sizeof(char));

  initiliaze_default_header(&header, *socket, length);
  header.ack_number = socket->ack_number + 1;

  memcpy(packet, &header, sizeof(header));
  memcpy((packet + sizeof(header)), buffer, length);
  header.checksum = crc32(packet, length + sizeof(header));
  convert_to_network_header(&header);
  memcpy(packet, &header, sizeof(header));

  while (1)
  {
    bytes_sent = sendto(socket->sd, packet, length + sizeof(header), flags, socket->address, socket->address_len);
    convert_to_local_header(&header);
    data_sent = bytes_sent - sizeof(header);

    if (bytes_sent == -1 || bytes_sent != length + sizeof(header) || data_sent != length)
    {
      //free(packet);
      continue;
    }

    microtcp_raw_recv(socket, &ack_header, sizeof(ack_header), MSG_WAITALL);
    convert_to_local_header(&ack_header);

    if (ack_header.ack_number == socket->seq_number + length)
    {
      //not duplicate ack
      socket->seq_number += length;
      socket->ack_number = ack_header.seq_number;
      break;
    }
    //else duplicate ack
  }

  if (DEBUG_DATA)
  {
    printf("Sent and recieved:\n");
    print_header(header);
    print_header(ack_header);
  }

  free(packet);
  return data_sent;
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  ssize_t bytes_recieved, data_size;
  microtcp_header_t header, ack_header;
  void *packet;

  if (socket == NULL)
    return -1;

  memset(&header, 0, sizeof(header));
  packet = malloc((length + sizeof(header)) * sizeof(char));

  while (1)
  {
    bytes_recieved = recvfrom(socket->sd, packet, length + sizeof(header), flags, (socket->address), &socket->address_len);
    /*Generic error check*/
    if (bytes_recieved == -1)
    {
      free(packet);
      return -1;
    }

    data_size = bytes_recieved - sizeof(header);
    memcpy(&header, packet, sizeof(header));
    memcpy(buffer, packet + (sizeof(header) * sizeof(char)), data_size);
    convert_to_local_header(&header);

    if (socket->ack_number == header.seq_number && validate_checksum(&header, packet, bytes_recieved))
    {
      if (get_bit(header.control, 0) && get_bit(header.control, 3))
      {
        socket->state = CLOSING_BY_PEER;
        socket->seq_number = header.ack_number;
        socket->ack_number += 1;

        memset(&ack_header, 0, sizeof(header));
        ack_header.seq_number = socket->seq_number;
        ack_header.ack_number = socket->ack_number;
        ack_header.control = set_control_bits(1, 0, 0, 0);
        ack_header.checksum = crc32(&ack_header, sizeof(microtcp_header_t));

        convert_to_network_header(&ack_header);
        microtcp_raw_send(socket, &ack_header, sizeof(header), 0);
        convert_to_local_header(&ack_header);

        if (DEBUG)
        {
          printf("Header 1:\n");
          print_header(header);
          printf("Header 2:\n");
          print_header(ack_header);
        }

        free(packet);
        return 0;
      }
      else
      {
        socket->seq_number = header.ack_number;
        socket->ack_number = header.seq_number + data_size;

        memset(&ack_header, 0, sizeof(header));
        ack_header.seq_number = socket->seq_number;
        ack_header.ack_number = socket->ack_number;
        ack_header.control = set_control_bits(1, 0, 0, 0);

        convert_to_network_header(&ack_header);
        microtcp_raw_send(socket, &ack_header, sizeof(header), 0);
        convert_to_local_header(&ack_header);

        memset(socket->recvbuf, 0, MICROTCP_RECVBUF_LEN);
        if (bytes_recieved <= MICROTCP_RECVBUF_LEN)
        {
          memcpy(socket->recvbuf, buffer, data_size);
          socket->buf_fill_level = data_size;
          socket->recvbuf[socket->buf_fill_level - 1] = '\0';
        }
      }

      break;
    }

    //send duplicate ack
    memset(&ack_header, 0, sizeof(header));
    ack_header.seq_number = socket->seq_number;
    ack_header.ack_number = socket->ack_number;
    ack_header.control = set_control_bits(1, 0, 0, 0);

    convert_to_network_header(&ack_header);
    microtcp_raw_send(socket, &ack_header, sizeof(header), 0);
    convert_to_local_header(&ack_header);
  }

  if (DEBUG_DATA)
  {
    printf("Recieved and sent:");
    print_header(header);
    print_header(ack_header);
  }

  free(packet);
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
