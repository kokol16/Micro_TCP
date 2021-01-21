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

#define DEBUG 0
#define DEBUG_DATA 0

/*
1) flow window  = 0
2) test retrans
3) code cleanup
4) test bandwidth
5) check ack/seq evaluations
*/

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

  socket->cwnd = MICROTCP_INIT_CWND;
  socket->ssthresh = MICROTCP_INIT_SSTHRESH;

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

  socket->cwnd = MICROTCP_INIT_CWND;
  socket->ssthresh = MICROTCP_INIT_SSTHRESH;

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
      printf("Header 1 ???:\n");
      print_header(header_1);
    }

    microtcp_raw_recv(socket, &header_2, sizeof(header_2), MSG_WAITALL);
    convert_to_local_header(&header_2);

    if (DEBUG)
    {
      printf("Header 2 ???:\n");
      print_header(header_2);
    }

    if (!validate_header(&header_2, header_1.seq_number, 0))
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
  ssize_t bytes_sent, data_sent, recv, bytes_to_sent, total_bytes_sent = 0; /*bytes_sent is data+header*/
  size_t rem, chunk_size, remaining_bytes, flow_control = socket->init_win_size, total_length = length + sizeof(microtcp_header_t);

  int chunks, i, duplicate_counter = 0, ret_chunk = 0, ret_ack = 0, isTripleDuplicate = 0, isTimeout = 0;

  microtcp_header_t header, ack_header;

  void *packet;
  struct timeval timeout;

  if (socket == NULL)
    return -1;

  /*MSS does not contain the header size*/
  packet = malloc((MICROTCP_MSS + sizeof(microtcp_header_t)) * sizeof(char));

  remaining_bytes = length;
  while (total_bytes_sent < length)
  {

    duplicate_counter = 0;
    bytes_to_sent = min(remaining_bytes, flow_control, socket->cwnd);
    chunks = bytes_to_sent / MICROTCP_MSS; /*how many segments*/
    printf("======================\n");
    printf("Remaining Bytes: %d\nFlow Control Window: %d\nCongestion Control Window: %d\n", remaining_bytes, flow_control, socket->cwnd);
    printf("Transmission round: Bytes to sent = %d\n", bytes_to_sent);

    for (i = 0; i < chunks; i++)
    {
      memset(&header, 0, sizeof(header));
      initiliaze_default_header(&header, *socket, MICROTCP_MSS);

      header.ack_number = socket->ack_number + 1 + i;
      header.seq_number = socket->seq_number + (i * MICROTCP_MSS);

      memcpy(packet, &header, sizeof(microtcp_header_t));
      memcpy((packet + sizeof(microtcp_header_t)), (buffer + (i * MICROTCP_MSS) * sizeof(char)), MICROTCP_MSS); //check again

      header.checksum = crc32(packet, MICROTCP_MSS + sizeof(header));

      convert_to_network_header(&header);
      memcpy(packet, &header, sizeof(header));
      sendto(socket->sd, packet, MICROTCP_MSS + sizeof(header), flags, socket->address, socket->address_len);
      convert_to_local_header(&header);

      if (DEBUG_DATA)
      {
        printf("Send: Header sent:\n");
        print_header(header);
      }
    }

    rem = bytes_to_sent % MICROTCP_MSS;
    /*rem = remaining bytes*/
    if (rem > 0)
    {
      memset(&header, 0, sizeof(header));
      initiliaze_default_header(&header, *socket, rem);

      header.ack_number = socket->ack_number + 1 + chunks;
      header.seq_number = socket->seq_number + (MICROTCP_MSS * chunks);

      memcpy(packet, &header, sizeof(microtcp_header_t));
      memcpy((packet + sizeof(microtcp_header_t)), (buffer + (MICROTCP_MSS * chunks) * sizeof(char)), rem); //check again

      header.checksum = crc32(packet, MICROTCP_MSS + sizeof(header));
      convert_to_network_header(&header);
      memcpy(packet, &header, sizeof(header));

      sendto(socket->sd, packet, rem + sizeof(header), flags, socket->address, socket->address_len);
      convert_to_local_header(&header);
      chunks++;

      if (DEBUG_DATA)
      {
        printf("Send: Header sent:\n");
        print_header(header);
      }
    }

    timeout.tv_sec = 0;
    timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

    for (i = 0; i < chunks; i++)
    {

      if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
      {
        perror("setsockopt");
      }

      recv = microtcp_raw_recv(socket, &ack_header, sizeof(ack_header), MSG_WAITALL);
      convert_to_local_header(&ack_header);

      chunk_size = MICROTCP_MSS;

      if (i + 1 == chunks)
      {
        chunk_size = rem;
      }

      if (recv < 0)
      {
        printf("Timeout!\n");
        isTimeout = 1;
        break;
      }

      if (ack_header.ack_number <= socket->seq_number + (i * chunk_size))
      {
        printf("Duplicate ACK!\n");

        if (ack_header.ack_number > ret_ack)
        {
          duplicate_counter = 0;
        }

        duplicate_counter++;

        if (duplicate_counter == 1)
        {
          ret_ack = ack_header.ack_number;
          ret_chunk = i;
        }

        if (duplicate_counter == 3)
        {
          isTripleDuplicate = 1;
          break;
        }
      }

      if (DEBUG_DATA)
      {
        printf("Send: Header recieved (ACK):\n");
        print_header(ack_header);
      }
    }

    flow_control = ack_header.window;
    socket->curr_win_size = flow_control;

    if (isTripleDuplicate)
    {
      printf("TRIPLE DUP OCCURED!!\n");
      socket->ssthresh = socket->cwnd / 2;
      socket->cwnd = socket->cwnd / 2 + 1;
      isTripleDuplicate = 0;
      continue;
    }

    if (isTimeout)
    {
      printf("TIMEOUT OCCURED!!\n");
      socket->ssthresh = socket->cwnd / 2;
      socket->cwnd = min(MICROTCP_MSS, socket->ssthresh, socket->ssthresh + MICROTCP_MSS);
      isTimeout = 0;
      printf("New ssthresh: %d\nNew cwnd: %d\n",socket->ssthresh, socket->cwnd);
      continue;
    }

    if (socket->cwnd <= socket->ssthresh)
    {
      printf("Slow Start Phase\n");
      socket->cwnd *= 2; //check again
    }
    else
    {
      printf("Congestion Avoidance Phase\n");
      socket->cwnd += MICROTCP_MSS;
    }

    remaining_bytes -= bytes_to_sent;
    total_bytes_sent += bytes_to_sent;

    socket->seq_number += bytes_to_sent;
    socket->ack_number = ack_header.seq_number + 1;
  }

  free(packet);
  return total_bytes_sent;
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  ssize_t bytes_recieved, data_size, rem_size;
  microtcp_header_t header, ack_header;
  void *packet;

  if (socket == NULL)
    return -1;

  memset(&header, 0, sizeof(header));
  packet = malloc((MICROTCP_MSS + sizeof(header)) * sizeof(char));

  bytes_recieved = recvfrom(socket->sd, packet, MICROTCP_MSS + sizeof(header), flags, (socket->address), &socket->address_len);

  /*Generic error check*/
  if (bytes_recieved == -1)
  {
    free(packet);
    printf("KOKOLAKI EISAI ILITHIOS\n");
    return -1;
  }

  data_size = bytes_recieved - sizeof(header);
  memcpy(&header, packet, sizeof(header));
  //memcpy(buffer, packet + (sizeof(header) * sizeof(char)), data_size);
  convert_to_local_header(&header);

  //sleep(1);

  if (socket->ack_number == header.seq_number && validate_checksum(&header, packet, bytes_recieved))
  {
    if (get_bit(header.control, 0) && get_bit(header.control, 3))
    {

      printf("O manos einai omorfos\n");

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

      //printf("before..\n");

      if (DEBUG)
      {
        printf("Header 1 LALA:\n");
        print_header(header);
        printf("Header 2:\n");
        print_header(ack_header);
      }

      printf("exiting...\n");
      free(packet);
      return 0;
    }
    else
    {
      data_size = header.data_len;

      if (socket->buf_fill_level + data_size < MICROTCP_RECVBUF_LEN)
      {
        memcpy((socket->recvbuf + socket->buf_fill_level), (packet + sizeof(microtcp_header_t)), data_size);
        socket->buf_fill_level += data_size;
        rem_size = MICROTCP_RECVBUF_LEN - socket->buf_fill_level;
      }
      else
      {
        rem_size = 0;
      }

      socket->seq_number = header.ack_number; //sdhfiueqwgrgpigpqe9gqehvgpqe
      socket->ack_number = header.seq_number + data_size;

      memset(&ack_header, 0, sizeof(header));
      ack_header.seq_number = socket->seq_number;
      ack_header.ack_number = socket->ack_number;
      ack_header.window = rem_size;
      ack_header.control = set_control_bits(1, 0, 0, 0);

      convert_to_network_header(&ack_header);
      microtcp_raw_send(socket, &ack_header, sizeof(header), 0);
      convert_to_local_header(&ack_header);

      memcpy(buffer, socket->recvbuf, socket->buf_fill_level);
      memset(socket->recvbuf, 0, socket->buf_fill_level);
      socket->buf_fill_level = 0;

      if (DEBUG_DATA)
      {
        printf("Recieve: Header recieved:\n");
        print_header(header);

        printf("Recieve: Header sent (ACK):\n");
        print_header(ack_header);
      }
    }
  }
  else
  {
    //send duplicate ack
    memset(&ack_header, 0, sizeof(header));
    ack_header.seq_number = socket->seq_number;
    ack_header.ack_number = socket->ack_number;
    ack_header.control = set_control_bits(1, 0, 0, 0);

    printf("DUPLICATE ACK");

    convert_to_network_header(&ack_header);
    microtcp_raw_send(socket, &ack_header, sizeof(header), 0);
    convert_to_local_header(&ack_header);
  }

  /*if (DEBUG_DATA)
  {
    printf("Recieved and sent:");
    print_header(header);
    print_header(ack_header);
  }*/

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
