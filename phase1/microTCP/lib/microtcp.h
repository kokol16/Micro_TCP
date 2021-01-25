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
 * @file microtcp.h
 * @author Manos Chatzakis (chatzakis@ics.forth.com)
 * @author George Kokolakis (gkokol@ics.forth.com)
 * @brief MicroTCP header file
 * @version 0.1
 * @date 2020-11-26
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#ifndef LIB_MICROTCP_H_
#define LIB_MICROTCP_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*
 * Several useful constants
 */
#define MICROTCP_ACK_TIMEOUT_US 200000
#define MICROTCP_MSS 1400
#define MICROTCP_RECVBUF_LEN 8192
#define MICROTCP_WIN_SIZE MICROTCP_RECVBUF_LEN
#define MICROTCP_INIT_CWND (3 * MICROTCP_MSS)
#define MICROTCP_INIT_SSTHRESH MICROTCP_WIN_SIZE

/**
 * Possible states of the microTCP socket
 *
 * NOTE: You can insert any other possible state
 * for your own convenience
 */
typedef enum
{
  CREATED,
  LISTEN,
  ESTABLISHED,
  CLOSING_BY_PEER,
  CLOSING_BY_HOST,
  CLOSED,
  INVALID
} mircotcp_state_t;

/**
 * This is the microTCP socket structure. It holds all the necessary
 * information of each microTCP socket.
 *
 * NOTE: Fill free to insert additional fields.
 */
typedef struct
{
  int sd;                 /**< The underline UDP socket descriptor */
  mircotcp_state_t state; /**< The state of the microTCP socket */
  size_t init_win_size;   /**< The window size negotiated at the 3-way handshake */
  size_t curr_win_size;   /**< The current window size */

  uint8_t *recvbuf;      /**< The *receive* buffer of the TCP
                                     connection. It is allocated during the connection establishment and
                                     is freed at the shutdown of the connection. This buffer is used
                                     to retrieve the data from the network. */
  size_t buf_fill_level; /**< Amount of data in the buffer */

  size_t cwnd;
  size_t ssthresh;

  /*Modified the types to be compatible with header struct*/
  uint32_t seq_number; /**< Keep the state of the sequence number */
  uint32_t ack_number; /**< Keep the state of the ack number */

  /*Added information for socket address*/
  struct sockaddr *address;
  socklen_t address_len;

  uint64_t packets_send;
  uint64_t packets_received;
  uint64_t packets_lost;
  uint64_t bytes_send;
  uint64_t bytes_received;
  uint64_t bytes_lost;
} microtcp_sock_t;

/**
 * microTCP header structure
 * NOTE: DO NOT CHANGE!
 */
typedef struct
{
  uint32_t seq_number;  /**< Sequence number */
  uint32_t ack_number;  /**< ACK number */
  uint16_t control;     /**< Control bits (e.g. SYN, ACK, FIN) */
  uint16_t window;      /**< Window size in bytes */
  uint32_t data_len;    /**< Data length in bytes (EXCLUDING header) */
  uint32_t future_use0; /**< 32-bits for future use */
  uint32_t future_use1; /**< 32-bits for future use */
  uint32_t future_use2; /**< 32-bits for future use */
  uint32_t checksum;    /**< CRC-32 checksum, see crc32() in utils folder */
} microtcp_header_t;

typedef struct
{
  microtcp_header_t header;
  void *data;
} microtcp_packet_t;

/**
 * @brief Returns a new microTCP socket.
 * NOTE: Domain, Type, Protocol are set inside to support UDP.
 * STATUS: Ready
 * @param domain  
 * @param type 
 * @param protocol 
 * @return microtcp_sock_t 
 */
microtcp_sock_t
microtcp_socket(int domain, int type, int protocol);

/**
 * @brief Binds a microtcp socket to a specific address.
 * STATUS: Ready
 * @param socket 
 * @param address 
 * @param address_len 
 * @return int 0 on success, -1 on failure.
 */
int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len);

/**
 * @brief Begins the connection among a server and a client.
 * Implements the client side functionality for the handshake.
 * STATUS: Error checking to be added. (Phase 2)
 * @param socket 
 * @param address 
 * @param address_len 
 * @return int 0 on success, -1 on failure
 */
int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len);

/**
 * Blocks waiting for a new connection from a remote peer.
 * STATUS: Error checking to be added. (Phase 2) - ONGOING
 * @param socket the socket structure
 * @param address pointer to store the address information of the connected peer
 * @param address_len the length of the address structure.
 * @return ATTENTION despite the original accept() this function returns
 * 0 on success or -1 on failure
 */
int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len);

/**
 * @brief Ends the connection between a client and a host.
 * WARNING: Client side should always start the connection finalization.
 * NOTE: Despite the classic shutdown, this function also closes the UPD socket descriptor.
 * STATUS: Error checking to be added. (Phase 2) - ONGOING
 * @param socket 
 * @param how 
 * @return int 0 on success, -1 on failure.
 */
int microtcp_shutdown(microtcp_sock_t *socket, int how);

/**
 * @brief Sends the buffer to the address of socket.
 * NOTE: As this send corresponds to microTCP protocol mechanisms, 
 * it sends the concatenation of the microTCP header and the buffer to the reciever. 
 * STATUS: 1) Error checking to be updates.
 *         2) Socket Values to be updated.
 *         3) Add ACK awaiting packets.
 *         (Phase 2) - ONGOING
 * @param socket 
 * @param buffer 
 * @param length 
 * @param flags 
 * @return ssize_t The data bytes that were sent. WARNING: This value could return negative, and
 * you should always check its value before procceding. Be careful using this one.
 */
ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,
              int flags);

/**
 * @brief Recieves the data sent from another host.
 * STATUS: 1) Error checking to be updates.
 *         2) Socket Values to be updated.
 *         3) Add ACK awaiting packets.
 *         (Phase 2) - ONGOING
 * @param socket 
 * @param buffer 
 * @param length 
 * @param flags 
 * @return ssize_t The data bytes read and put into the buffer. WARNING: This could return negative uppon errors,
 * thus you should always check this value. 
 */
ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags);

ssize_t
microtcp_raw_send(microtcp_sock_t *socket, const void *buffer, size_t length,
                  int flags);

ssize_t
microtcp_raw_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                  int flags);

void print_server_statistics(microtcp_sock_t socket);

void print_client_statistics(microtcp_sock_t socket);

int DEBUG = 1;
int DEBUG_DATA = 1;
int DEBUG_TCP_FLOW = 1;

#endif /* LIB_MICROTCP_H_ */
