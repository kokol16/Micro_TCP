#include <unistd.h>
#include <stdlib.h>
#include "microtcp.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
/*For sockadrr*/
//#include "../utils/crc32.h"

/*TODO: 1)Set errno*/

microtcp_sock_t microtcp_socket(int domain, int type, int protocol)
{
  microtcp_sock_t new_socket;
  if ((new_socket.sd = socket(domain, type, protocol)) < 0)
  { /*check type*/
    perror("Socket Failed.");
    exit(EXIT_FAILURE);
  }
  new_socket.state = CREATED;
  return new_socket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  int ret_val = bind(socket->sd, address, address_len);
  return ret_val;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  socket->address =(struct sockaddr *)  address;
  socket->address_len = address_len;

  microtcp_header_t *header_ptr;

  //first packet
  microtcp_header_t header_1;
  memset(&header_1, 0, sizeof(header_1));
  header_1.seq_number = getRandomInt();
  header_1.control = setControlBits(0, 0, 1, 0);
  //remember error check
  header_ptr = &header_1;
  microtcp_send(socket, header_ptr, sizeof(header_1), 0);

  //second
  microtcp_header_t header_2;
  header_ptr = &header_2;
  microtcp_recv(socket, header_ptr, sizeof(header_2), MSG_WAITALL);

  microtcp_header_t header_3;
  memset(&header_3, 0, sizeof(header_3));
  header_3.seq_number = header_1.seq_number + 1;
  header_3.ack_number = header_2.ack_number + 1;
  header_3.control = setControlBits(1, 0, 0, 0);
  header_ptr = &header_3;
  microtcp_send(socket, header_ptr, sizeof(header_3), 0);


  return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
  socket->address = address;
  socket->address_len = address_len;

  return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  return 0;
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  ssize_t bytes_sent = sendto(socket->sd, buffer, length, flags, (socket->address), socket->address_len);
  if (bytes_sent == length)
  {
    //set errno
  }
  return bytes_sent;
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  ssize_t bytes_recieved = recvfrom(socket->sd, buffer, length, flags, (socket->address), &socket->address_len);
  if (bytes_recieved == length)
  {
    //set errno
  }
  return bytes_recieved;
}

int getRandomInt()
{
  srand(time(NULL)); // Initialization, should only be called once.
  return rand();     // Returns a pseudo-random integer between 0 and RAND_MAX
}

uint16_t setControlBits(int ACK, int RST, int SYN, int FIN)
{
  uint16_t control;
  int ack = 12, rst = 13, syn = 14, fin = 15;
  control = control | ack << ACK;
  control = control | rst << RST;
  control = control | syn << SYN;
  control = control | fin << FIN;
  return control;
}
