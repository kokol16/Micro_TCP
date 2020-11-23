 /**
 * @file common.h
 * @author Manos Chatzakis (chatzakis@ics.forth.gr)
 * @brief Some common functions needed to implement microtcp library.
 * @version 0.1
 * @date 2020-11-18
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#include "microtcp.h"

#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief Set the control bits of control field.
 * 
 * @param ACK 
 * @param RST 
 * @param SYN 
 * @param FIN 
 * @return uint16_t 
 */
uint16_t set_control_bits(int ACK, int RST, int SYN, int FIN)
{
    uint16_t control = 0;
    int ack = 3, rst = 2, syn = 1, fin = 0;
    control = control | ACK << ack;
    control = control | RST << rst;
    control = control | SYN << syn;
    control = control | FIN << fin;
    return control;
}

/**
 * @brief Return the status of number's pos bit.
 * 
 * @param number 
 * @param pos 
 * @return int (0 or 1)
 */
int get_bit(int number,int pos){
    return (number >> pos) & 1;  //<< 
}

/**
 * @brief Returns a random int in range [min,max]
 * 
 * @param min 
 * @param max 
 * @return int 
 */
int get_random_int(int min,int max)
{
    srand(time(NULL)); // Initialization, should only be called once.
    return min + rand() % (max + 1 - min);
}

/**
 * @brief Prints the given header for debugging.
 * 
 * @param header 
 */
void print_header(microtcp_header_t header)
{
    int ack = 3, rst = 2, syn = 1, fin = 0, control = header.control;
    printf("Header fields are:\n");
    printf("Sequence number: %d\n",header.seq_number);
    printf("Acknowledgement number: %d\n",header.ack_number);
    printf("Checksum: %d\n",header.checksum);
    printf("Data length: %d\n",header.data_len);
    printf("Window size: %d\n",header.window);
    printf("Control bits:\n");
    printf("    ACK: %d\n",get_bit(control,ack));
    printf("    RST: %d\n",get_bit(control,rst));
    printf("    SYN: %d\n",get_bit(control,syn));
    printf("    FIN: %d\n",get_bit(control,fin));    
}

/**
 * @brief 
 * 
 * @param header 
 * @param socket 
 * @param length 
 */
void initiliaze_default_header(microtcp_header_t *header,microtcp_sock_t socket,int length){ 
  header->ack_number = socket.ack_number;
  header->seq_number = socket.seq_number;
  header->data_len   = length;
  header->control    = set_control_bits(1,0,0,0);
}



