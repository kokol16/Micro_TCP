/**
 * @file common.h
 * @author Manos Chatzakis (chatzakis@ics.forth.gr)
 * @author George Kokolakis (gkokol@ics.forth.gr)
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

#include "../utils/crc32.h"

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
int get_bit(int number, int pos)
{
    return (number >> pos) & 1;
}

/**
 * @brief Returns a random int in range [min,max]
 * 
 * @param min 
 * @param max 
 * @return int 
 */
int get_random_int(int min, int max)
{
    srand(time(NULL));
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
    printf("    Sequence number: %d\n", header.seq_number);
    printf("    Acknowledgement number: %d\n", header.ack_number);
    printf("    Checksum: %x\n", header.checksum);
    printf("    Data length: %d\n", header.data_len);
    printf("    Window size: %d\n", header.window);
    printf("    Control bits:\n");
    printf("        ACK: %d\n", get_bit(control, ack));
    printf("        RST: %d\n", get_bit(control, rst));
    printf("        SYN: %d\n", get_bit(control, syn));
    printf("        FIN: %d\n", get_bit(control, fin));
}

/**
 * @brief 
 * 
 * @param header 
 * @param socket 
 * @param length 
 */
void initiliaze_default_header(microtcp_header_t *header, microtcp_sock_t socket, int length)
{
    header->ack_number = socket.ack_number;
    header->seq_number = socket.seq_number;
    header->data_len = length;
    header->control = set_control_bits(1, 0, 0, 0);
    header->checksum = 0;
    header->window = socket.curr_win_size;
}

int skip_ack(){
    
    int ret;
    ret = get_random_int(0,3);
    if(ret>=1){
        return 0;
    }
    else{
        return 1;
    }

}

/**
 * @brief Converts a local header to network header
 * 
 * @param  
 */
microtcp_header_t set_outgoing_header(microtcp_header_t local_header)
{
    microtcp_header_t header;

    header.ack_number = htonl(local_header.ack_number);
    header.seq_number = htonl(local_header.seq_number);
    header.data_len = htonl(local_header.data_len);
    header.checksum = htonl(local_header.checksum);

    header.window = htons(local_header.window);
    header.control = htons(local_header.control);

    return header;
}

/**
 * @brief Converts a local header to network header
 * 
 * @param  
 */
void convert_to_network_header(microtcp_header_t *header)
{
    header->ack_number = htonl(header->ack_number);
    header->seq_number = htonl(header->seq_number);
    header->data_len = htonl(header->data_len);
    header->checksum = htonl(header->checksum);
    header->window = htons(header->window);
    header->control = htons(header->control);
}

/**
 * @brief Converts a network header to local
 * 
 * @param  
 */
void convert_to_local_header(microtcp_header_t *header)
{
    header->ack_number = ntohl(header->ack_number);
    header->seq_number = ntohl(header->seq_number);
    header->data_len = ntohl(header->data_len);
    header->checksum = ntohl(header->checksum);

    header->control = ntohs(header->control);
    header->window = ntohs(header->window);
}

int sleep_random_time(){
    int seconds = get_random_int(0,MICROTCP_ACK_TIMEOUT_US);
    return usleep(seconds);
}

/**
 * 
 * flag is to check seq num or not 
 */
int validate_header(microtcp_header_t *header, int seq, int flag)
{
    long long int curr,old_checksum = (long long int)header->checksum;
    header->checksum = 0;
    curr = (long long int) crc32(header, sizeof(microtcp_header_t));
    return (old_checksum == curr) && (flag || seq == header->ack_number - 1);
}

int validate_checksum(microtcp_header_t *header, void *packet, size_t length)
{
    long long int curr, old_checksum = (long long int)header->checksum;
    header->checksum = 0;
    memcpy(packet, header, sizeof(microtcp_header_t));
    curr = (long long int)old_checksum, crc32(packet, length);
    return old_checksum == curr;
}

size_t min(size_t a, size_t b, size_t c)
{
    if (a < b && a < c)
    {
        return a;
    }
    else if (b < c)
    {
        return b;
    }

    return c;
}
