#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#define CRC_MAGIC_1 0xFFF8
#define CRC_MAGIC_2 0xA517

// #define CRC_MAGIC_1 0xc387
// #define CRC_MAGIC_2 0xc37b

uint32_t encode_payload_uint(uint32_t local_34, uint32_t cur_pos, uint32_t input);
uint32_t setup_key(uint32_t key);
uint32_t next_key(uint32_t key);
uint32_t data_to_int(unsigned char *input);
void encode_payload_4bytes(uint32_t key, size_t cur_pos, unsigned char *input, unsigned char **output);
uint32_t crc_step(uint32_t crc, uint32_t value);
