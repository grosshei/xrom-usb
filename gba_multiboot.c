#include "gba_multiboot.h"

// uint32_t encode_payload_uint(uint32_t local_34, uint32_t cur_pos, uint32_t input){
//     uint32_t local_3c = ~(cur_pos + 0x2000000) + 1 ^ 0x6465646f;
//     return input ^ local_34 ^ local_3c;
// }

uint32_t encode_payload_uint(uint32_t key, uint32_t cur_pos, uint32_t input){
    uint32_t k = 0x6465646F;
    uint32_t basis = 0xFE000000;
    return key ^ input ^ (basis - cur_pos) ^ k;
}

// uint32_t setup_key(uint32_t key){
//     //key setup
//     uint32_t local_10 = key;
//     uint32_t local_58 = 0xc1;
//     uint32_t local_34 = (local_10 & 0xff) * 0x100 + -0x10000 + local_58;
//     return local_34;
// }

// uint32_t setup_key(uint32_t key){
//     uint32_t seed = 0xFFFF00D1 | (key << 8);
//     return seed;
// }

uint32_t setup_key(uint32_t key){
    uint32_t seed = 0xffff00c1 | ((key & 0xff) << 8);
    return seed;
}

uint32_t next_key(uint32_t key){
    return key * 0x6f646573 + 1;
}

uint32_t data_to_int(unsigned char *input){
    uint32_t intput = 0;
    intput += ((uint32_t)input[3] << 24);
    intput += ((uint32_t)input[2] << 16);
    intput += ((uint32_t)input[1] << 8);
    intput += ((uint32_t)input[0] << 0);
    return intput;
}

void encode_payload_4bytes(uint32_t key, size_t cur_pos, unsigned char *input, unsigned char **output){

    uint32_t intput = data_to_int(input);

    // printf("INTput = %#x\n", intput);

    uint32_t intcoded = encode_payload_uint(key, (uint32_t)cur_pos, intput);

    // printf("INTOUTPUT: %#x\n", intcoded);

    unsigned char *out = calloc(4, sizeof(unsigned char));
    out[0] = (intcoded & 0x000000ff) >> 0;
    out[1] = (intcoded & 0x0000ff00) >> 8;
    out[2] = (intcoded & 0x00ff0000) >> 16;
    out[3] = (intcoded & 0xff000000) >> 24;

    *output = out;
    return;
}

uint32_t crc_step(uint32_t crc, uint32_t value) {
    for(int i = 0; i < 32; i++){
        uint32_t var_30 = crc ^ value;
		crc = crc >> 1;
		value = value >> 1;
		if (var_30 & 0x01){
            crc = crc ^ CRC_MAGIC_2;
        }
    }
    return crc;
}