#include <stdint.h>
#include <string.h>
#include "../include/pzmac.h"

static void arrXOR(uint8_t *out, const uint8_t *right, const uint16_t len){
    for(uint8_t i = 0; i<len; ++i){
        out[i] ^= right[i];
    }
}

/**** PMAC1 only in 256 bit ****/
void PMAC1_256_skinny(const uint8_t key[16], uint8_t out[16], const uint8_t *message, const uint32_t mlen){
    uint8_t tweak[PZMAC_256_T_SIZE + 1], buffer[PZMAC_256_N_SIZE], last_msg[PZMAC_256_N_SIZE];
    uint8_t res = mlen%PZMAC_256_N_SIZE;
    uint8_t res_flag = (res) ? 1:0;
    uint16_t numP_complete = (uint16_t)(mlen/PZMAC_256_N_SIZE) - 1 + res_flag;
    skinny_128_256_tweakey_schedule_t tks1, tks2;
    
    // Normal rounds have tweak ending in 2 - last round different
    memset(tweak, 0, PZMAC_256_T_SIZE + 1);
    memset(out, 0, PZMAC_256_N_SIZE);
    tweak[15] = 0x02;
    skinny_128_256_init_tk1(&tks1, key, SKINNY_128_256_ROUNDS);

    for(uint16_t i = 0; i<numP_complete; ++i){
        tweak[13] = (uint8_t)     (i+1);
        tweak[14] = (uint8_t)((i+1)>>8);
        skinny_128_256_init_tk2(&tks2, tweak, SKINNY_128_256_ROUNDS);
        skinny_128_256_encrypt_with_tks(&tks1, &tks2, buffer, message + i*PZMAC_256_N_SIZE);
        arrXOR(out, buffer, PZMAC_256_N_SIZE);
    }
    
    /** Last Block **/        
    memset(last_msg, 0 , PZMAC_256_N_SIZE);
    last_msg[res] = (1<<7);
    memcpy(last_msg, message + numP_complete*PZMAC_256_N_SIZE, PZMAC_256_N_SIZE*(1-res_flag) + res);
    tweak[13] = (uint8_t)     (numP_complete+1);
    tweak[14] = (uint8_t)((numP_complete+1)>>8);
    tweak[15] = 0x03 + res_flag;
    arrXOR(last_msg, out, PZMAC_256_N_SIZE);
    skinny_128_256_init_tk2(&tks2, tweak, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(&tks1, &tks2, out, last_msg);
}

