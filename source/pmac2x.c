#include <stdint.h>
#include <string.h>
#include "../include/pzmac.h"

static void arrXOR(uint8_t *out, const uint8_t *right, const uint16_t len){
    for(uint8_t i = 0; i<len; ++i){
        out[i] ^= right[i];
    }
}

/* Double Function in GF(2^128) */
static void arrDOUBLE_128(uint8_t out[16]){
    uint8_t tmp;
    
    tmp = (out[15] >> 7) & 1;
    for (uint8_t i = 0;  i < 15;  ++i){
        out[i] = (out[i] << 1) | ((out[i+1] >> 7) & 1);
    }
    out[15] = out[15] << 1;
    out[0] ^= 0x87 * tmp;
}

/* Double Function in GF(2^64) */
static void arrDOUBLE_64(uint8_t out[8]){
    uint8_t tmp;
    
    tmp = (out[7] >> 7) & 1;
    for (uint8_t i = 0;  i < 7;  ++i){
        out[i] = (out[i] << 1) | ((out[i+1] >> 7) & 1);
    }
    out[7] = out[7] << 1;
    out[0] ^= 0x1b * tmp;
}

void PMAC2x_256_skinny(const uint8_t key[16], uint8_t out_left[16], uint8_t out_right[16], const uint8_t *message, const uint32_t mlen){
    uint8_t res, res_flag;
    uint16_t numP_complete;
    Pmac2xStruct Pmac2x;
    MacChains Chains;

    res = mlen%PZMAC_256_N_SIZE;
    res_flag = (res) ? 1:0;
    numP_complete = (uint16_t)(mlen/PZMAC_256_N_SIZE) - 1 + res_flag;

    skinny_128_256_tweakey_schedule_t tks1, tks2;
    Pmac2x.tks1.tks128 = &tks1;
    Pmac2x.tks2.tks128 = &tks2;
    skinny_128_256_init_tk1(Pmac2x.tks1.tks128, key, SKINNY_128_256_ROUNDS);

    memset(Pmac2x.tweak,0, PZMAC_256_T_SIZE  + 1);
    memset(Pmac2x.out, 0, PZMAC_256_N_SIZE * 2);
    memset(Chains.u, 0, PZMAC_256_N_SIZE);
    memset(Chains.v, 0, PZMAC_256_T_SIZE + 1);

    for(uint16_t i = 0; i<numP_complete; ++i){
        //PHASH2x
        Pmac2x.tweak[1] = (uint8_t)(i+1);
        Pmac2x.tweak[2] = (uint8_t)(i+1) >> 8;
        skinny_128_256_init_tk2(Pmac2x.tks2.tks128, Pmac2x.tweak, SKINNY_128_256_ROUNDS);
        skinny_128_256_encrypt_with_tks(Pmac2x.tks1.tks128, Pmac2x.tks2.tks128, Pmac2x.out, message + PZMAC_256_N_SIZE*i);

        arrXOR(Chains.u, Pmac2x.out, PZMAC_256_N_SIZE);
        arrXOR(Chains.v, Pmac2x.out, PZMAC_256_N_SIZE);
        arrDOUBLE_128(Chains.v);
    }

    /* Last Round */
    memset(Pmac2x.message, 0, PZMAC_256_N_SIZE);
    Pmac2x.message[res] ^= (1<<7);
    memcpy(Pmac2x.message, message + PZMAC_256_N_SIZE*numP_complete, PZMAC_256_N_SIZE*(1-res_flag) + res);

    //PHASH2x
    Pmac2x.tweak[1] = (uint8_t)(numP_complete+1);
    Pmac2x.tweak[2] = (uint8_t)(numP_complete+1) >> 8;
    skinny_128_256_init_tk2(Pmac2x.tks2.tks128, Pmac2x.tweak, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(Pmac2x.tks1.tks128, Pmac2x.tks2.tks128, Pmac2x.out, Pmac2x.message);
    arrXOR(Chains.u, Pmac2x.out, PZMAC_256_N_SIZE);
    arrXOR(Chains.v, Pmac2x.out, PZMAC_256_N_SIZE);
    arrDOUBLE_128(Chains.v);

    //PFIN2x
    uint8_t tmp[PZMAC_256_T_SIZE + 1];
    // U
    tmp[0] = 0x02;
    memcpy(tmp + 1, Chains.v, PZMAC_256_T_SIZE);
    skinny_128_256_init_tk2(Pmac2x.tks2.tks128, tmp, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(Pmac2x.tks1.tks128, Pmac2x.tks2.tks128, Pmac2x.out, Chains.u);
    // V
    tmp[0] = 0x03;
    memcpy(tmp + 1, Chains.u, PZMAC_256_T_SIZE);
    skinny_128_256_init_tk2(Pmac2x.tks2.tks128, tmp, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(Pmac2x.tks1.tks128, Pmac2x.tks2.tks128, Pmac2x.out + PZMAC_256_N_SIZE, Chains.v);

    memcpy(out_left , Pmac2x.out                   , PZMAC_256_N_SIZE);
    memcpy(out_right, Pmac2x.out + PZMAC_256_N_SIZE, PZMAC_256_N_SIZE);
}

void PMAC2x_192_skinny(const uint8_t key[16], uint8_t out_left[8], uint8_t out_right[8], const uint8_t *message, const uint32_t mlen){
    uint8_t res, res_flag;
    uint16_t numP_complete;
    Pmac2xStruct Pmac2x;
    MacChains Chains;

    res = mlen%PZMAC_192_N_SIZE;
    res_flag = (res) ? 1:0;
    numP_complete = (uint16_t)(mlen/PZMAC_192_N_SIZE) - 1 + res_flag;

    skinny_64_192_tweakey_schedule_t tks1, tks2;
    Pmac2x.tks1.tks64 = &tks1;
    Pmac2x.tks2.tks64 = &tks2;
    skinny_64_192_init_keypart(Pmac2x.tks1.tks64, key, SKINNY_64_192_ROUNDS);

    memset(Pmac2x.tweak,0, PZMAC_192_T_SIZE  + 1);
    memset(Pmac2x.out, 0, PZMAC_192_N_SIZE * 2);
    memset(Chains.u, 0, PZMAC_192_N_SIZE);
    memset(Chains.v, 0, PZMAC_192_T_SIZE + 1);

    for(uint16_t i = 0; i<numP_complete; ++i){
        //PHASH2x
        Pmac2x.tweak[1] = (uint8_t)(i+1);
        Pmac2x.tweak[2] = (uint8_t)(i+1) >> 8;
        skinny_64_192_init_tweakpart(Pmac2x.tks2.tks64, Pmac2x.tweak, SKINNY_64_192_ROUNDS);
        skinny_64_192_encrypt_with_tks(Pmac2x.tks1.tks64, Pmac2x.tks2.tks64, Pmac2x.out, message + PZMAC_192_N_SIZE*i);

        arrXOR(Chains.u, Pmac2x.out, PZMAC_192_N_SIZE);
        arrXOR(Chains.v, Pmac2x.out, PZMAC_192_N_SIZE);
        arrDOUBLE_64(Chains.v);
    }

    /* Last Round */
    memset(Pmac2x.message, 0, PZMAC_192_N_SIZE);
    Pmac2x.message[res] ^= (1<<7);
    memcpy(Pmac2x.message, message + PZMAC_192_N_SIZE*numP_complete, PZMAC_192_N_SIZE*(1-res_flag) + res);

    //PHASH2x
    Pmac2x.tweak[1] = (uint8_t)(numP_complete+1);
    Pmac2x.tweak[2] = (uint8_t)(numP_complete+1) >> 8;
    skinny_64_192_init_tweakpart(Pmac2x.tks2.tks64, Pmac2x.tweak, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(Pmac2x.tks1.tks64, Pmac2x.tks2.tks64, Pmac2x.out, Pmac2x.message);
    arrXOR(Chains.u, Pmac2x.out, PZMAC_192_N_SIZE);
    arrXOR(Chains.v, Pmac2x.out, PZMAC_192_N_SIZE);
    arrDOUBLE_64(Chains.v);

    //PFIN2x
    uint8_t tmp[PZMAC_192_T_SIZE + 1];
    // U
    tmp[0] = 0x02;
    memcpy(tmp + 1, Chains.v, PZMAC_192_T_SIZE);
    skinny_64_192_init_tweakpart(Pmac2x.tks2.tks64, tmp, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(Pmac2x.tks1.tks64, Pmac2x.tks2.tks64, Pmac2x.out, Chains.u);
    // V
    tmp[0] = 0x03;
    memcpy(tmp + 1, Chains.u, PZMAC_192_T_SIZE);
    skinny_64_192_init_tweakpart(Pmac2x.tks2.tks64, tmp, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(Pmac2x.tks1.tks64, Pmac2x.tks2.tks64, Pmac2x.out + PZMAC_192_N_SIZE, Chains.v);

    memcpy(out_left , Pmac2x.out                   , PZMAC_192_N_SIZE);
    memcpy(out_right, Pmac2x.out + PZMAC_192_N_SIZE, PZMAC_192_N_SIZE);
}
