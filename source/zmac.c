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

static void ZHASH_256(ZmacStruct *pZmac, MacChains *pChains){
    uint8_t tmp[PZMAC_256_T_SIZE], cmask[PZMAC_256_N_SIZE];
    memcpy(tmp, pZmac->P + PZMAC_256_N_SIZE, PZMAC_256_T_SIZE);
    
    arrXOR(pZmac->P, pZmac->mask_l, PZMAC_256_N_SIZE);
    arrXOR(pZmac->P + PZMAC_256_N_SIZE, pZmac->mask_r, PZMAC_256_T_SIZE);
    
    pZmac->P[PZMAC_256_N_SIZE+PZMAC_256_T_SIZE] = 0x08;
    skinny_128_256_init_tk2(pZmac->tks2.tks128, pZmac->P + PZMAC_256_N_SIZE, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(pZmac->tks1.tks128, pZmac->tks2.tks128, cmask, pZmac->P);

    arrXOR(pChains->u, cmask, PZMAC_256_N_SIZE);
    arrDOUBLE_128(pChains->u);

    arrXOR(tmp, cmask, PZMAC_256_T_SIZE);
    arrXOR(pChains->v, tmp, PZMAC_256_T_SIZE);

    arrDOUBLE_128(pZmac->mask_l);
    arrDOUBLE_128(pZmac->mask_r);
}

static void ZFIN_256(ZmacStruct *pZmac, uint8_t fin){
    uint8_t tmp[PZMAC_256_N_SIZE];
    // Y_1
    pZmac->P[PZMAC_256_N_SIZE+PZMAC_256_T_SIZE] = fin;
    skinny_128_256_init_tk2(pZmac->tks2.tks128, pZmac->P + PZMAC_256_N_SIZE, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(pZmac->tks1.tks128, pZmac->tks2.tks128, pZmac->out, pZmac->P);

    ++pZmac->P[PZMAC_256_N_SIZE+PZMAC_256_T_SIZE];
    skinny_128_256_init_tk2(pZmac->tks2.tks128, pZmac->P + PZMAC_256_N_SIZE, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(pZmac->tks1.tks128, pZmac->tks2.tks128, tmp, pZmac->P);
    arrXOR(pZmac->out, tmp, PZMAC_256_N_SIZE);

    // Y_2
    ++pZmac->P[PZMAC_256_N_SIZE+PZMAC_256_T_SIZE];
    skinny_128_256_init_tk2(pZmac->tks2.tks128, pZmac->P + PZMAC_256_N_SIZE, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(pZmac->tks1.tks128, pZmac->tks2.tks128, &pZmac->out[PZMAC_256_N_SIZE], pZmac->P);

    ++pZmac->P[PZMAC_256_N_SIZE+PZMAC_256_T_SIZE];
    skinny_128_256_init_tk2(pZmac->tks2.tks128, pZmac->P + PZMAC_256_N_SIZE, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(pZmac->tks1.tks128, pZmac->tks2.tks128, tmp, pZmac->P);
    arrXOR(pZmac->out + PZMAC_256_N_SIZE, tmp, PZMAC_256_N_SIZE);
}

void ZMAC_256_skinny(const uint8_t key[16], uint8_t out_left[16], uint8_t out_right[16], const uint8_t *message, const uint32_t mlen){
    uint8_t pbsize, res, res_flag, fin;
    uint16_t numP_complete;
    ZmacStruct Zmac;
    MacChains Chains;
    skinny_128_256_tweakey_schedule_t tks1, tks2;

    Zmac.tks1.tks128 = &tks1;
    Zmac.tks2.tks128 = &tks2;

    pbsize = PZMAC_256_N_SIZE+PZMAC_256_T_SIZE;
    res = mlen%pbsize;
    res_flag = (res) ? 1:0;
    numP_complete = (uint16_t)(mlen/pbsize) - 1 + res_flag;

    memset(Zmac.P, 0, PZMAC_256_P_SIZE + 1);
    memset(Chains.u, 0, PZMAC_256_N_SIZE);
    memset(Chains.v, 0, PZMAC_256_T_SIZE+1);

    Zmac.P[pbsize] = 0x09;
    skinny_128_256_init_tk1(Zmac.tks1.tks128, key, SKINNY_128_256_ROUNDS);
    skinny_128_256_init_tk2(Zmac.tks2.tks128, Zmac.P + PZMAC_256_N_SIZE, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(Zmac.tks1.tks128, Zmac.tks2.tks128, Zmac.mask_l, Zmac.P);

    Zmac.P[pbsize-1] = 0x01;
    skinny_128_256_init_tk2(Zmac.tks2.tks128, Zmac.P + PZMAC_256_N_SIZE, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(Zmac.tks1.tks128, Zmac.tks2.tks128, Zmac.mask_r, Zmac.P);


    for(uint16_t i = 0; i<numP_complete; ++i){
        
        memcpy(Zmac.P, message + pbsize*i, pbsize);
        ZHASH_256(&Zmac, &Chains);
    }

    /* Padding */
    memset(Zmac.P, 0, PZMAC_256_N_SIZE+PZMAC_256_T_SIZE + 1);
    Zmac.P[res] = (1<<7);
    fin = 4*res_flag;
    memcpy(Zmac.P, message + pbsize*numP_complete, PZMAC_256_N_SIZE*(1-res_flag) + res);

    /* Last round */
    ZHASH_256(&Zmac, &Chains);
    memcpy(Zmac.P, Chains.u, PZMAC_256_N_SIZE);
    memcpy(Zmac.P + PZMAC_256_N_SIZE, Chains.v, PZMAC_256_T_SIZE + 1);
    ZFIN_256(&Zmac, fin);

    memcpy(out_left, Zmac.out, PZMAC_256_N_SIZE);
    memcpy(out_right, Zmac.out +PZMAC_256_N_SIZE, PZMAC_256_N_SIZE);
}

static void ZHASH_192(ZmacStruct *pZmac, MacChains *pChains){
    uint8_t tmp[PZMAC_192_T_SIZE], cmask[PZMAC_192_N_SIZE];
    memcpy(tmp, pZmac->P + PZMAC_192_N_SIZE, PZMAC_192_T_SIZE);
    
    arrXOR(pZmac->P, pZmac->mask_l, PZMAC_192_N_SIZE);
    arrXOR(pZmac->P + PZMAC_192_N_SIZE, pZmac->mask_r, PZMAC_192_T_SIZE);
    
    pZmac->P[PZMAC_192_N_SIZE+PZMAC_192_T_SIZE] = 0x08;
    skinny_64_192_init_tweakpart(pZmac->tks2.tks64, pZmac->P + PZMAC_192_N_SIZE, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(pZmac->tks1.tks64, pZmac->tks2.tks64, cmask, pZmac->P);

    arrXOR(pChains->u, cmask, PZMAC_192_N_SIZE);
    arrDOUBLE_64(pChains->u);

    arrXOR(tmp, cmask, PZMAC_192_T_SIZE);
    arrXOR(pChains->v, tmp, PZMAC_192_T_SIZE);

    arrDOUBLE_64(pZmac->mask_l);
    arrDOUBLE_64(pZmac->mask_r);
}

static void ZFIN_192(ZmacStruct *pZmac, uint8_t fin){
    uint8_t tmp[PZMAC_192_N_SIZE];
    // Y_1
    pZmac->P[PZMAC_192_N_SIZE+PZMAC_192_T_SIZE] = fin;
    skinny_64_192_init_tweakpart(pZmac->tks2.tks64, pZmac->P + PZMAC_192_N_SIZE, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(pZmac->tks1.tks64, pZmac->tks2.tks64, pZmac->out, pZmac->P);

    ++pZmac->P[PZMAC_192_N_SIZE+PZMAC_192_T_SIZE];
    skinny_64_192_init_tweakpart(pZmac->tks2.tks64, pZmac->P + PZMAC_192_N_SIZE, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(pZmac->tks1.tks64, pZmac->tks2.tks64, tmp, pZmac->P);
    arrXOR(pZmac->out, tmp, PZMAC_192_N_SIZE);

    // Y_2
    ++pZmac->P[PZMAC_192_N_SIZE+PZMAC_192_T_SIZE];
    skinny_64_192_init_tweakpart(pZmac->tks2.tks64, pZmac->P + PZMAC_192_N_SIZE, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(pZmac->tks1.tks64, pZmac->tks2.tks64, &pZmac->out[PZMAC_192_N_SIZE], pZmac->P);

    ++pZmac->P[PZMAC_192_N_SIZE+PZMAC_192_T_SIZE];
    skinny_64_192_init_tweakpart(pZmac->tks2.tks64, pZmac->P + PZMAC_192_N_SIZE, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(pZmac->tks1.tks64, pZmac->tks2.tks64, tmp, pZmac->P);
    arrXOR(pZmac->out + PZMAC_192_N_SIZE, tmp, PZMAC_192_N_SIZE);
}

void ZMAC_192_skinny(const uint8_t key[16], uint8_t out_left[8], uint8_t out_right[8], const uint8_t *message, const uint32_t mlen){
    uint8_t pbsize, res, res_flag, fin;
    uint16_t numP_complete;
    ZmacStruct Zmac;
    MacChains Chains;
    skinny_64_192_tweakey_schedule_t tks1, tks2;

    Zmac.tks1.tks64 = &tks1;
    Zmac.tks2.tks64 = &tks2;

    pbsize = PZMAC_192_N_SIZE+PZMAC_192_T_SIZE;
    res = mlen%pbsize;
    res_flag = (res) ? 1:0;
    numP_complete = (uint16_t)(mlen/pbsize) - 1 + res_flag;

    memset(Zmac.P, 0, PZMAC_192_P_SIZE + 1);
    memset(Chains.u, 0, PZMAC_192_N_SIZE);
    memset(Chains.v, 0, PZMAC_192_T_SIZE+1);

    Zmac.P[pbsize] = 0x09;
    skinny_64_192_init_keypart(Zmac.tks1.tks64, key, SKINNY_64_192_ROUNDS);
    skinny_64_192_init_tweakpart(Zmac.tks2.tks64, Zmac.P + PZMAC_192_N_SIZE, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(Zmac.tks1.tks64, Zmac.tks2.tks64, Zmac.mask_l, Zmac.P);

    Zmac.P[pbsize-1] = 0x01;
    skinny_64_192_init_tweakpart(Zmac.tks2.tks64, Zmac.P + PZMAC_192_N_SIZE, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(Zmac.tks1.tks64, Zmac.tks2.tks64, Zmac.mask_r, Zmac.P);


    for(uint16_t i = 0; i<numP_complete; ++i){
        memcpy(Zmac.P, message + pbsize*i, pbsize);
        ZHASH_192(&Zmac, &Chains);
    }

    /* Padding */
    memset(Zmac.P, 0, PZMAC_192_N_SIZE+PZMAC_192_T_SIZE + 1);
    Zmac.P[res] = (1<<7);
    fin = 4*res_flag;
    memcpy(Zmac.P, message + pbsize*numP_complete, PZMAC_192_N_SIZE*(1-res_flag) + res);

    /* Last round */
    ZHASH_192(&Zmac, &Chains);
    memcpy(Zmac.P, Chains.u, PZMAC_192_N_SIZE);
    memcpy(Zmac.P + PZMAC_192_N_SIZE, Chains.v, PZMAC_192_T_SIZE + 1);
    ZFIN_192(&Zmac, fin);

    memcpy(out_left, Zmac.out, PZMAC_192_N_SIZE);
    memcpy(out_right, Zmac.out +PZMAC_192_N_SIZE, PZMAC_192_N_SIZE);
}
