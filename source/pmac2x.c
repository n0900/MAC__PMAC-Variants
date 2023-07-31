#include <stdint.h>
#include <string.h>
#include "pzmac.h"
#include "../forkskinny/skinny.h"

// static void iterate_tweakey(uint8_t *pTweakey, uint8_t start){
//     if (pTweakey[start]<0xFF){
//         ++pTweakey[start];
//     }else{
//         pTweakey[start] = 0x00;
//         ++pTweakey[start+1];
//     }
// }

static void arrLeftByOne(uint8_t *out, int len){
    for (uint8_t i = 0;  i < len - 1;  ++i){
        out[i] = (out[i] << 1) | ((out[i+1] >> 7) & 1);
    }
    out[len-1] = out[len-1] << 1;
}

static void arrXOR(uint8_t *out, uint8_t *right, uint16_t len){
    for(uint8_t i = 0; i<len; ++i){
        out[i] ^= right[i];
    }
}

static void arrMULT(uint8_t *out, uint8_t prpol, uint8_t len){
    uint8_t tmp = (out[len-1] >> 7) & 1;
    arrLeftByOne(out, len);
    out[0] ^= prpol * tmp;
}

// static void PHASH2x(Pmac2xStruct *pPmac2x, MacChains *pChains, uint8_t prpol){    
//     iterate_tweakey(pPmac2x->tweak, 1);
//     #if BS==16
//     skinny_128_256_init_tk2(pPmac2x->tks2.tks128, pPmac2x->tweak, SKINNY_128_256_ROUNDS);
//     skinny_128_256_encrypt_with_tks(pPmac2x->tks1.tks128, pPmac2x->tks2.tks128, pPmac2x->out, pPmac2x->message);
//     #else
//     skinny_64_192_init_tweakpart(pPmac2x->tks2.tks64, pPmac2x->tweak, SKINNY_64_192_ROUNDS);
//     skinny_64_192_encrypt_with_tks(pPmac2x->tks1.tks64,  pPmac2x->tks2.tks64, pPmac2x->out, pPmac2x->message);
//     #endif

//     arrXOR(pChains->u, pPmac2x->out, BS);
//     arrXOR(pChains->v, pPmac2x->out, BS);
//     arrMULT(pChains->v, prpol, BS);
// }

static void PFIN2x(Pmac2xStruct *pPmac2x, MacChains *pChains){
    uint8_t tmp[TS];
    // U
    tmp[0] = 0x02;
    memcpy(&tmp[1], pChains->v, TS-1);
    #if BS==16
    skinny_128_256_init_tk2(pPmac2x->tks2.tks128, tmp, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(pPmac2x->tks1.tks128, pPmac2x->tks2.tks128, pPmac2x->out, pChains->u);
    #else
    skinny_64_192_init_tweakpart(pPmac2x->tks2.tks64, tmp, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(pPmac2x->tks1.tks64,  pPmac2x->tks2.tks64, pPmac2x->out, pChains->u);
    #endif
    // V
    tmp[0] = 0x03;
    memcpy(&tmp[1], pChains->u, TS-1);
    #if BS==16
    skinny_128_256_init_tk2(pPmac2x->tks2.tks128, tmp, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(pPmac2x->tks1.tks128, pPmac2x->tks2.tks128, &pPmac2x->out[BS], pChains->v);
    #else
    skinny_64_192_init_tweakpart(pPmac2x->tks2.tks64, tmp, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(pPmac2x->tks1.tks64,  pPmac2x->tks2.tks64, &pPmac2x->out[BS], pChains->v);
    #endif
}

void PMAC2x_encrypt(const uint8_t key[KS], uint8_t out_left[BS], uint8_t out_right[BS], const uint8_t *message, const uint32_t mlen){
    uint8_t pbsize, res, res_flag;
    uint16_t numP_complete;
    Pmac2xStruct Pmac2x;
    MacChains Chains;

    pbsize = BS;
    res = mlen%pbsize;
    res_flag = (res) ? 1:0;
    numP_complete = (uint16_t)(mlen/pbsize) - 1 + res_flag;

    #if BS == 16
        uint8_t prpol = 0b10000111;
    #else
        uint8_t prpol = 0b00011011;
    #endif

    #if BS == 16
    skinny_128_256_tweakey_schedule_t tks1, tks2;
    Pmac2x.tks1.tks128 = &tks1;
    Pmac2x.tks2.tks128 = &tks2;
    skinny_128_256_init_tk1(Pmac2x.tks1.tks128, key, SKINNY_128_256_ROUNDS);
    #else 
    skinny_64_192_tweakey_schedule_t tks1, tks2;
    Pmac2x.tks1.tks64 = &tks1;
    Pmac2x.tks2.tks64 = &tks2;
    skinny_64_192_init_keypart(Pmac2x.tks1.tks64, key, SKINNY_64_192_ROUNDS);
    #endif

    memset(Pmac2x.tweak,0, TS);
	memset(Pmac2x.out, 0, BS*2);
    memset(Chains.u, 0, BS);
    memset(Chains.v, 0, TS);

    for(uint16_t i = 0; i<numP_complete; ++i){
        //PHASH2x
        Pmac2x.tweak[1] = (uint8_t)   (i+1);
        Pmac2x.tweak[2] = (uint8_t)(i+1)>>8;
        #if BS==16
        skinny_128_256_init_tk2(Pmac2x.tks2.tks128, Pmac2x.tweak, SKINNY_128_256_ROUNDS);
        skinny_128_256_encrypt_with_tks(Pmac2x.tks1.tks128, Pmac2x.tks2.tks128, Pmac2x.out, message + pbsize*i);
        #else
        skinny_64_192_init_tweakpart(Pmac2x.tks2.tks64, Pmac2.tweak, SKINNY_64_192_ROUNDS);
        skinny_64_192_encrypt_with_tks(Pmac2x.tks1.tks64, Pmac2x.tks2.tks64, pPmac2x.out, message + pbsize*i);
        #endif
        arrXOR(Chains.u, Pmac2x.out, BS);
        arrXOR(Chains.v, Pmac2x.out, BS);
        arrMULT(Chains.v, prpol, BS);
    }

    memset(Pmac2x.message, 0, BS);
    Pmac2x.message[res] ^= (1<<7);
    memcpy(Pmac2x.message, message + pbsize*numP_complete, BS*(1-res_flag) + res);

    //PHASH2x
    Pmac2x.tweak[1] = (uint8_t)   (numP_complete+1);
    Pmac2x.tweak[2] = (uint8_t)(numP_complete+1)>>8;
    #if BS==16
    skinny_128_256_init_tk2(Pmac2x.tks2.tks128, Pmac2x.tweak, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(Pmac2x.tks1.tks128, Pmac2x.tks2.tks128, Pmac2x.out, Pmac2x.message);
    #else
    skinny_64_192_init_tweakpart(Pmac2x.tks2.tks64, Pmac2.tweak, SKINNY_64_192_ROUNDS);
    skinny_64_192_encrypt_with_tks(Pmac2x.tks1.tks64, Pmac2x.tks2.tks64, pPmac2x.out, Pmac2x.message);
    #endif
    arrXOR(Chains.u, Pmac2x.out, BS);
    arrXOR(Chains.v, Pmac2x.out, BS);
    arrMULT(Chains.v, prpol, BS);

    PFIN2x(&Pmac2x, &Chains);

    memcpy(out_left , Pmac2x.out     , BS);
    memcpy(out_right, Pmac2x.out + BS, BS);
}

