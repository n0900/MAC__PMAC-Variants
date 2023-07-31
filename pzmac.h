#ifndef PZMAC
#define PZMAC

#include <stdint.h>
#include "../globvar.h"
#include "../forkskinny/skinny.h"

typedef union {
    skinny_128_256_tweakey_schedule_t *tks128;
    skinny_64_192_tweakey_schedule_t *tks64;
} TweakeySched;

typedef struct {
    unsigned char v[TS];
    unsigned char u[BS];
} MacChains;

typedef struct{
    unsigned char in[BS];
    unsigned char out[BS];
    skinny_128_256_tweakey_schedule_t *tks1;
    skinny_128_256_tweakey_schedule_t *tks2;
} Pmac1Struct;

typedef struct {
    unsigned char message[BS];
    unsigned char tweak[TS];
	unsigned char out[BS*2];
    TweakeySched tks1;
    TweakeySched tks2;
} Pmac2xStruct;

typedef struct {
    unsigned char message[BS];
    unsigned char tweak[TS];
    unsigned char P[BS+TS];
    unsigned char mask_l[BS];
    unsigned char mask_r[BS];
	unsigned char out[BS*2];
    TweakeySched tks1;
    TweakeySched tks2;
} ZmacStruct;


// Utils
//void skinny_encrypt(unsigned char *output, unsigned char *input, unsigned char *key);

// PMAC1
void PMAC1_encrypt(unsigned char *out, unsigned char *key, uint32_t mlen, uint64_t *cc);

// PMAC2x
// static void PHASH2x(Pmac2xStruct *pPmac2x, MacChains *pChains);
// static void PFIN2x(Pmac2xStruct *pPmac2x, MacChains *pChains);
void PMAC2x_encrypt(unsigned char *out_left, unsigned char *out_right, unsigned char *key, uint32_t mlen, uint64_t *cc);

// ZMAC
// static void ZHASH(ZmacStruct *pZmac, MacChains *pChains);
// static void ZFIN(ZmacStruct *pZmac, uint8_t i);
// static void ZMAC_padding_stream(ZmacStruct *pZmac, uint8_t *fin, uint8_t res);
void ZMAC_encrypt(unsigned char *out_left, unsigned char *out_right, unsigned char *key, uint32_t mlen, uint64_t *cc);
#endif
