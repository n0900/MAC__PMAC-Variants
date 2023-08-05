#ifndef PZMAC
#define PZMAC

#include <stdint.h>
#include "../../forkskinny-opt32/skinny.h"

typedef union {
    skinny_128_256_tweakey_schedule_t *tks128;
    skinny_64_192_tweakey_schedule_t *tks64;
} TweakeySched;

typedef struct {
    uint8_t v[16];
    uint8_t u[16];
} MacChains;

typedef struct{
    uint8_t in[16];
    uint8_t out[16];
    skinny_128_256_tweakey_schedule_t *tks1;
    skinny_128_256_tweakey_schedule_t *tks2;
} Pmac1Struct;

typedef struct {
    uint8_t message[16];
    uint8_t tweak[16];
    uint8_t out[32];
    TweakeySched tks1;
    TweakeySched tks2;
} Pmac2xStruct;

typedef struct {
    uint8_t message[16];
    uint8_t tweak[16];
    uint8_t P[32];
    uint8_t mask_l[16];
    uint8_t mask_r[16];
    uint8_t out[32];
    TweakeySched tks1;
    TweakeySched tks2;
} ZmacStruct;

#define PZMAC_192_N_SIZE 8
#define PZMAC_192_K_SIZE 16
#define PZMAC_192_T_SIZE 7
#define PZMAC_192_P_SIZE (PZMAC_192_N_SIZE + PZMAC_192_T_SIZE)

#define PZMAC_256_N_SIZE 16
#define PZMAC_256_K_SIZE 16
#define PZMAC_256_T_SIZE 15
#define PZMAC_256_P_SIZE (PZMAC_256_N_SIZE + PZMAC_256_T_SIZE)

// PMAC1
void PMAC1_256_skinny(const uint8_t key[16], uint8_t out[16], const uint8_t *message, const uint32_t mlen);

// PMAC2x
void PMAC2x_192_skinny(const uint8_t key[16], uint8_t out_left[ 8], uint8_t out_right[ 8], const uint8_t *message, const uint32_t mlen);
void PMAC2x_256_skinny(const uint8_t key[16], uint8_t out_left[16], uint8_t out_right[16], const uint8_t *message, const uint32_t mlen);

// ZMAC
void ZMAC_192_skinny(const uint8_t key[16], uint8_t out_left[ 8], uint8_t out_right[ 8], const uint8_t *message, const uint32_t mlen);
void ZMAC_256_skinny(const uint8_t key[16], uint8_t out_left[16], uint8_t out_right[16], const uint8_t *message, const uint32_t mlen);

#endif

