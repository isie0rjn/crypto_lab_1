#ifndef CRYPTO_LAB_1_EXPMOD_H
#define CRYPTO_LAB_1_EXPMOD_H

#include <stdint.h>

/* a * b mod m без переполнения */
uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m);

/* все функции: m <= 1 даёт 0 */
uint64_t EXP_rtl(uint64_t b, uint64_t e, uint64_t m);
uint64_t EXP_ltr(uint64_t b, uint64_t e, uint64_t m);
uint64_t EXP_ladder(uint64_t b, uint64_t e, uint64_t m);
/* k - ширина окна, приводится к 1..8 */
uint64_t EXP_window(uint64_t b, uint64_t e, uint64_t m, int k);

#endif
