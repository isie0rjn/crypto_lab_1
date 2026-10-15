#ifndef CRYPTO_LAB_1_GF_H
#define CRYPTO_LAB_1_GF_H

#include <stdint.h>

/* поле GF(2^8) с модулем x^8 + x^4 + x^3 + x + 1 (0x11B) */
uint8_t GF_mul_peasant(uint8_t a, uint8_t b);
uint8_t GF_mul_poly(uint8_t a, uint8_t b);
/* GF_inv(0) = 0 */
uint8_t GF_inv(uint8_t a);
uint8_t GF_mul_table(uint8_t a, uint8_t b);

#endif
