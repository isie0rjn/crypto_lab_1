#ifndef CRYPTO_LAB_1_LOGDIS_H
#define CRYPTO_LAB_1_LOGDIS_H

#include <stdint.h>

/* g^x = h (mod p), x - наименьший неотрицательный
   0 - найден, -1 - решения нет, -2 - p не простое или g, h = 0 (mod p), -3 - метод не сработал */
int DL_brute(uint64_t g, uint64_t h, uint64_t p, uint64_t *x);
int DL_bsgs(uint64_t g, uint64_t h, uint64_t p, uint64_t *x);
int DL_rho(uint64_t g, uint64_t h, uint64_t p, uint64_t *x);
int DL_ph(uint64_t g, uint64_t h, uint64_t p, uint64_t *x);
/* нужен первообразный корень g, иначе -3 */
int DL_ic(uint64_t g, uint64_t h, uint64_t p, uint64_t *x);

#endif
