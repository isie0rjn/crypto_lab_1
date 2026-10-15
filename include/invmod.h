#ifndef CRYPTO_LAB_1_INVMOD_H
#define CRYPTO_LAB_1_INVMOD_H

#include <stdint.h>
#include <stdio.h>

/* 0 - ok, -1 - обратного нет, -2 - модуль не простой, -3 - метод неприменим, -4 - m < 2 */
int INV_eea(int64_t a, int64_t m, int64_t *inv);
/* то же, что INV_eea, плюс таблица n0 b0 q r t0 t temp в trace (если не NULL) */
int INV_eea_trace(int64_t a, int64_t m, int64_t *inv, FILE *trace);
int INV_fermat(int64_t a, int64_t m, int64_t *inv);
/* только для нечётного m */
int INV_binary(int64_t a, int64_t m, int64_t *inv);

#endif
