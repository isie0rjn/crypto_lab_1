#ifndef CRYPTO_LAB_1_UTIL_H
#define CRYPTO_LAB_1_UTIL_H

#include <stdint.h>

/* результат в [0, n) и для отрицательного a */
int mod_int(int a, int n);
/* -1, если символа нет в алфавите */
int alpha_index(const char *alphabet, char c);

/* 0 - ok, -1 - не число или переполнение; hex != 0: шестнадцатеричное, 0x необязателен */
int parse_u64(const char *s, uint64_t *out, int hex);
int parse_i64(const char *s, int64_t *out);

uint64_t gcd_u64(uint64_t a, uint64_t b);
uint64_t isqrt_u64(uint64_t n);
int is_prime_u64(uint64_t n);
/* число различных простых делителей, -1 если их больше max */
int factor_u64(uint64_t n, uint64_t *primes, int *exps, int max);

#endif
