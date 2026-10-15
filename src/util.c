#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

int mod_int(int a, int n) {
    int r = a % n;
    return (r < 0) ? r + n : r;
}

int alpha_index(const char *alphabet, char c) {
    for (int i = 0; alphabet[i] != '\0'; i++) {
        if (alphabet[i] == c)
            return i;
    }
    return -1;
}

int parse_u64(const char *s, uint64_t *out, int hex) {
    char *end;
    int base = 10;

    if (s == NULL || *s == '\0' || *s == '-' || *s == '+' || isspace((unsigned char) *s))
        return -1;
    if (hex) {
        base = 16;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            s += 2;
            if (*s == '\0' || *s == '-' || *s == '+')
                return -1;
        }
    }
    errno = 0;
    unsigned long long v = strtoull(s, &end, base);
    if (errno == ERANGE || *end != '\0')
        return -1;
    *out = (uint64_t) v;
    return 0;
}

int parse_i64(const char *s, int64_t *out) {
    char *end;

    if (s == NULL || *s == '\0' || isspace((unsigned char) *s))
        return -1;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno == ERANGE || *end != '\0')
        return -1;
    *out = (int64_t) v;
    return 0;
}

uint64_t gcd_u64(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

/* побитовый корень "столбиком", без плавающей точки */
uint64_t isqrt_u64(uint64_t n) {
    uint64_t r = 0;
    uint64_t bit = (uint64_t) 1 << 62;

    while (bit > n)
        bit >>= 2;
    while (bit != 0) {
        if (n >= r + bit) {
            n -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    return r;
}

int is_prime_u64(uint64_t n) {
    if (n < 2)
        return 0;
    if (n < 4)
        return 1;
    if (n % 2 == 0 || n % 3 == 0)
        return 0;
    uint64_t limit = isqrt_u64(n);
    /* делители вида 6k +- 1 */
    for (uint64_t i = 5; i <= limit; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return 0;
    }
    return 1;
}

int factor_u64(uint64_t n, uint64_t *primes, int *exps, int max) {
    int count = 0;

    for (uint64_t d = 2; n > 1; d += (d == 2) ? 1 : 2) {
        /* остаток после пробных делителей до корня - простой */
        if (d > n / d)
            d = n;
        if (n % d != 0)
            continue;
        if (count == max)
            return -1;
        primes[count] = d;
        exps[count] = 0;
        while (n % d == 0) {
            n /= d;
            exps[count]++;
        }
        count++;
    }
    return count;
}
