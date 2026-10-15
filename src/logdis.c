#include "logdis.h"

#include <stdlib.h>

#include "expmod.h"
#include "invmod.h"
#include "util.h"

#define MAX_FACTORS 16
#define RHO_TRIES 20

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

/* xorshift64*, детерминированный - результаты воспроизводимы */
static uint64_t rng_next(void) {
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Dull;
}

static uint64_t rand_below(uint64_t n) {
    return (n == 0) ? 0 : rng_next() % n;
}

static uint64_t inv_mod(uint64_t a, uint64_t m) {
    int64_t inv = 0;

    if (INV_eea((int64_t) a, (int64_t) m, &inv) != 0)
        return 0;
    return (uint64_t) inv;
}

/* ord(g) - делим p - 1 на простые делители, пока g^(n/q) = 1 */
static uint64_t group_order(uint64_t g, uint64_t p) {
    uint64_t primes[MAX_FACTORS];
    int exps[MAX_FACTORS];
    uint64_t n = p - 1;
    int count = factor_u64(n, primes, exps, MAX_FACTORS);

    for (int i = 0; i < count; i++) {
        while (n % primes[i] == 0 && EXP_rtl(g, n / primes[i], p) == 1)
            n /= primes[i];
    }
    return n;
}

/* 0 - решать дальше, 1 - ответ x = 0 уже готов, < 0 - код ошибки */
static int prepare(uint64_t *g, uint64_t *h, uint64_t p, uint64_t *n, uint64_t *x) {
    if (p < 2 || p > (uint64_t) INT64_MAX || !is_prime_u64(p))
        return -2;
    *g %= p;
    *h %= p;
    if (*g == 0 || *h == 0)
        return -2;
    *n = group_order(*g, p);
    if (*h == 1) {
        *x = 0;
        return 1;
    }
    /* подгруппа порядка n в Z_p* единственна, так что h^n = 1 <=> h лежит в <g> */
    if (EXP_rtl(*h, *n, p) != 1)
        return -1;
    return 0;
}

static int finish(uint64_t g, uint64_t h, uint64_t p, uint64_t x, uint64_t *out) {
    if (EXP_rtl(g, x, p) != h)
        return -3;
    *out = x;
    return 0;
}

int DL_brute(uint64_t g, uint64_t h, uint64_t p, uint64_t *x) {
    uint64_t n, cur = 1;
    int rc = prepare(&g, &h, p, &n, x);

    if (rc != 0)
        return (rc < 0) ? rc : 0;
    for (uint64_t k = 0; k < n; k++) {
        if (cur == h)
            return finish(g, h, p, k, x);
        cur = mul_mod(cur, g, p);
    }
    return -1;
}

struct baby {
    uint64_t value;
    uint64_t j;
};

static int cmp_baby(const void *pa, const void *pb) {
    const struct baby *a = pa, *b = pb;

    if (a->value != b->value)
        return (a->value < b->value) ? -1 : 1;
    if (a->j != b->j)
        return (a->j < b->j) ? -1 : 1;
    return 0;
}

/* шаг младенца / шаг великана в подгруппе известного порядка n */
static int bsgs_order(uint64_t g, uint64_t h, uint64_t p, uint64_t n, uint64_t *x) {
    uint64_t m = isqrt_u64(n);
    if (m * m < n)
        m++;
    if (m > SIZE_MAX / sizeof(struct baby))
        return -3;

    struct baby *table = malloc((size_t) m * sizeof *table);
    if (table == NULL)
        return -3;

    uint64_t cur = 1;
    for (uint64_t j = 0; j < m; j++) {
        table[j].value = cur;
        table[j].j = j;
        cur = mul_mod(cur, g, p);
    }
    qsort(table, (size_t) m, sizeof *table, cmp_baby);

    /* cur = g^m, великан делает шаг умножением на g^-m */
    uint64_t factor = inv_mod(cur, p);
    uint64_t gamma = h;
    for (uint64_t i = 0; i < m; i++) {
        /* левая граница среди равных значений даёт наименьшее j */
        size_t lo = 0, hi = (size_t) m;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (table[mid].value < gamma)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo < (size_t) m && table[lo].value == gamma) {
            *x = i * m + table[lo].j;
            free(table);
            return 0;
        }
        gamma = mul_mod(gamma, factor, p);
    }
    free(table);
    return -1;
}

int DL_bsgs(uint64_t g, uint64_t h, uint64_t p, uint64_t *x) {
    uint64_t n, r;
    int rc = prepare(&g, &h, p, &n, x);

    if (rc != 0)
        return (rc < 0) ? rc : 0;
    if ((rc = bsgs_order(g, h, p, n, &r)) != 0)
        return rc;
    return finish(g, h, p, r, x);
}

/* разбиение по y mod 3, y = g^a * h^b; salt != 0 только на повторных попытках */
static void rho_step(uint64_t *y, uint64_t *a, uint64_t *b,
                     uint64_t g, uint64_t h, uint64_t p, uint64_t n, uint64_t salt) {
    switch ((*y ^ salt) % 3) {
    case 1:
        *y = mul_mod(*y, h, p);
        *b = (*b + 1) % n;
        break;
    case 0:
        *y = mul_mod(*y, *y, p);
        *a = mul_mod(*a, 2, n);
        *b = mul_mod(*b, 2, n);
        break;
    default:
        *y = mul_mod(*y, g, p);
        *a = (*a + 1) % n;
        break;
    }
}

int DL_rho(uint64_t g, uint64_t h, uint64_t p, uint64_t *x) {
    uint64_t n;
    int rc = prepare(&g, &h, p, &n, x);

    if (rc != 0)
        return (rc < 0) ? rc : 0;
    /* в группе из пары элементов блуждание сразу замыкается с b = B, проще перебрать */
    if (n < 8)
        return DL_brute(g, h, p, x);

    for (int attempt = 0; attempt < RHO_TRIES; attempt++) {
        uint64_t a = attempt ? rand_below(n) : 0;
        uint64_t b = attempt ? rand_below(n) : 0;
        /* новый старт без смены разбиения попадает в тот же цикл с тем же приращением */
        uint64_t salt = attempt ? rng_next() : 0;
        uint64_t y = mul_mod(EXP_rtl(g, a, p), EXP_rtl(h, b, p), p);
        uint64_t Y = y, A = a, B = b;

        /* последовательность в группе из n элементов зацикливается не позже чем за n шагов */
        for (uint64_t step = 0; step <= n; step++) {
            rho_step(&y, &a, &b, g, h, p, n, salt);
            rho_step(&Y, &A, &B, g, h, p, n, salt);
            rho_step(&Y, &A, &B, g, h, p, n, salt);
            if (y == Y)
                break;
        }
        if (y != Y)
            continue;

        /* g^a h^b = g^A h^B  =>  (B - b) x = a - A (mod n) */
        uint64_t r = (B + n - b) % n;
        uint64_t s = (a + n - A) % n;
        if (r == 0)
            continue;
        uint64_t d = gcd_u64(r, n);
        if (s % d != 0)
            continue;
        uint64_t nd = n / d;
        uint64_t x0 = mul_mod(s / d, inv_mod((r / d) % nd, nd), nd);
        /* gcd > 1 даёт d кандидатов, проверяем каждый */
        for (uint64_t k = 0; k < d; k++) {
            uint64_t cand = x0 + k * nd;
            if (EXP_rtl(g, cand, p) == h)
                return finish(g, h, p, cand, x);
        }
    }
    return -3;
}

/* x = X (mod M), x = xi (mod q)  ->  x mod M*q */
static uint64_t crt_add(uint64_t X, uint64_t M, uint64_t xi, uint64_t q) {
    uint64_t diff = (xi % q + q - X % q) % q;
    uint64_t t = mul_mod(diff, inv_mod(M % q, q), q);
    return X + M * t;
}

int DL_ph(uint64_t g, uint64_t h, uint64_t p, uint64_t *x) {
    uint64_t primes[MAX_FACTORS];
    int exps[MAX_FACTORS];
    uint64_t n;
    int rc = prepare(&g, &h, p, &n, x);

    if (rc != 0)
        return (rc < 0) ? rc : 0;
    int count = factor_u64(n, primes, exps, MAX_FACTORS);
    if (count < 0)
        return -3;

    uint64_t X = 0, M = 1;
    for (int i = 0; i < count; i++) {
        uint64_t q = primes[i], qe = 1;
        for (int k = 0; k < exps[i]; k++)
            qe *= q;

        /* переходим в подгруппу порядка q^e */
        uint64_t g0 = EXP_rtl(g, n / qe, p);
        uint64_t h0 = EXP_rtl(h, n / qe, p);
        uint64_t gamma = EXP_rtl(g0, qe / q, p);
        uint64_t xi = 0, qk = 1;

        /* xi = d0 + d1 q + ... ; цифра dk из (g0^-xi * h0)^(q^(e-1-k)) = gamma^dk */
        for (int k = 0; k < exps[i]; k++) {
            uint64_t t = mul_mod(inv_mod(EXP_rtl(g0, xi, p), p), h0, p);
            uint64_t hk = EXP_rtl(t, qe / (qk * q), p);
            uint64_t d;
            if (bsgs_order(gamma, hk, p, q, &d) != 0)
                return -3;
            xi += d * qk;
            qk *= q;
        }
        X = crt_add(X, M, xi, qe);
        M *= qe;
    }
    return finish(g, h, p, X, x);
}
