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

#define IC_MAX_BASE 700
#define IC_ATTEMPTS 10
#define IC_PHASE2_TRIES 200000

/* граница факторной базы растёт с длиной p */
static uint64_t ic_bound(uint64_t p) {
    uint64_t bits = 0;

    for (uint64_t t = p; t != 0; t >>= 1)
        bits++;
    return (bits <= 16) ? 50 : bits * bits / 2;
}

static int ic_smooth(uint64_t y, const uint64_t *base, int nb, int *e) {
    for (int i = 0; i < nb; i++) {
        e[i] = 0;
        while (y % base[i] == 0) {
            y /= base[i];
            e[i]++;
        }
    }
    return y == 1;
}

/* Гаусс-Жордан по модулю q^e: пивот должен быть обратим, т.е. не делиться на q.
   столбец без такого пивота пропускается, его значение в sol неверно и отсеется проверкой */
static int ic_solve_mod(const int *ex, const uint64_t *rhs, int rows, int cols,
                        uint64_t mod, uint64_t q, uint64_t *sol) {
    size_t width = (size_t) cols + 1;
    uint64_t *a = malloc((size_t) rows * width * sizeof *a);

    if (a == NULL)
        return -3;
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++)
            a[r * width + c] = (uint64_t) ex[(size_t) r * cols + c] % mod;
        a[r * width + cols] = rhs[r] % mod;
    }

    int top = 0;
    for (int c = 0; c < cols; c++) {
        int piv = -1;
        sol[c] = 0;
        for (int r = top; r < rows; r++) {
            if (a[r * width + c] % q != 0) {
                piv = r;
                break;
            }
        }
        if (piv < 0)
            continue;
        if (piv != top) {
            for (size_t k = 0; k < width; k++) {
                uint64_t t = a[(size_t) piv * width + k];
                a[(size_t) piv * width + k] = a[(size_t) top * width + k];
                a[(size_t) top * width + k] = t;
            }
        }
        uint64_t *prow = &a[(size_t) top * width];
        uint64_t inv = inv_mod(prow[c], mod);
        for (size_t k = 0; k < width; k++)
            prow[k] = mul_mod(prow[k], inv, mod);
        for (int r = 0; r < rows; r++) {
            uint64_t *row = &a[(size_t) r * width];
            uint64_t f = row[c];
            if (r == top || f == 0)
                continue;
            for (size_t k = 0; k < width; k++)
                row[k] = (row[k] + mod - mul_mod(f, prow[k], mod)) % mod;
        }
        /* пока только номер строки, значение снимем после полного прохода */
        sol[c] = (uint64_t) top + 1;
        top++;
    }
    for (int c = 0; c < cols; c++) {
        if (sol[c] != 0)
            sol[c] = a[(size_t) (sol[c] - 1) * width + cols];
    }
    free(a);
    return 0;
}

/* логарифмы факторной базы; known[j] = 1, если log(p_j) найден и проверен.
   0 - ok, -1 - не набралось соотношений, -3 - нет памяти */
static int ic_phase1(uint64_t g, uint64_t p, const uint64_t *base, int nb, int rows,
                     const uint64_t *pq, const int *pe, int pcount, uint64_t *logs, int *known) {
    uint64_t n = p - 1;
    int *ex = malloc((size_t) rows * nb * sizeof *ex);
    uint64_t *rhs = malloc((size_t) rows * sizeof *rhs);
    uint64_t *sol = malloc((size_t) nb * sizeof *sol);
    int rc = 0;

    if (ex == NULL || rhs == NULL || sol == NULL) {
        rc = -3;
        goto out;
    }

    /* соотношения k = sum e_j log(p_j) (mod p - 1) из гладких g^k */
    int found = 0;
    for (uint64_t tries = 0; found < rows && tries < (uint64_t) rows * 2000; tries++) {
        uint64_t k = 1 + rand_below(n - 1);
        if (ic_smooth(EXP_rtl(g, k, p), base, nb, &ex[(size_t) found * nb])) {
            rhs[found] = k;
            found++;
        }
    }
    if (found < rows) {
        rc = -1;
        goto out;
    }

    /* решаем по модулю каждого q^e из p - 1 и склеиваем по КТО */
    for (int c = 0; c < nb; c++)
        logs[c] = 0;
    uint64_t M = 1;
    for (int i = 0; i < pcount; i++) {
        uint64_t qe = 1;
        for (int k = 0; k < pe[i]; k++)
            qe *= pq[i];
        if ((rc = ic_solve_mod(ex, rhs, rows, nb, qe, pq[i], sol)) != 0)
            goto out;
        for (int c = 0; c < nb; c++)
            logs[c] = crt_add(logs[c], M, sol[c], qe);
        M *= qe;
    }
    /* малые p: простое из базы может встретиться только как само g^k, и если такое k
       не выпало, столбец вырожден - его логарифм просто не используем */
    for (int c = 0; c < nb; c++)
        known[c] = EXP_rtl(g, logs[c], p) == base[c];

out:
    free(ex);
    free(rhs);
    free(sol);
    return rc;
}

int DL_ic(uint64_t g, uint64_t h, uint64_t p, uint64_t *x) {
    uint64_t base[IC_MAX_BASE], logs[IC_MAX_BASE];
    int e[IC_MAX_BASE], known[IC_MAX_BASE];
    uint64_t pq[MAX_FACTORS];
    int pe[MAX_FACTORS];
    uint64_t n;
    int rc = prepare(&g, &h, p, &n, x);

    if (rc != 0)
        return (rc < 0) ? rc : 0;
    /* соотношения выводятся по модулю p - 1, это верно только для первообразного корня */
    if (n != p - 1)
        return -3;

    uint64_t bound = ic_bound(p);
    int nb = 0;
    for (uint64_t q = 2; q <= bound && q < p && nb < IC_MAX_BASE; q++) {
        if (is_prime_u64(q))
            base[nb++] = q;
    }
    int pcount = factor_u64(n, pq, pe, MAX_FACTORS);
    if (nb == 0 || pcount < 0)
        return -3;

    for (int attempt = 0; attempt < IC_ATTEMPTS; attempt++) {
        /* если вторая фаза не удалась, повторяем первую с большим числом соотношений */
        int rows = nb + 10 + attempt * (nb / 2 + 5);
        rc = ic_phase1(g, p, base, nb, rows, pq, pe, pcount, logs, known);
        if (rc == -3)
            return -3;
        if (rc != 0)
            continue;

        for (int t = 0; t < IC_PHASE2_TRIES / IC_ATTEMPTS; t++) {
            uint64_t k = rand_below(n);
            if (!ic_smooth(mul_mod(h, EXP_rtl(g, k, p), p), base, nb, e))
                continue;
            /* log h = sum e_j log(p_j) - k, годится только разложение по известным логарифмам */
            uint64_t s = 0;
            int usable = 1;
            for (int j = 0; j < nb && usable; j++) {
                if (e[j] != 0 && !known[j])
                    usable = 0;
                else
                    s = (s + mul_mod((uint64_t) e[j], logs[j], n)) % n;
            }
            if (usable)
                return finish(g, h, p, (s + n - k) % n, x);
        }
    }
    return -3;
}
