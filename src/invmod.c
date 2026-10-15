#include "invmod.h"

#include "expmod.h"
#include "util.h"

static int64_t reduce(int64_t a, int64_t m) {
    int64_t r = a % m;
    return (r < 0) ? r + m : r;
}

int INV_eea_trace(int64_t a, int64_t m, int64_t *inv, FILE *trace) {
    if (m < 2)
        return -4;
    a = reduce(a, m);
    if (a == 0)
        return -1;

    uint64_t n = (uint64_t) m;
    uint64_t n0 = n, b0 = (uint64_t) a;
    uint64_t t0 = 0, t = 1;
    uint64_t q = n0 / b0, r = n0 - q * b0;

    if (trace != NULL)
        fprintf(trace, "%-12s %-12s %-12s %-12s %-12s %-12s %-12s\n",
                "n0", "b0", "q", "r", "t0", "t", "temp");
    while (r > 0) {
        /* temp = t0 - q*t, сразу по модулю n, так q*t не переполняется */
        uint64_t temp = (t0 + n - mul_mod(q % n, t, n)) % n;
        if (trace != NULL)
            fprintf(trace, "%-12llu %-12llu %-12llu %-12llu %-12llu %-12llu %-12llu\n",
                    (unsigned long long) n0, (unsigned long long) b0, (unsigned long long) q,
                    (unsigned long long) r, (unsigned long long) t0, (unsigned long long) t,
                    (unsigned long long) temp);
        t0 = t;
        t = temp;
        n0 = b0;
        b0 = r;
        q = n0 / b0;
        r = n0 - q * b0;
    }
    if (trace != NULL)
        fprintf(trace, "%-12llu %-12llu %-12llu %-12llu %-12llu %-12llu %-12s\n",
                (unsigned long long) n0, (unsigned long long) b0, (unsigned long long) q,
                (unsigned long long) r, (unsigned long long) t0, (unsigned long long) t, "-");

    /* b0 здесь равен gcd(a, m) */
    if (b0 != 1)
        return -1;
    *inv = (int64_t) t;
    return 0;
}

int INV_eea(int64_t a, int64_t m, int64_t *inv) {
    return INV_eea_trace(a, m, inv, NULL);
}

int INV_fermat(int64_t a, int64_t m, int64_t *inv) {
    if (m < 2)
        return -4;
    a = reduce(a, m);
    if (gcd_u64((uint64_t) a, (uint64_t) m) != 1)
        return -1;
    if (!is_prime_u64((uint64_t) m))
        return -2;
    *inv = (int64_t) EXP_ladder((uint64_t) a, (uint64_t) m - 2, (uint64_t) m);
    return 0;
}

int INV_binary(int64_t a, int64_t m, int64_t *inv) {
    if (m < 2)
        return -4;
    a = reduce(a, m);
    /* при gcd != 1 цикл из методички не останавливается */
    if (gcd_u64((uint64_t) a, (uint64_t) m) != 1)
        return -1;
    /* деление (x + m) / 2 работает только при нечётном m */
    if (m % 2 == 0)
        return -3;

    uint64_t n = (uint64_t) m;
    uint64_t u = (uint64_t) a, v = n;
    uint64_t x1 = 1, x2 = 0;

    /* инвариант: x1 * a = u (mod m), x2 * a = v (mod m) */
    while (u != 1 && v != 1) {
        while ((u & 1) == 0) {
            u >>= 1;
            x1 = (x1 & 1) ? (x1 + n) >> 1 : x1 >> 1;
        }
        while ((v & 1) == 0) {
            v >>= 1;
            x2 = (x2 & 1) ? (x2 + n) >> 1 : x2 >> 1;
        }
        if (u >= v) {
            u -= v;
            x1 = (x1 >= x2) ? x1 - x2 : x1 + n - x2;
        } else {
            v -= u;
            x2 = (x2 >= x1) ? x2 - x1 : x2 + n - x1;
        }
    }
    *inv = (int64_t) ((u == 1) ? x1 : x2);
    return 0;
}
