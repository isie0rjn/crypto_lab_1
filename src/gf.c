#include "gf.h"

#define GF_MODULUS 0x11Bu

static uint8_t exp_table[510];
static uint8_t log_table[256];
static int tables_ready = 0;

uint8_t GF_mul_peasant(uint8_t a, uint8_t b) {
    uint8_t p = 0;

    while (b != 0) {
        if (b & 1)
            p ^= a;
        // старший бит ушёл при сдвиге, приводим по 0x11B
        if (a & 0x80)
            a = (uint8_t) ((a << 1) ^ 0x1B);
        else
            a = (uint8_t) (a << 1);
        b >>= 1;
    }
    return p;
}

static int poly_deg(uint32_t p) {
    int d = -1;

    while (p != 0) {
        p >>= 1;
        d++;
    }
    return d;
}

/* умножение многочленов над GF(2), без переносов */
static uint32_t poly_mult(uint32_t a, uint32_t b) {
    uint32_t r = 0;

    while (b != 0) {
        if (b & 1)
            r ^= a;
        a <<= 1;
        b >>= 1;
    }
    return r;
}

/* деление столбиком, вычитание = xor */
static void poly_divmod(uint32_t a, uint32_t b, uint32_t *q, uint32_t *r) {
    int db = poly_deg(b);
    uint32_t quot = 0;

    for (int da = poly_deg(a); da >= db; da = poly_deg(a)) {
        quot |= (uint32_t) 1 << (da - db);
        a ^= b << (da - db);
    }
    if (q != NULL)
        *q = quot;
    if (r != NULL)
        *r = a;
}

uint8_t GF_mul_poly(uint8_t a, uint8_t b) {
    uint32_t r;

    poly_divmod(poly_mult(a, b), GF_MODULUS, NULL, &r);
    return (uint8_t) r;
}

/* расширенный Евклид по многочленам: t * a = r (mod 0x11B) */
uint8_t GF_inv(uint8_t a) {
    uint32_t r0 = GF_MODULUS, r1 = a;
    uint32_t t0 = 0, t1 = 1;

    if (a == 0)
        return 0;
    while (r1 != 0) {
        uint32_t q, r;
        poly_divmod(r0, r1, &q, &r);
        uint32_t t = t0 ^ poly_mult(q, t1);
        r0 = r1;
        r1 = r;
        t0 = t1;
        t1 = t;
    }
    return (uint8_t) t0;
}

/* генератор 0x03: 0x02 в этом поле имеет порядок 51, а не 255 */
static void build_tables(void) {
    uint8_t x = 1;

    for (int i = 0; i < 255; i++) {
        exp_table[i] = x;
        exp_table[i + 255] = x;
        log_table[x] = (uint8_t) i;
        x = GF_mul_peasant(x, 0x03);
    }
    tables_ready = 1;
}

uint8_t GF_mul_table(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0)
        return 0;
    if (!tables_ready)
        build_tables();
    /* таблица удвоена, поэтому сумму логарифмов не нужно брать по модулю 255 */
    return exp_table[log_table[a] + log_table[b]];
}
