#include "expmod.h"

uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m) {
#ifdef __SIZEOF_INT128__
    return (uint64_t) ((unsigned __int128) a * b % m);
#else
    uint64_t r = 0;

    a %= m;
    b %= m;
    /* удвоение со сложением, сравнение с m - a вместо a + a, чтобы не переполниться */
    while (b != 0) {
        if (b & 1)
            r = (r >= m - a) ? r - (m - a) : r + a;
        a = (a >= m - a) ? a - (m - a) : a + a;
        b >>= 1;
    }
    return r;
#endif
}

static int top_bit(uint64_t e) {
    int i = -1;

    while (e != 0) {
        e >>= 1;
        i++;
    }
    return i;
}

uint64_t EXP_rtl(uint64_t b, uint64_t e, uint64_t m) {
    uint64_t r = 1;

    if (m <= 1)
        return 0;
    b %= m;
    while (e != 0) {
        if (e & 1)
            r = mul_mod(r, b, m);
        b = mul_mod(b, b, m);
        e >>= 1;
    }
    return r;
}

uint64_t EXP_ltr(uint64_t b, uint64_t e, uint64_t m) {
    uint64_t r = 1;

    if (m <= 1)
        return 0;
    b %= m;
    for (int i = top_bit(e); i >= 0; i--) {
        r = mul_mod(r, r, m);
        if ((e >> i) & 1)
            r = mul_mod(r, b, m);
    }
    return r;
}

/* инвариант: r1 = r0 * b, на каждом бите одно умножение и одно возведение в квадрат */
uint64_t EXP_ladder(uint64_t b, uint64_t e, uint64_t m) {
    uint64_t r0 = 1, r1;

    if (m <= 1)
        return 0;
    r1 = b % m;
    for (int i = top_bit(e); i >= 0; i--) {
        if ((e >> i) & 1) {
            r0 = mul_mod(r0, r1, m);
            r1 = mul_mod(r1, r1, m);
        } else {
            r1 = mul_mod(r0, r1, m);
            r0 = mul_mod(r0, r0, m);
        }
    }
    return r0;
}

uint64_t EXP_window(uint64_t b, uint64_t e, uint64_t m, int k) {
    uint64_t odd[128];
    uint64_t r = 1;

    if (m <= 1)
        return 0;
    if (k < 1)
        k = 1;
    if (k > 8)
        k = 8;
    b %= m;

    /* odd[i] = b^(2i+1) */
    uint64_t b2 = mul_mod(b, b, m);
    int count = 1 << (k - 1);
    odd[0] = b;
    for (int i = 1; i < count; i++)
        odd[i] = mul_mod(odd[i - 1], b2, m);

    int i = top_bit(e);
    while (i >= 0) {
        if (((e >> i) & 1) == 0) {
            r = mul_mod(r, r, m);
            i--;
            continue;
        }
        /* окно [i..l] не длиннее k и заканчивается единичным битом */
        int l = (i - k + 1 > 0) ? i - k + 1 : 0;
        while (((e >> l) & 1) == 0)
            l++;
        uint64_t w = (e >> l) & (((uint64_t) 1 << (i - l + 1)) - 1);
        for (int s = 0; s < i - l + 1; s++)
            r = mul_mod(r, r, m);
        r = mul_mod(r, odd[w >> 1], m);
        i = l - 1;
    }
    return r;
}
