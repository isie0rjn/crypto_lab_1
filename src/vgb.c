#include "vgb.h"

#include <stdio.h>
#include <string.h>

#define CHUNK 4096
#define HEADER 8

static const char hex_digits[] = "0123456789ABCDEF";

uint32_t VGB_random(uint32_t *state) {
    uint32_t x = *state;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* у xorshift ноль - неподвижная точка, его подменяем */
uint32_t VGB_seed_state(uint64_t seed) {
    uint32_t s = (uint32_t) (seed ^ (seed >> 32));
    return (s != 0) ? s : 0x6D2B79F5u;
}

/* младшие биты xorshift32 слабее, берём старший байт */
static unsigned char next_gamma(uint32_t *state) {
    return (unsigned char) (VGB_random(state) >> 24);
}

/* pos - сквозной номер байта, чтобы ключ не сбивался на границе блоков */
static void vgb_xor(unsigned char *buf, size_t n, const char *key, size_t key_len,
                    uint64_t *pos, uint32_t *state) {
    for (size_t i = 0; i < n; i++) {
        buf[i] ^= (unsigned char) key[*pos % key_len] ^ next_gamma(state);
        (*pos)++;
    }
}

char *VGB_exclud(const unsigned char *bytes, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hex_digits[bytes[i] >> 4];
        out[2 * i + 1] = hex_digits[bytes[i] & 0x0F];
    }
    out[2 * n] = '\0';
    return out;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

size_t VGB_restore(const char *printable, unsigned char *bytes) {
    size_t len = strlen(printable);

    if (len % 2 != 0)
        return (size_t) -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_value(printable[2 * i]);
        int lo = hex_value(printable[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return (size_t) -1;
        bytes[i] = (unsigned char) ((hi << 4) | lo);
    }
    return len / 2;
}

char *VGB_encrypt(const char *message, const char *key, uint64_t seed, char *out_hex) {
    size_t key_len = strlen(key);
    uint32_t state = VGB_seed_state(seed);
    uint64_t pos = 0;

    if (key_len == 0)
        return NULL;
    out_hex[0] = '\0';
    for (size_t i = 0; message[i] != '\0'; i++) {
        unsigned char c = (unsigned char) message[i];
        vgb_xor(&c, 1, key, key_len, &pos, &state);
        VGB_exclud(&c, 1, out_hex + 2 * i);
    }
    return out_hex;
}

char *VGB_decrypt(const char *hex, const char *key, uint64_t seed, char *out) {
    size_t key_len = strlen(key);
    uint32_t state = VGB_seed_state(seed);
    uint64_t pos = 0;

    if (key_len == 0)
        return NULL;
    size_t n = VGB_restore(hex, (unsigned char *) out);
    if (n == (size_t) -1)
        return NULL;
    vgb_xor((unsigned char *) out, n, key, key_len, &pos, &state);
    out[n] = '\0';
    return out;
}

static int xor_stream(FILE *in, FILE *out, const char *key, uint64_t seed) {
    unsigned char buf[CHUNK];
    uint32_t state = VGB_seed_state(seed);
    uint64_t pos = 0;
    size_t key_len = strlen(key);
    size_t n;

    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        vgb_xor(buf, n, key, key_len, &pos, &state);
        if (fwrite(buf, 1, n, out) != n)
            return -3;
    }
    return ferror(in) ? -3 : 0;
}

int VGB_encrypt_file(const char *in_path, const char *out_path, const char *key, uint64_t seed) {
    unsigned char header[HEADER];
    int rc;

    if (key[0] == '\0')
        return -4;
    FILE *in = fopen(in_path, "rb");
    if (in == NULL)
        return -1;
    FILE *out = fopen(out_path, "wb");
    if (out == NULL) {
        fclose(in);
        return -2;
    }
    /* seed в начале файла, little-endian, чтобы для расшифровки хватало ключа */
    for (int i = 0; i < HEADER; i++)
        header[i] = (unsigned char) (seed >> (8 * i));
    rc = (fwrite(header, 1, HEADER, out) == HEADER) ? xor_stream(in, out, key, seed) : -3;
    fclose(in);
    if (fclose(out) != 0 && rc == 0)
        rc = -3;
    return rc;
}

int VGB_decrypt_file(const char *in_path, const char *out_path, const char *key) {
    unsigned char header[HEADER];
    uint64_t seed = 0;
    int rc;

    if (key[0] == '\0')
        return -4;
    FILE *in = fopen(in_path, "rb");
    if (in == NULL)
        return -1;
    if (fread(header, 1, HEADER, in) != HEADER) {
        fclose(in);
        return -5;
    }
    for (int i = 0; i < HEADER; i++)
        seed |= (uint64_t) header[i] << (8 * i);
    FILE *out = fopen(out_path, "wb");
    if (out == NULL) {
        fclose(in);
        return -2;
    }
    rc = xor_stream(in, out, key, seed);
    fclose(in);
    if (fclose(out) != 0 && rc == 0)
        rc = -3;
    return rc;
}
