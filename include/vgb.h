#ifndef CRYPTO_LAB_1_VGB_H
#define CRYPTO_LAB_1_VGB_H

#include <stddef.h>
#include <stdint.h>

/* c_i = m_i ^ k_(i mod |k|) ^ r_i, r_i - старший байт очередного xorshift32 */

/* out_hex: 2 * strlen(message) + 1; NULL при пустом ключе */
char *VGB_encrypt(const char *message, const char *key, uint64_t seed, char *out_hex);
/* out: strlen(hex) / 2 + 1; NULL при пустом ключе или неверном hex */
char *VGB_decrypt(const char *hex, const char *key, uint64_t seed, char *out);
/* байты -> hex, out: 2 * n + 1 */
char *VGB_exclud(const unsigned char *bytes, size_t n, char *out);
/* hex -> байты, (size_t) -1 при нечётной длине или не-hex символе */
size_t VGB_restore(const char *printable, unsigned char *bytes);
uint32_t VGB_random(uint32_t *state);
/* seed -> ненулевое 32-битное состояние генератора */
uint32_t VGB_seed_state(uint64_t seed);

/* 0 - ok, -1 - не открыть вход, -2 - не открыть выход, -3 - ошибка чтения/записи,
   -4 - пустой ключ, -5 - нет заголовка с seed */
int VGB_encrypt_file(const char *in_path, const char *out_path, const char *key, uint64_t seed);
int VGB_decrypt_file(const char *in_path, const char *out_path, const char *key);

#endif
