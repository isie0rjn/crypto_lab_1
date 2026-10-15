#ifndef CRYPTO_LAB_1_VGN_H
#define CRYPTO_LAB_1_VGN_H

#include <stdint.h>

/* extended: 0 - letters, 1 - letters3 (A-Z a-z 0-9 и знаки) */
char *VGN_encrypt(const char *message, const char *key, int extended, char *out);
char *VGN_decrypt(const char *message, const char *key, int extended, char *out);
/* только алфавит letters, к каждой букве ключа добавляется seed mod 26 */
char *VGN_encrypt_seed(const char *message, const char *key, uint64_t seed, char *out);
char *VGN_decrypt_seed(const char *message, const char *key, uint64_t seed, char *out);
/* 0 - ключ непустой и весь из алфавита, -1 - нет */
int VGN_check_key(const char *key, int extended);

#endif
