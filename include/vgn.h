#ifndef CRYPTO_LAB_1_VGN_H
#define CRYPTO_LAB_1_VGN_H

/* extended: 0 - letters, 1 - letters3 (A-Z a-z 0-9 и знаки) */
char *VGN_encrypt(const char *message, const char *key, int extended, char *out);
char *VGN_decrypt(const char *message, const char *key, int extended, char *out);
/* 0 - ключ непустой и весь из алфавита, -1 - нет */
int VGN_check_key(const char *key, int extended);

#endif
