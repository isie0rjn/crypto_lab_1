#ifndef CRYPTO_LAB_1_CSK_H
#define CRYPTO_LAB_1_CSK_H

/* keystream должен вмещать strlen(alphabet) + 1 */
char *CSK_keygen(const char *key, const char *alphabet, char *keystream);
/* extended: 0 - letters, 1 - letters2 (A-Z a-z 0-9) */
char *CSK_encrypt(const char *message, const char *key, int extended, char *out);
char *CSK_decrypt(const char *message, const char *key, int extended, char *out);
/* 0 - ключ непустой и весь из алфавита, -1 - нет */
int CSK_check_key(const char *key, int extended);

#endif
