#ifndef CRYPTO_LAB_1_CSR_H
#define CRYPTO_LAB_1_CSR_H

/* табличный метод, символы вне алфавита копируются как есть */
char *CSR_encrypt(const char *message, int key, char *out);
char *CSR_decrypt(const char *message, int key, char *out);
/* (m +- k) mod 26 */
char *CSR_enc_math(const char *message, int key, char *out);
char *CSR_dec_math(const char *message, int key, char *out);

#endif
