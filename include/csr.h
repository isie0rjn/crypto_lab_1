//
// Created by Владимир on 10.10.2026.
//

#ifndef CRYPTO_LAB_1_CSR_H
#define CRYPTO_LAB_1_CSR_H

void CSR_encrypt(const char *message, int key, char *out);
void CSR_decrypt(const char *message, int key, char *out);
void CSR_enc_math(const char *message, int key, char *out);
void CSR_dec_math(const char *message, int key, char *out);

#endif //CRYPTO_LAB_1_CSR_H