//
// Created by Владимир on 10.10.2026.
//

#include "csr.h"

#include <stdio.h>
#include <string.h>

#include "vars.h"

static int mod(int a, int n) {
    int r = a % n;
    return (r < 0) ? r + n : r;
}

void CSR_encrypt(const char *message, int key, char *out) {
    size_t message_len = strlen(message);
    size_t letters_len = strlen(letters);

    for (int i = 0; i < message_len; i++) {
        for (int j = 0; j < letters_len; j++) {
            if (message[i] == letters[j]) {
                out[i] = letters[mod((j + key), (int) letters_len)];
                break;
            }
        }
    }
    out[message_len] = '\0';
}

void CSR_decrypt(const char *message, int key, char *out) {
    size_t message_len = strlen(message);
    size_t letters_len = strlen(letters);

    for (int i = 0; i < message_len; i++) {
        for (int j = 0; j < letters_len; j++) {
            if (message[i] == letters[j]) {
                out[i] = letters[mod((j - key), (int) letters_len)];
                break;
            }
        }
    }
    out[message_len] = '\0';
}

void CSR_enc_math(const char *message, int key, char *out) {

}

void CSR_dec_math(const char *message, int key, char *out) {

}

