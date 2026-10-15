#include "csr.h"

#include <string.h>

#include "util.h"
#include "vars.h"

char *CSR_encrypt(const char *message, int key, char *out) {
    int len = (int) strlen(letters);
    size_t i;

    key = mod_int(key, len);
    for (i = 0; message[i] != '\0'; i++) {
        int index = alpha_index(letters, message[i]);
        if (index < 0) {
            out[i] = message[i];
            continue;
        }
        /* сдвиг вышел за конец алфавита - заходим с начала */
        if (index + key < len)
            out[i] = letters[index + key];
        else
            out[i] = letters[index + key - len];
    }
    out[i] = '\0';
    return out;
}

char *CSR_decrypt(const char *message, int key, char *out) {
    int len = (int) strlen(letters);
    size_t i;

    key = mod_int(key, len);
    for (i = 0; message[i] != '\0'; i++) {
        int index = alpha_index(letters, message[i]);
        if (index < 0) {
            out[i] = message[i];
            continue;
        }
        if (index - key >= 0)
            out[i] = letters[index - key];
        else
            out[i] = letters[index - key + len];
    }
    out[i] = '\0';
    return out;
}

char *CSR_enc_math(const char *message, int key, char *out) {
    int len = (int) strlen(letters);
    size_t i;

    for (i = 0; message[i] != '\0'; i++) {
        int index = alpha_index(letters, message[i]);
        out[i] = (index < 0) ? message[i] : letters[mod_int(index + key, len)];
    }
    out[i] = '\0';
    return out;
}

char *CSR_dec_math(const char *message, int key, char *out) {
    int len = (int) strlen(letters);
    size_t i;

    for (i = 0; message[i] != '\0'; i++) {
        int index = alpha_index(letters, message[i]);
        out[i] = (index < 0) ? message[i] : letters[mod_int(index - key, len)];
    }
    out[i] = '\0';
    return out;
}
