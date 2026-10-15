#include "csk.h"

#include <string.h>

#include "util.h"
#include "vars.h"

static const char letters2[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789";

static const char *pick_alphabet(int extended) {
    return extended ? letters2 : letters;
}

/* ключ ставится в начало алфавита, повторы выкидываются */
char *CSK_keygen(const char *key, const char *alphabet, char *keystream) {
    const char *parts[2] = {key, alphabet};
    size_t n = 0;

    for (int p = 0; p < 2; p++) {
        for (const char *c = parts[p]; *c != '\0'; c++) {
            if (alpha_index(alphabet, *c) < 0)
                continue;
            if (n > 0 && memchr(keystream, *c, n) != NULL)
                continue;
            keystream[n++] = *c;
        }
    }
    keystream[n] = '\0';
    return keystream;
}

int CSK_check_key(const char *key, int extended) {
    const char *alphabet = pick_alphabet(extended);

    if (key == NULL || *key == '\0')
        return -1;
    for (; *key != '\0'; key++) {
        if (alpha_index(alphabet, *key) < 0)
            return -1;
    }
    return 0;
}

char *CSK_encrypt(const char *message, const char *key, int extended, char *out) {
    const char *alphabet = pick_alphabet(extended);
    char keystream[sizeof letters2];
    size_t i;

    CSK_keygen(key, alphabet, keystream);
    for (i = 0; message[i] != '\0'; i++) {
        int index = alpha_index(alphabet, message[i]);
        out[i] = (index < 0) ? message[i] : keystream[index];
    }
    out[i] = '\0';
    return out;
}

char *CSK_decrypt(const char *message, const char *key, int extended, char *out) {
    const char *alphabet = pick_alphabet(extended);
    char keystream[sizeof letters2];
    size_t i;

    CSK_keygen(key, alphabet, keystream);
    for (i = 0; message[i] != '\0'; i++) {
        int index = alpha_index(keystream, message[i]);
        out[i] = (index < 0) ? message[i] : alphabet[index];
    }
    out[i] = '\0';
    return out;
}
