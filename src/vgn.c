#include "vgn.h"

#include <string.h>

#include "util.h"
#include "vars.h"

static const char letters3[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%^&*()-_=+[]{};:,.<>/?";

static const char *pick_alphabet(int extended) {
    return extended ? letters3 : letters;
}

/* sign = +1 шифрование, -1 расшифровка; extra - добавка к каждому сдвигу ключа */
static char *vgn_run(const char *message, const char *key, const char *alphabet,
                     int extra, int sign, char *out) {
    int len = (int) strlen(alphabet);
    size_t key_len = strlen(key);
    size_t i, j = 0;

    for (i = 0; message[i] != '\0'; i++) {
        int m = alpha_index(alphabet, message[i]);
        if (m < 0) {
            out[i] = message[i];
            continue;
        }
        int k = alpha_index(alphabet, key[j]) + extra;
        out[i] = alphabet[mod_int(m + sign * k, len)];
        /* позиция ключа двигается только на преобразованных символах */
        j = (j + 1) % key_len;
    }
    out[i] = '\0';
    return out;
}

int VGN_check_key(const char *key, int extended) {
    const char *alphabet = pick_alphabet(extended);

    if (key == NULL || *key == '\0')
        return -1;
    for (; *key != '\0'; key++) {
        if (alpha_index(alphabet, *key) < 0)
            return -1;
    }
    return 0;
}

char *VGN_encrypt(const char *message, const char *key, int extended, char *out) {
    return vgn_run(message, key, pick_alphabet(extended), 0, 1, out);
}

char *VGN_decrypt(const char *message, const char *key, int extended, char *out) {
    return vgn_run(message, key, pick_alphabet(extended), 0, -1, out);
}
