#include "attack.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "vars.h"
#include "vgn.h"

#define ALPHA 26
#define COA_MAX_PERIOD 16
#define MAX_TEXT 4096

/* частоты букв английского текста, % */
static const double english[ALPHA] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074
};

static const char sample[] =
    "THE HISTORY OF SECRET WRITING IS AS OLD AS WRITING ITSELF AND FOR MOST OF THAT "
    "TIME THE ADVANTAGE BELONGED TO THE PEOPLE WHO MADE CIPHERS RATHER THAN TO THOSE "
    "WHO TRIED TO BREAK THEM A SIMPLE SHIFT OF THE ALPHABET WAS ENOUGH TO HIDE A "
    "MESSAGE FROM A CURIOUS MESSENGER BUT IT COULD NOT STAND AGAINST A PATIENT READER "
    "WHO COUNTED HOW OFTEN EACH LETTER APPEARED IN THE TEXT THE POLYALPHABETIC CIPHER "
    "WAS INVENTED TO DEFEAT THIS KIND OF COUNTING BECAUSE THE SAME LETTER OF THE "
    "MESSAGE IS REPLACED BY DIFFERENT LETTERS DEPENDING ON ITS POSITION FOR SEVERAL "
    "CENTURIES IT WAS CALLED THE INDECIPHERABLE CIPHER UNTIL CAREFUL STUDENTS OF THE "
    "PROBLEM NOTICED THAT THE KEY REPEATS AND THAT REPEATED FRAGMENTS OF THE PLAIN "
    "TEXT OFTEN MEET THE SAME PART OF THE KEY WHEN THE LENGTH OF THE KEY IS KNOWN THE "
    "CIPHERTEXT FALLS APART INTO SEVERAL SIMPLE SHIFT CIPHERS AND EACH OF THEM IS "
    "SOLVED BY FREQUENCY ANALYSIS IN A FEW MINUTES WITH PAPER AND PENCIL TODAY A "
    "COMPUTER DOES THE SAME WORK FASTER THAN A PERSON CAN READ THE RESULT";

const char *ATK_sample(void) {
    return sample;
}

/* индексы букв текста в letters, прочие символы пропускаются */
static int letters_of(const char *text, int *idx, int max) {
    int n = 0;

    for (; *text != '\0' && n < max; text++) {
        int i = alpha_index(letters, *text);
        if (i >= 0)
            idx[n++] = i;
    }
    return n;
}

int ATK_letter_count(const char *text) {
    int n = 0;

    for (; *text != '\0'; text++) {
        if (alpha_index(letters, *text) >= 0)
            n++;
    }
    return n;
}

static double chi2_counts(const int *count, int total) {
    double chi = 0.0;

    for (int i = 0; i < ALPHA; i++) {
        double expected = total * english[i] / 100.0;
        double d = count[i] - expected;
        chi += d * d / expected;
    }
    return chi;
}

double ATK_chi2(const char *text) {
    int count[ALPHA] = {0};
    int total = 0;

    for (; *text != '\0'; text++) {
        int i = alpha_index(letters, *text);
        if (i >= 0) {
            count[i]++;
            total++;
        }
    }
    return (total == 0) ? 1e30 : chi2_counts(count, total);
}

static double ioc_of(const int *idx, int n, int period) {
    double sum = 0.0;
    int columns = 0;

    for (int c = 0; c < period; c++) {
        int count[ALPHA] = {0};
        int len = 0;
        for (int i = c; i < n; i += period) {
            count[idx[i]]++;
            len++;
        }
        if (len < 2)
            continue;
        long pairs = 0;
        for (int k = 0; k < ALPHA; k++)
            pairs += (long) count[k] * (count[k] - 1);
        sum += (double) pairs / ((double) len * (len - 1));
        columns++;
    }
    return (columns == 0) ? 0.0 : sum / columns;
}

double ATK_ioc(const char *cipher, int period) {
    static int idx[MAX_TEXT];
    int n = letters_of(cipher, idx, MAX_TEXT);

    return ioc_of(idx, n, period);
}

/* расстояния между повторами триграмм делятся на период; счёт нормируем на P,
   иначе всегда выигрывают маленькие делители */
int ATK_kasiski(const char *cipher, int max_period) {
    static int idx[MAX_TEXT];
    int n = letters_of(cipher, idx, MAX_TEXT);
    long hits[COA_MAX_PERIOD + 1] = {0};
    int repeats = 0;

    if (max_period > COA_MAX_PERIOD)
        max_period = COA_MAX_PERIOD;
    for (int i = 0; i + 2 < n; i++) {
        for (int j = i + 1; j + 2 < n; j++) {
            if (idx[i] != idx[j] || idx[i + 1] != idx[j + 1] || idx[i + 2] != idx[j + 2])
                continue;
            repeats++;
            for (int p = 2; p <= max_period; p++) {
                if ((j - i) % p == 0)
                    hits[p]++;
            }
        }
    }
    if (repeats < 2)
        return 0;

    long best_score = 0;
    for (int p = 2; p <= max_period; p++) {
        if (hits[p] * p > best_score)
            best_score = hits[p] * p;
    }
    /* кратные периоду набирают почти тот же счёт, берём самый короткий из близких к лучшему */
    for (int p = 2; p <= max_period; p++) {
        if (best_score > 0 && hits[p] * p * 5 >= best_score * 4)
            return p;
    }
    return 0;
}

int ATK_known_plaintext(const char *plain, const char *cipher, char *eff_key, int max_period) {
    static int pi[MAX_TEXT], ci[MAX_TEXT], shift[MAX_TEXT];
    int n = letters_of(plain, pi, MAX_TEXT);

    if (letters_of(cipher, ci, MAX_TEXT) != n || n == 0)
        return -1;
    for (int i = 0; i < n; i++)
        shift[i] = mod_int(ci[i] - pi[i], ALPHA);

    /* самый короткий период, с которым согласованы все сдвиги */
    for (int period = 1; period <= max_period && period <= n; period++) {
        int ok = 1;
        for (int i = period; i < n && ok; i++)
            ok = shift[i] == shift[i % period];
        if (!ok)
            continue;
        for (int j = 0; j < period; j++)
            eff_key[j] = letters[shift[j]];
        eff_key[period] = '\0';
        return period;
    }
    return -2;
}

int ATK_ciphertext_only(const char *cipher, char *eff_key, char *plain) {
    static int idx[MAX_TEXT];
    int n = letters_of(cipher, idx, MAX_TEXT);
    int max_period = n / 2;

    if (n < 4)
        return -1;
    if (max_period > COA_MAX_PERIOD)
        max_period = COA_MAX_PERIOD;

    /* английский даёт IoC около 0.066, случайный текст 0.038; берём первый период выше порога,
       кратные периоды тоже проходят порог, но они длиннее */
    int period = 1;
    double best = -1.0;
    for (int p = 1; p <= max_period; p++) {
        double ioc = ioc_of(idx, n, p);
        if (ioc >= 0.058) {
            period = p;
            break;
        }
        if (ioc > best) {
            best = ioc;
            period = p;
        }
    }

    for (int c = 0; c < period; c++) {
        int count[ALPHA] = {0};
        int len = 0;
        for (int i = c; i < n; i += period) {
            count[idx[i]]++;
            len++;
        }
        int best_shift = 0;
        double best_chi = 1e30;
        for (int s = 0; s < ALPHA; s++) {
            int shifted[ALPHA];
            for (int k = 0; k < ALPHA; k++)
                shifted[k] = count[(k + s) % ALPHA];
            double chi = chi2_counts(shifted, len);
            if (chi < best_chi) {
                best_chi = chi;
                best_shift = s;
            }
        }
        eff_key[c] = letters[best_shift];
    }
    eff_key[period] = '\0';
    VGN_decrypt(cipher, eff_key, 0, plain);
    return period;
}

int ATK_seed_bruteforce(const char *cipher, const char *key, uint64_t *seed_residue, char *plain) {
    double chi[ALPHA];
    int order[ALPHA];
    char *tmp = malloc(strlen(cipher) + 1);

    if (tmp == NULL || ATK_letter_count(cipher) == 0) {
        free(tmp);
        return -1;
    }
    /* значим только seed mod 26, так что вариантов всего 26 */
    for (int s = 0; s < ALPHA; s++) {
        VGN_decrypt_seed(cipher, key, (uint64_t) s, tmp);
        chi[s] = ATK_chi2(tmp);
        order[s] = s;
    }
    for (int i = 1; i < ALPHA; i++) {
        int v = order[i], j = i;
        for (; j > 0 && chi[order[j - 1]] > chi[v]; j--)
            order[j] = order[j - 1];
        order[j] = v;
    }
    for (int i = 0; i < 3; i++)
        seed_residue[i] = (uint64_t) order[i];
    VGN_decrypt_seed(cipher, key, seed_residue[0], plain);
    free(tmp);
    return 3;
}
