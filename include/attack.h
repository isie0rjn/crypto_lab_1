#ifndef CRYPTO_LAB_1_ATTACK_H
#define CRYPTO_LAB_1_ATTACK_H

#include <stdint.h>

/* атаки на VGN с seed; в расчёт идут только буквы A-Z */

/* период или -1 (разное число букв), -2 (период больше max_period) */
int ATK_known_plaintext(const char *plain, const char *cipher, char *eff_key, int max_period);
/* период по IoC, сдвиги по chi^2; -1 - слишком мало букв */
int ATK_ciphertext_only(const char *cipher, char *eff_key, char *plain);
/* seed_residue[0..2] - три лучших остатка seed mod 26, plain - текст для лучшего; -1 - нет букв */
int ATK_seed_bruteforce(const char *cipher, const char *key, uint64_t *seed_residue, char *plain);

int ATK_letter_count(const char *text);
/* chi^2 частот букв текста против английского, меньше - ближе */
double ATK_chi2(const char *text);
/* средний индекс совпадений по столбцам при данном периоде */
double ATK_ioc(const char *cipher, int period);
/* период по повторам триграмм, 0 - повторов нет */
int ATK_kasiski(const char *cipher, int max_period);
/* английский текст для демонстрации, только A-Z и пробелы */
const char *ATK_sample(void);

#endif
