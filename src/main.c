#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

#include "attack.h"
#include "csk.h"
#include "csr.h"
#include "expmod.h"
#include "gf.h"
#include "invmod.h"
#include "logdis.h"
#include "util.h"
#include "vars.h"
#include "vgb.h"
#include "vgn.h"

enum {
    EXIT_ILLEGAL = 1,
    EXIT_NO_ARG = 2,
    EXIT_NOTHING = 3,
    EXIT_COUNT = 4,
    EXIT_NUMBER = 5,
    EXIT_ALGO = 6
};

#define MAX_PERIOD_KPA 64

static char prog[64] = "crypto";

static const char *const msg_options[] = {
    "-Ecsr", "-Dcsr", "-Ecsrm", "-Dcsrm",
    "-Ecsk", "-Dcsk", "-Ecskx", "-Dcskx",
    "-Evgn", "-Dvgn", "-Evgnx", "-Dvgnx",
    "-Evgns", "-Dvgns", "-Evgb", "-Dvgb"
};

struct multi_option {
    const char *name;
    const char *usage;
};

static const struct multi_option multi_options[] = {
    {"-GF", "-GF pm|poly|tbl A B  or  -GF inv A  (A, B in hex)"},
    {"-ME", "-ME rlbe|lrbe|ml|swe A K N"},
    {"-MI", "-MI eea|ferma|gcd B N"},
    {"-DL", "-DL br|bsgs|pollard|ph|ic A B P"},
    {"-Dl", "-Dl br|bsgs|pollard|ph|ic A B P"},
    {"-ATK", "-ATK coa CIPHER  |  -ATK kpa PLAIN CIPHER  |  -ATK seed CIPHER"},
    {"-Efvgb", "-Efvgb IN OUT"},
    {"-Dfvgb", "-Dfvgb IN OUT"},
    {NULL, NULL}
};

static void set_prog_name(const char *argv0) {
    const char *base = argv0;

    if (argv0 == NULL)
        return;
    for (const char *p = argv0; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    size_t len = strlen(base);
    if (len >= 4 && (strcmp(base + len - 4, ".exe") == 0 || strcmp(base + len - 4, ".EXE") == 0))
        len -= 4;
    if (len == 0 || len >= sizeof prog)
        return;
    memcpy(prog, base, len);
    prog[len] = '\0';
}

static int fail(int code, const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "%s: ", prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return code;
}

/* при вводе через pipe печатаем прочитанное, чтобы вывод выглядел как в интерактиве */
static int read_line(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int) size, stdin) == NULL) {
        buf[0] = '\0';
        if (!isatty(fileno(stdin)))
            putchar('\n');
        return -1;
    }
    buf[strcspn(buf, "\r\n")] = '\0';
    /* powershell при перенаправлении может дописать BOM */
    if ((unsigned char) buf[0] == 0xEF && (unsigned char) buf[1] == 0xBB && (unsigned char) buf[2] == 0xBF)
        memmove(buf, buf + 3, strlen(buf + 3) + 1);
    if (!isatty(fileno(stdin)))
        printf("%s\n", buf);
    return 0;
}

static int is_msg_option(const char *option) {
    for (size_t i = 0; i < sizeof msg_options / sizeof msg_options[0]; i++) {
        if (strcmp(option, msg_options[i]) == 0)
            return 1;
    }
    return 0;
}

static const struct multi_option *find_multi_option(const char *option) {
    for (size_t i = 0; multi_options[i].name != NULL; i++) {
        if (strcmp(option, multi_options[i].name) == 0)
            return &multi_options[i];
    }
    return NULL;
}

static void usage(void) {
    printf("usage: %s OPTION ARGS...\n"
           "  -Ecsr  | -Dcsr  MESSAGE      Caesar, table method\n"
           "  -Ecsrm | -Dcsrm MESSAGE      Caesar, math method\n"
           "  -Ecsk  | -Dcsk  MESSAGE      Caesar with keyword, A-Z\n"
           "  -Ecskx | -Dcskx MESSAGE      Caesar with keyword, A-Z a-z 0-9\n"
           "  -Evgn  | -Dvgn  MESSAGE      Vigenere, A-Z\n"
           "  -Evgnx | -Dvgnx MESSAGE      Vigenere, A-Z a-z 0-9 and signs\n"
           "  -Evgns | -Dvgns MESSAGE      Vigenere with seed, A-Z\n"
           "  -Evgb  | -Dvgb  MESSAGE      Vigenere with XOR, ciphertext in hex\n"
           "  -Efvgb | -Dfvgb IN OUT       Vigenere with XOR for files\n"
           "  -GF pm|poly|tbl A B          A*B in GF(2^8), hex\n"
           "  -GF inv A                    A^-1 in GF(2^8), hex\n"
           "  -ME rlbe|lrbe|ml|swe A K N   A^K mod N\n"
           "  -MI eea|ferma|gcd B N        B^-1 mod N\n"
           "  -DL br|bsgs|pollard|ph|ic A B P\n"
           "                               x: A^x = B (mod P)\n"
           "  -ATK coa CIPHER              ciphertext-only attack on seeded Vigenere\n"
           "  -ATK kpa PLAIN CIPHER        known-plaintext attack on seeded Vigenere\n"
           "  -ATK seed CIPHER             seed brute force with a known key\n"
           "  -BENCH                       timing of all GF, EXP, INV and DL methods\n"
           "  -h, --help                   this text\n"
           "keys and seeds are read from stdin after the prompts 'key: ' and 'seed: ';\n"
           "an empty seed on encryption means the current time\n",
           prog);
}

/* ---------- part 2: classical ciphers ---------- */

static int read_shift_key(int *key) {
    char line[128];
    int64_t value;

    if (read_line("key: ", line, sizeof line) != 0 || line[0] == '\0')
        return fail(EXIT_NUMBER, "no key given");
    if (parse_i64(line, &value) != 0)
        return fail(EXIT_NUMBER, "invalid number: %s", line);
    int len = (int) strlen(letters);
    *key = mod_int((int) (value % len), len);
    return 0;
}

static int read_word_key(char *key, size_t size, int (*check)(const char *, int), int extended) {
    if (read_line("key: ", key, size) != 0 || key[0] == '\0')
        return fail(EXIT_NUMBER, "no key given");
    if (check(key, extended) != 0)
        return fail(EXIT_NUMBER, "invalid key: %s (characters outside the alphabet)", key);
    return 0;
}

static int read_any_key(char *key, size_t size) {
    if (read_line("key: ", key, size) != 0 || key[0] == '\0')
        return fail(EXIT_NUMBER, "no key given");
    return 0;
}

static int read_seed(uint64_t *seed, int allow_empty) {
    char line[64];

    if (read_line("seed: ", line, sizeof line) != 0 || line[0] == '\0') {
        if (!allow_empty)
            return fail(EXIT_NUMBER, "no seed given");
        *seed = (uint64_t) time(NULL);
        printf("seed: %llu\n", (unsigned long long) *seed);
        return 0;
    }
    if (parse_u64(line, seed, 0) != 0)
        return fail(EXIT_NUMBER, "invalid number: %s", line);
    return 0;
}

static int run_message(const char *option, const char *message) {
    /* hex у VGB вдвое длиннее сообщения */
    size_t out_size = 2 * strlen(message) + 1;
    char *out = malloc(out_size);
    char key[256];
    uint64_t seed = 0;
    int rc = 0;
    int shift = 0;

    if (out == NULL)
        return fail(EXIT_ALGO, "out of memory");

    if (strcmp(option, "-Ecsr") == 0 || strcmp(option, "-Dcsr") == 0
        || strcmp(option, "-Ecsrm") == 0 || strcmp(option, "-Dcsrm") == 0) {
        int encrypt = option[1] == 'E';
        int math = option[5] == 'm';
        if ((rc = read_shift_key(&shift)) == 0) {
            if (encrypt && math)
                CSR_enc_math(message, shift, out);
            else if (encrypt)
                CSR_encrypt(message, shift, out);
            else if (math)
                CSR_dec_math(message, shift, out);
            else
                CSR_decrypt(message, shift, out);
            printf("%s: %s\n", encrypt ? "enc" : "dec", out);
        }
    } else if (strcmp(option, "-Ecsk") == 0 || strcmp(option, "-Dcsk") == 0
               || strcmp(option, "-Ecskx") == 0 || strcmp(option, "-Dcskx") == 0) {
        int encrypt = option[1] == 'E';
        int extended = option[5] == 'x';
        if ((rc = read_word_key(key, sizeof key, CSK_check_key, extended)) == 0) {
            if (encrypt)
                CSK_encrypt(message, key, extended, out);
            else
                CSK_decrypt(message, key, extended, out);
            printf("%s: %s\n", encrypt ? "enc" : "dec", out);
        }
    } else if (strcmp(option, "-Evgn") == 0 || strcmp(option, "-Dvgn") == 0
               || strcmp(option, "-Evgnx") == 0 || strcmp(option, "-Dvgnx") == 0) {
        int encrypt = option[1] == 'E';
        int extended = option[5] == 'x';
        if ((rc = read_word_key(key, sizeof key, VGN_check_key, extended)) == 0) {
            if (encrypt)
                VGN_encrypt(message, key, extended, out);
            else
                VGN_decrypt(message, key, extended, out);
            printf("%s: %s\n", encrypt ? "enc" : "dec", out);
        }
    } else if (strcmp(option, "-Evgns") == 0 || strcmp(option, "-Dvgns") == 0) {
        int encrypt = option[1] == 'E';
        if ((rc = read_word_key(key, sizeof key, VGN_check_key, 0)) == 0
            && (rc = read_seed(&seed, encrypt)) == 0) {
            if (encrypt)
                VGN_encrypt_seed(message, key, seed, out);
            else
                VGN_decrypt_seed(message, key, seed, out);
            printf("%s: %s\n", encrypt ? "enc" : "dec", out);
        }
    } else if (strcmp(option, "-Evgb") == 0 || strcmp(option, "-Dvgb") == 0) {
        int encrypt = option[1] == 'E';
        if ((rc = read_any_key(key, sizeof key)) == 0 && (rc = read_seed(&seed, encrypt)) == 0) {
            if (encrypt) {
                VGB_encrypt(message, key, seed, out);
                printf("enc: %s\n", out);
            } else if (VGB_decrypt(message, key, seed, out) == NULL) {
                rc = fail(EXIT_NUMBER, "invalid hex: %s", message);
            } else {
                printf("dec: %s\n", out);
            }
        }
    }

    free(out);
    return rc;
}

/* ---------- part 3: number theory ---------- */

static int wrong_count(const struct multi_option *opt) {
    fail(EXIT_COUNT, "wrong number of arguments for %s", opt->name);
    fprintf(stderr, "usage: %s %s\n", prog, opt->usage);
    return EXIT_COUNT;
}

static int get_u64(const char *s, uint64_t *v, int hex) {
    if (parse_u64(s, v, hex) != 0)
        return fail(EXIT_NUMBER, "invalid number: %s", s);
    return 0;
}

static int get_byte(const char *s, uint8_t *v) {
    uint64_t x;

    if (parse_u64(s, &x, 1) != 0 || x > 0xFF)
        return fail(EXIT_NUMBER, "invalid number: %s", s);
    *v = (uint8_t) x;
    return 0;
}

static int run_gf(const struct multi_option *opt, int argc, char *argv[]) {
    uint8_t a, b, r;
    int rc;

    if (argc < 4)
        return wrong_count(opt);
    const char *method = argv[2];

    if (strcmp(method, "inv") == 0) {
        if (argc != 4)
            return wrong_count(opt);
        if ((rc = get_byte(argv[3], &a)) != 0)
            return rc;
        r = GF_inv(a);
        printf("result: 0x%02X\n", r);
        if (a != 0)
            printf("check: 0x%02X * 0x%02X = 0x%02X\n", a, r, GF_mul_peasant(a, r));
        return 0;
    }

    if (strcmp(method, "pm") != 0 && strcmp(method, "poly") != 0 && strcmp(method, "tbl") != 0)
        return fail(EXIT_ILLEGAL, "illegal method for %s: %s", opt->name, method);
    if (argc != 5)
        return wrong_count(opt);
    if ((rc = get_byte(argv[3], &a)) != 0 || (rc = get_byte(argv[4], &b)) != 0)
        return rc;
    if (strcmp(method, "pm") == 0)
        r = GF_mul_peasant(a, b);
    else if (strcmp(method, "poly") == 0)
        r = GF_mul_poly(a, b);
    else
        r = GF_mul_table(a, b);
    printf("result: 0x%02X\n", r);
    return 0;
}

static int run_expmod(const struct multi_option *opt, int argc, char *argv[]) {
    uint64_t a, k, n, r;
    int rc;

    if (argc != 6)
        return wrong_count(opt);
    const char *method = argv[2];
    if ((rc = get_u64(argv[3], &a, 0)) != 0 || (rc = get_u64(argv[4], &k, 0)) != 0
        || (rc = get_u64(argv[5], &n, 0)) != 0)
        return rc;
    if (n == 0)
        return fail(EXIT_NUMBER, "invalid number: %s (modulus must be positive)", argv[5]);

    if (strcmp(method, "rlbe") == 0)
        r = EXP_rtl(a, k, n);
    else if (strcmp(method, "lrbe") == 0)
        r = EXP_ltr(a, k, n);
    else if (strcmp(method, "ml") == 0)
        r = EXP_ladder(a, k, n);
    else if (strcmp(method, "swe") == 0)
        r = EXP_window(a, k, n, 4);
    else
        return fail(EXIT_ILLEGAL, "illegal method for %s: %s", opt->name, method);

    printf("result: %llu\n", (unsigned long long) r);
    return 0;
}

static int inv_error(int code) {
    switch (code) {
    case -1:
        return fail(EXIT_ALGO, "inverse does not exist (gcd != 1)");
    case -2:
        return fail(EXIT_ALGO, "modulus is not prime, fermat method is not applicable");
    case -3:
        return fail(EXIT_ALGO, "binary method needs an odd modulus");
    case -4:
        return fail(EXIT_NUMBER, "modulus must be >= 2");
    default:
        return fail(EXIT_ALGO, "unknown error %d", code);
    }
}

static int run_invmod(const struct multi_option *opt, int argc, char *argv[]) {
    int64_t b, n, inv = 0;
    int code;

    if (argc != 5)
        return wrong_count(opt);
    const char *method = argv[2];
    if (parse_i64(argv[3], &b) != 0)
        return fail(EXIT_NUMBER, "invalid number: %s", argv[3]);
    if (parse_i64(argv[4], &n) != 0)
        return fail(EXIT_NUMBER, "invalid number: %s", argv[4]);

    if (strcmp(method, "eea") == 0)
        code = INV_eea_trace(b, n, &inv, stdout);
    else if (strcmp(method, "ferma") == 0)
        code = INV_fermat(b, n, &inv);
    else if (strcmp(method, "gcd") == 0)
        code = INV_binary(b, n, &inv);
    else
        return fail(EXIT_ILLEGAL, "illegal method for %s: %s", opt->name, method);

    if (code != 0)
        return inv_error(code);
    printf("result: %lld\n", (long long) inv);
    printf("%lld * %lld === 1 (mod %lld)\n", (long long) b, (long long) inv, (long long) n);
    return 0;
}

static int run_logdis(const struct multi_option *opt, int argc, char *argv[]) {
    uint64_t a, b, p, x = 0;
    int rc, code;

    if (argc != 6)
        return wrong_count(opt);
    const char *method = argv[2];
    if ((rc = get_u64(argv[3], &a, 0)) != 0 || (rc = get_u64(argv[4], &b, 0)) != 0
        || (rc = get_u64(argv[5], &p, 0)) != 0)
        return rc;

    if (strcmp(method, "br") == 0)
        code = DL_brute(a, b, p, &x);
    else if (strcmp(method, "bsgs") == 0)
        code = DL_bsgs(a, b, p, &x);
    else if (strcmp(method, "pollard") == 0)
        code = DL_rho(a, b, p, &x);
    else if (strcmp(method, "ph") == 0)
        code = DL_ph(a, b, p, &x);
    else if (strcmp(method, "ic") == 0)
        code = DL_ic(a, b, p, &x);
    else
        return fail(EXIT_ILLEGAL, "illegal method for %s: %s", opt->name, method);

    switch (code) {
    case 0:
        break;
    case -1:
        return fail(EXIT_ALGO, "no solution: %llu is not a power of %llu mod %llu",
                    (unsigned long long) b, (unsigned long long) a, (unsigned long long) p);
    case -2:
        return fail(EXIT_ALGO, "invalid input: p must be prime, a and b nonzero mod p");
    default:
        if (strcmp(method, "ic") == 0)
            return fail(EXIT_ALGO, "method ic failed (it needs a primitive root as the base)");
        return fail(EXIT_ALGO, "method %s failed", method);
    }
    printf("result: %llu\n", (unsigned long long) x);
    printf("%llu ^ %llu === %llu (mod %llu)\n", (unsigned long long) a, (unsigned long long) x,
           (unsigned long long) b, (unsigned long long) p);
    return 0;
}

/* ---------- case studies: attacks (3.8), files for VGB (4.1) ---------- */

static void print_head(const char *label, const char *text, size_t max) {
    size_t len = strlen(text);

    printf("%s%.*s%s\n", label, (int) (len < max ? len : max), text, len > max ? "..." : "");
}

static void attack_report(const char *cipher) {
    char *plain = malloc(strlen(cipher) + 1);
    char eff_key[32];

    if (plain == NULL)
        return;
    int letters_count = ATK_letter_count(cipher);
    int kasiski = ATK_kasiski(cipher, 16);
    printf("letters: %d\n", letters_count);
    if (kasiski > 0)
        printf("kasiski: period %d\n", kasiski);
    else
        printf("kasiski: no repeated trigrams\n");
    int period = ATK_ciphertext_only(cipher, eff_key, plain);
    if (period < 0) {
        printf("too few letters for the attack\n");
        free(plain);
        return;
    }
    printf("period (ioc): %d, ioc = %.4f\n", period, ATK_ioc(cipher, period));
    printf("effective key: %s\n", eff_key);
    print_head("plain: ", plain, 70);
    free(plain);
}

static int run_attack(const struct multi_option *opt, int argc, char *argv[]) {
    if (argc < 3)
        return wrong_count(opt);
    const char *mode = argv[2];

    if (strcmp(mode, "kpa") == 0) {
        if (argc != 5)
            return wrong_count(opt);
        const char *plain = argv[3];
        const char *cipher = argv[4];
        char eff_key[MAX_PERIOD_KPA + 1];
        int period = ATK_known_plaintext(plain, cipher, eff_key, MAX_PERIOD_KPA);
        if (period == -1)
            return fail(EXIT_ALGO, "plain and cipher have a different number of letters");
        if (period < 0)
            return fail(EXIT_ALGO, "no period up to %d found, not a Vigenere ciphertext?", MAX_PERIOD_KPA);
        printf("period: %d\n", period);
        printf("effective key: %s\n", eff_key);
        printf("effective key = key + (seed mod 26), every pair below gives the same ciphertext:\n");
        int len = (int) strlen(letters);
        for (int s = 0; s < len; s++) {
            char key[MAX_PERIOD_KPA + 1];
            for (int j = 0; j < period; j++)
                key[j] = letters[mod_int(alpha_index(letters, eff_key[j]) - s, len)];
            key[period] = '\0';
            printf("  seed mod 26 = %2d -> key %s\n", s, key);
        }
        return 0;
    }
    if (argc != 4)
        return wrong_count(opt);
    const char *cipher = argv[3];

    if (strcmp(mode, "coa") == 0) {
        attack_report(cipher);
        if (ATK_letter_count(cipher) < 200)
            printf("note: %d letters is too short for reliable statistics, the result is a guess\n",
                   ATK_letter_count(cipher));

        /* демонстрация на длинном тексте с известными ключом и seed */
        const char *sample = ATK_sample();
        char *sample_cipher = malloc(strlen(sample) + 1);
        if (sample_cipher == NULL)
            return fail(EXIT_ALGO, "out of memory");
        VGN_encrypt_seed(sample, "MTIME", 1644485555u, sample_cipher);
        printf("\ndemo: built-in English sample, key MTIME, seed 1644485555 (expected effective key XETXP)\n");
        print_head("cipher: ", sample_cipher, 70);
        attack_report(sample_cipher);
        free(sample_cipher);
        return 0;
    }
    if (strcmp(mode, "seed") == 0) {
        char key[256];
        uint64_t residues[3];
        int rc;
        if ((rc = read_word_key(key, sizeof key, VGN_check_key, 0)) != 0)
            return rc;
        char *plain = malloc(strlen(cipher) + 1);
        if (plain == NULL)
            return fail(EXIT_ALGO, "out of memory");
        if (ATK_seed_bruteforce(cipher, key, residues, plain) < 0) {
            free(plain);
            return fail(EXIT_ALGO, "no letters in the ciphertext");
        }
        for (int i = 0; i < 3; i++) {
            VGN_decrypt_seed(cipher, key, residues[i], plain);
            printf("rank %d: seed mod 26 = %2llu, chi2 = %8.1f, plain: %s\n", i + 1,
                   (unsigned long long) residues[i], ATK_chi2(plain), plain);
        }
        printf("result: %llu\n", (unsigned long long) residues[0]);
        free(plain);
        return 0;
    }
    return fail(EXIT_ILLEGAL, "illegal method for %s: %s", opt->name, mode);
}

static int run_vgb_file(const struct multi_option *opt, int argc, char *argv[]) {
    char key[256];
    uint64_t seed = 0;
    int rc;

    if (argc != 4)
        return wrong_count(opt);
    const char *in_path = argv[2];
    const char *out_path = argv[3];
    int encrypt = opt->name[1] == 'E';
    if (strcmp(in_path, out_path) == 0)
        return fail(EXIT_ALGO, "input and output must be different files");
    if ((rc = read_any_key(key, sizeof key)) != 0)
        return rc;
    if (encrypt && (rc = read_seed(&seed, 1)) != 0)
        return rc;

    int code = encrypt ? VGB_encrypt_file(in_path, out_path, key, seed)
                       : VGB_decrypt_file(in_path, out_path, key);
    switch (code) {
    case 0:
        printf("result: %s -> %s (%s)\n", in_path, out_path, encrypt ? "encrypted" : "decrypted");
        return 0;
    case -1:
        return fail(EXIT_ALGO, "cannot open input file: %s", in_path);
    case -2:
        return fail(EXIT_ALGO, "cannot open output file: %s", out_path);
    case -5:
        return fail(EXIT_ALGO, "input file is too short, no seed header");
    default:
        return fail(EXIT_ALGO, "read/write error");
    }
}

/* ---------- benchmark ---------- */

/* volatile на входах и на выходе, чтобы вызовы не выкинул и не вынес из цикла оптимизатор */
static volatile uint64_t bench_sink;
static volatile uint8_t gf_a = 0x57, gf_b = 0x83, gf_c = 0x53;
static volatile uint64_t exp_vec[4][3] = {
    {15, 4947, 31}, {7181, 2953, 9286}, {5617, 1234, 9627}, {4, 13, 497}
};
static volatile int64_t inv_vec[3][2] = {{7, 11}, {3, 11}, {1777, 2699}};
static volatile uint64_t dl_vec[2][3] = {{31, 3, 29}, {2, 22, 29}};

static void bench_gf_pm(void) { bench_sink += GF_mul_peasant(gf_a, gf_b); }
static void bench_gf_poly(void) { bench_sink += GF_mul_poly(gf_a, gf_b); }
static void bench_gf_tbl(void) { bench_sink += GF_mul_table(gf_a, gf_b); }
static void bench_gf_inv(void) { bench_sink += GF_inv(gf_c); }

#define BENCH_EXP(name, call)                                          \
    static void name(void) {                                           \
        for (int i = 0; i < 4; i++) {                                  \
            uint64_t b = exp_vec[i][0], e = exp_vec[i][1], m = exp_vec[i][2]; \
            bench_sink += call;                                        \
        }                                                              \
    }
BENCH_EXP(bench_exp_rtl, EXP_rtl(b, e, m))
BENCH_EXP(bench_exp_ltr, EXP_ltr(b, e, m))
BENCH_EXP(bench_exp_ladder, EXP_ladder(b, e, m))
BENCH_EXP(bench_exp_window, EXP_window(b, e, m, 4))

#define BENCH_INV(name, fn)                                            \
    static void name(void) {                                           \
        for (int i = 0; i < 3; i++) {                                  \
            int64_t r = 0;                                             \
            fn(inv_vec[i][0], inv_vec[i][1], &r);                      \
            bench_sink += (uint64_t) r;                                \
        }                                                              \
    }
BENCH_INV(bench_inv_eea, INV_eea)
BENCH_INV(bench_inv_fermat, INV_fermat)
BENCH_INV(bench_inv_binary, INV_binary)

#define BENCH_DL(name, fn)                                             \
    static void name(void) {                                           \
        for (int i = 0; i < 2; i++) {                                  \
            uint64_t r = 0;                                            \
            fn(dl_vec[i][0], dl_vec[i][1], dl_vec[i][2], &r);          \
            bench_sink += r;                                           \
        }                                                              \
    }
BENCH_DL(bench_dl_brute, DL_brute)
BENCH_DL(bench_dl_bsgs, DL_bsgs)
BENCH_DL(bench_dl_rho, DL_rho)
BENCH_DL(bench_dl_ph, DL_ph)
BENCH_DL(bench_dl_ic, DL_ic)

struct bench_case {
    const char *module;
    const char *method;
    void (*fn)(void);
    int calls;      /* вызовов метода за один fn() */
};

static const struct bench_case bench_cases[] = {
    {"GF", "pm", bench_gf_pm, 1},
    {"GF", "poly", bench_gf_poly, 1},
    {"GF", "tbl", bench_gf_tbl, 1},
    {"GF", "inv", bench_gf_inv, 1},
    {"EXP", "rlbe", bench_exp_rtl, 4},
    {"EXP", "lrbe", bench_exp_ltr, 4},
    {"EXP", "ml", bench_exp_ladder, 4},
    {"EXP", "swe", bench_exp_window, 4},
    {"INV", "eea", bench_inv_eea, 3},
    {"INV", "ferma", bench_inv_fermat, 3},
    {"INV", "gcd", bench_inv_binary, 3},
    {"DL", "br", bench_dl_brute, 2},
    {"DL", "bsgs", bench_dl_bsgs, 2},
    {"DL", "pollard", bench_dl_rho, 2},
    {"DL", "ph", bench_dl_ph, 2},
    {"DL", "ic", bench_dl_ic, 2},
};

/* число повторов удваивается, пока один замер не займёт хотя бы 100 мс */
static int run_bench(void) {
    printf("%-8s %-8s %12s %10s %12s\n", "module", "method", "iterations", "total_ms", "ns_per_call");
    for (size_t c = 0; c < sizeof bench_cases / sizeof bench_cases[0]; c++) {
        const struct bench_case *bc = &bench_cases[c];
        long iters = 1;
        clock_t spent;
        for (;;) {
            clock_t start = clock();
            for (long i = 0; i < iters; i++)
                bc->fn();
            spent = clock() - start;
            if ((double) spent * 1000.0 / CLOCKS_PER_SEC >= 100.0 || iters >= (1L << 30))
                break;
            iters *= 2;
        }
        double ms = (double) spent * 1000.0 / CLOCKS_PER_SEC;
        double calls = (double) iters * bc->calls;
        printf("%-8s %-8s %12.0f %10.1f %12.1f\n", bc->module, bc->method, calls, ms, ms * 1e6 / calls);
    }
    return 0;
}

static int run_multi(const struct multi_option *opt, int argc, char *argv[]) {
    if (strcmp(opt->name, "-ATK") == 0)
        return run_attack(opt, argc, argv);
    if (strcmp(opt->name, "-Efvgb") == 0 || strcmp(opt->name, "-Dfvgb") == 0)
        return run_vgb_file(opt, argc, argv);
    if (strcmp(opt->name, "-DL") == 0 || strcmp(opt->name, "-Dl") == 0)
        return run_logdis(opt, argc, argv);
    if (strcmp(opt->name, "-GF") == 0)
        return run_gf(opt, argc, argv);
    if (strcmp(opt->name, "-ME") == 0)
        return run_expmod(opt, argc, argv);
    if (strcmp(opt->name, "-MI") == 0)
        return run_invmod(opt, argc, argv);
    return fail(EXIT_ILLEGAL, "illegal option: %s", opt->name);
}

int main(int argc, char *argv[]) {
    set_prog_name(argc > 0 ? argv[0] : NULL);

    if (argc <= 1)
        return fail(EXIT_NOTHING, "no option and message");

    const char *option = argv[1];

    if (strcmp(option, "-h") == 0 || strcmp(option, "--help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(option, "-BENCH") == 0)
        return run_bench();
    if (argc == 2) {
        if (option[0] == '-')
            return fail(EXIT_NO_ARG, "no message");
        return fail(EXIT_NO_ARG, "no option");
    }
    if (option[0] != '-')
        return fail(EXIT_NO_ARG, "no option");

    if (is_msg_option(option)) {
        if (argc > 3)
            return fail(EXIT_COUNT, "to many strings");
        const char *message = argv[2];
        return run_message(option, message);
    }

    const struct multi_option *multi = find_multi_option(option);
    if (multi == NULL)
        return fail(EXIT_ILLEGAL, "illegal option: %s", option);
    return run_multi(multi, argc, argv);
}
