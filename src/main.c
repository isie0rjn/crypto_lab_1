#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

#include "csk.h"
#include "csr.h"
#include "expmod.h"
#include "invmod.h"
#include "util.h"
#include "vars.h"
#include "vgn.h"

enum {
    EXIT_ILLEGAL = 1,
    EXIT_NO_ARG = 2,
    EXIT_NOTHING = 3,
    EXIT_COUNT = 4,
    EXIT_NUMBER = 5,
    EXIT_ALGO = 6
};

static char prog[64] = "crypto";

static const char *const msg_options[] = {
    "-Ecsr", "-Dcsr", "-Ecsrm", "-Dcsrm",
    "-Ecsk", "-Dcsk", "-Ecskx", "-Dcskx",
    "-Evgn", "-Dvgn", "-Evgnx", "-Dvgnx"
};

struct multi_option {
    const char *name;
    const char *usage;
};

static const struct multi_option multi_options[] = {
    {"-ME", "-ME rlbe|lrbe|ml|swe A K N"},
    {"-MI", "-MI eea|ferma|gcd B N"},
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
           "  -ME rlbe|lrbe|ml|swe A K N   A^K mod N\n"
           "  -MI eea|ferma|gcd B N        B^-1 mod N\n"
           "  -h, --help                   this text\n"
           "keys are read from stdin after the prompt 'key: '\n",
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

static int run_message(const char *option, const char *message) {
    size_t out_size = strlen(message) + 1;
    char *out = malloc(out_size);
    char key[256];
    int rc = 0;
    int shift;

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

static int run_multi(const struct multi_option *opt, int argc, char *argv[]) {
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
