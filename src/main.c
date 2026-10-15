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

static int run_multi(const struct multi_option *opt, int argc, char *argv[]) {
    (void) argc;
    (void) argv;
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
