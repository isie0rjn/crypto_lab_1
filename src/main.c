#include <string.h>
#include <stdio.h>

#include "csr.h"

int main(int argc, char *argv[]) {
    int answ = 0;

    if (argc == 1) {
        printf("No message and key provided.");
        return 1;
    }
    if (argc == 2) {
        if (argv[1][0] == '-')
            printf("No message provided.");
        else
            printf("No key provided.");
        return 1;
    }
    if (argc > 3) {
        printf("Too many arguments.");
    }
    if (argc == 3) {
        if (strcmp(argv[1], "-Ecsr") == 0) {
            printf("key: ");
            scanf("%d", &answ);
            char out[255];
            CSR_encrypt(argv[2], answ, out);
            printf("%s with key %d", out, answ);
        } else if (strcmp(argv[1], "-Dcsr") == 0) {
            printf("key: ");
            scanf("%d", &answ);
            char out[255];
            CSR_decrypt(argv[2], answ, out);
            printf("%s with key %d", out, answ);
        } else {
            printf("No such option.");
            return 1;
        }
    }

    return 0;
}

