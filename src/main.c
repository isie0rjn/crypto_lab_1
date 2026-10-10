#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include <stdio.h>

char *CSR_encrypt(char message[]);
char *CSR_decrypt(char cipher[]);

int main(int argc, char *argv[]) {
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
            printf("%s", CSR_encrypt(argv[2]));
        } else if (strcmp(argv[1], "-Dcsr") == 0) {
            printf("%s", CSR_decrypt(argv[2]));
        } else {
            printf("No such option.");
            return 1;
        }
    }

    return 0;
}

char *CSR_encrypt(char message[]) {
    return "Caesar encrypt of message ";
}

char *CSR_decrypt(char cipher[]) {
    return "Caesar decrypt of message";
}