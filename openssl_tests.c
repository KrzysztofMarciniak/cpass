#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl.h"

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    const char *test_file = "test.db";
    const char *password = "mysecret";
    const char *plaintext = "Hello, OpenBSD crypto!\n";

    printf("[*] Encrypting test data...\n");
    if (!encrypt_file(test_file, (unsigned char *)plaintext, strlen(plaintext), password)) {
        fprintf(stderr, "Encryption failed!\n");
        return 1;
    }
    printf("[+] Encryption successful.\n");

    FILE *f = fopen(test_file, "rb");
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    rewind(f);
    unsigned char *data = malloc(filesize);
    fread(data, 1, filesize, f);
    fclose(f);

    printf("[*] Raw encrypted file (hex):\n");
    print_hex(data, filesize);
    free(data);

    printf("[*] Decrypting test data...\n");
    size_t outlen;
    unsigned char *decrypted = decrypt_file(test_file, &outlen, password);
    if (!decrypted) return 1;

    printf("[+] Decryption successful. Output:\n%.*s", (int)outlen, decrypted);

    free(decrypted);
    remove(test_file);

    return 0;
}
