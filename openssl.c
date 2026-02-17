#include "openssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LEN 16
#define NONCE_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32  // AES-256

// --- derive key from password + salt ---
static int derive_key(const char *password, unsigned char *salt, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password),
                             salt, SALT_LEN, 100000,
                             EVP_sha256(), KEY_LEN, key);
}

// --- encrypt plaintext to file ---
int encrypt_file(const char *filename, const unsigned char *plaintext, size_t len, const char *password) {
    unsigned char salt[SALT_LEN];
    unsigned char key[KEY_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];

    if (!RAND_bytes(salt, SALT_LEN) || !RAND_bytes(nonce, NONCE_LEN)) return 0;
    if (!derive_key(password, salt, key)) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return 0;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) return 0;

    int outlen;
    unsigned char *ciphertext = malloc(len);
    if (!ciphertext) return 0;

    if (!EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)len)) return 0;
    int ciphertext_len = outlen;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen)) return 0;
    ciphertext_len += outlen;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) return 0;

    FILE *f = fopen(filename, "wb");
    if (!f) return 0;

    fwrite(salt, 1, SALT_LEN, f);
    fwrite(nonce, 1, NONCE_LEN, f);
    fwrite(ciphertext, 1, ciphertext_len, f);
    fwrite(tag, 1, TAG_LEN, f);
    fclose(f);

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    explicit_bzero(key, KEY_LEN);

    return 1;
}

// --- decrypt file ---
unsigned char *decrypt_file(const char *filename, size_t *outlen, const char *password) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    rewind(f);

    if (filesize < SALT_LEN + NONCE_LEN + TAG_LEN) {
        fclose(f);
        return NULL;
    }

    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];

    fread(salt, 1, SALT_LEN, f);
    fread(nonce, 1, NONCE_LEN, f);

    size_t cipherlen = filesize - SALT_LEN - NONCE_LEN - TAG_LEN;
    unsigned char *ciphertext = malloc(cipherlen);
    fread(ciphertext, 1, cipherlen, f);
    fread(tag, 1, TAG_LEN, f);
    fclose(f);

    unsigned char key[KEY_LEN];
    if (!derive_key(password, salt, key)) {
        free(ciphertext);
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return NULL;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) return NULL;

    unsigned char *plaintext = malloc(cipherlen);
    int outlen_tmp;
    if (!EVP_DecryptUpdate(ctx, plaintext, &outlen_tmp, ciphertext, (int)cipherlen)) return NULL;
    int plaintext_len = outlen_tmp;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) return NULL;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + outlen_tmp, &outlen_tmp)) {
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len += outlen_tmp;

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    explicit_bzero(key, KEY_LEN);

    *outlen = plaintext_len;
    return plaintext;
}
