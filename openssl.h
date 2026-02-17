#ifndef OPENSSL_H
#define OPENSSL_H

#include <stddef.h>

// Encrypt plaintext buffer into a file.
// Returns 1 on success, 0 on failure.
int encrypt_file(const char *filename, const unsigned char *plaintext, size_t len, const char *password);

// Decrypt file into plaintext buffer.
// Returns pointer to allocated buffer on success (caller frees), or NULL on failure.
// *outlen is set to the plaintext length.
unsigned char *decrypt_file(const char *filename, size_t *outlen, const char *password);

#endif // OPENSSL_H
