#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "../header/cryptodef.h"

int hashData(const unsigned char *data, int dataLen, unsigned char **hash) {
    SHA256_CTX sha256;

    *hash = (unsigned char *)malloc(SHA256_LENGTH);
    if (*hash == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    if(!SHA256_Init(&sha256)) {
        fprintf(stderr, "Error: Failed to initialize SHA-256 context\n");
        free(*hash);
        return 1;
    }

    if(!SHA256_Update(&sha256, data, dataLen)) {
        fprintf(stderr, "Error: Failed to update hash calculation\n");
        free(*hash);
        return 1;
    }

    if(!SHA256_Final(*hash, &sha256)) {
        fprintf(stderr, "Error: Failed to finalize hash calculation\n");
        free(*hash);
        return 1;
    }

    return 0;
}
