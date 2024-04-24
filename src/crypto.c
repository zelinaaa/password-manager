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


unsigned char *getRandomSalt() {
    unsigned char *salt = (unsigned char *)malloc(SALT_SIZE);
    if (salt == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (!RAND_bytes(salt, SALT_SIZE)) {
        fprintf(stderr, "Failed to generate salt\n");
        free(salt);
        return NULL;
    }

    return salt;
}

unsigned char *deriveKey(const char *password, unsigned char *salt) {
	unsigned char *key = (unsigned char *)malloc(KEY_SIZE);
	if (key == NULL) {
	    fprintf(stderr, "Memory allocation failed\n");
	    return NULL;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
	    fprintf(stderr, "Failed to create EVP_MD_CTX\n");
	    free(key);
	    return NULL;
}

unsigned char *getRandomIV() {
	unsigned char *iv = (unsigned char *)malloc(AES_BLOCK_SIZE / 8);
	if (iv == NULL) {
	    fprintf(stderr, "getRandomIV: Memory allocation failed\n");
	    return NULL;
	}

	if (!RAND_bytes(iv, AES_BLOCK_SIZE / 8)) {
	    fprintf(stderr, "getRandomIV: Failed to generate IV\n");
	    free(iv);
	    return NULL;
	}
	return iv;
}

