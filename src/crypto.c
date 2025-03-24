#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "../header/cryptodef.h"

/*Algoritmus pro hash sha256, parametr data je spojena sul a master heslo, dataLen je delka data a hash je vystupni
 * parametr. Nejprve se alokuje pamet pro delku sha256, tj. 32 bajtu. Dala se provede algoritmus nejprve inicializaci pak
 * update a nakonec final. Navratova hodnota je 0 pri uspechu, 1 pri neuspechu.*/
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

/*Funkce pro vygenerovani nahodne soli. Nejprve se alokuje pamet pro sul, to je 16 bajtu. Dale pomoci RAND_bytes
 * je vygenerovan nahodny retezec bajtu. Navratova hodnota je sul.*/
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

/*Derivace klice. Nejprve alokujeme pamet velikosti klice pro AES256, to je 32 bajtu. Dale nacteme algoritmus.
 * Derivace klice je provedena v 262000 iteracich pro vetsi bezpecnost. Derivovano je z master hesla a soli.
 *  Navratova hodnota je samotny klic.*/
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

	if (EVP_PBE_scrypt(password, strlen(password), salt, SALT_SIZE, ITERATIONS, 8, 1, 256*ITERATIONS*8*1, key, KEY_SIZE) != 1) {
		    fprintf(stderr, "Failed to derive key\n");
		    free(key);
		    EVP_MD_CTX_free(ctx);
		    return NULL;
	}

		EVP_MD_CTX_free(ctx);
		return key;
}

/*Funkce pro vygenerovani nahodneho inicializacniho vektoru. Nejprve se alokuje pamet pro iv, to je 16 bajtu. Dale pomoci RAND_bytes
 * je vygenerovan nahodny retezec bajtu. Navratova hodnota je iv.*/
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

/*Funkce pro sifrovani. Provedeme algoritmus aes256 v modu cbc, kde vstupni parametry jsou klic a iv a plainText (heslo).
 * Vystupni parametr je zasifrovany plainText a delka zasifrovaneho textu.*/
int encryptData(const char *plainText, int plainTextLen, const unsigned char *key, unsigned char *iv, unsigned char **outCipherText, int *outCipherTextLen) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int cipherTextAllocatedLen = plainTextLen + AES_BLOCK_SIZE;

    *outCipherText = (unsigned char *)malloc(cipherTextAllocatedLen);
    if (*outCipherText == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        free(*outCipherText);
        return 1;
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error: Failed to initialize encryption operation\n");
        free(*outCipherText);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if(!EVP_EncryptUpdate(ctx, *outCipherText, &len, plainText, plainTextLen)) {
        fprintf(stderr, "Error: Encryption failed\n");
        free(*outCipherText);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *outCipherTextLen = len;

    if(!EVP_EncryptFinal_ex(ctx, *outCipherText + len, &len)) {
        fprintf(stderr, "Error: Finalizing encryption failed\n");
        free(*outCipherText);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *outCipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/*Funkce pro desifrovani. Provedeme algoritmus aes256 v modu cbc, kde vstupni parametry jsou klic a iv a cipherText (heslo).
 * Vystupni parametr je plainText a delka plainTextu.*/
int decryptData(const unsigned char *cipherText, int cipherTextLen, const unsigned char *key, unsigned char *iv, unsigned char **plainText, int *plainTextLen) {
    EVP_CIPHER_CTX *ctx;
    int len;

    *plainText = (unsigned char *)malloc(cipherTextLen);
    if (*plainText == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        free(*plainText);
        return 1;
    }

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error: Failed to initialize decryption operation\n");
        free(*plainText);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if(!EVP_DecryptUpdate(ctx, *plainText, &len, cipherText, cipherTextLen)) {
        fprintf(stderr, "Error: Decryption failed\n");
        free(*plainText);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *plainTextLen = len;

    if(!EVP_DecryptFinal_ex(ctx, *plainText + len, &len)) {
        fprintf(stderr, "Error: Finalizing decryption failed\n");
        free(*plainText);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
