#ifndef HEADER_CRYPTO_H_
#define HEADER_CRYPTO_H_

int hashData(const unsigned char *data, int dataLen, unsigned char **outHash);
unsigned char *getRandomIV();
unsigned char *getRandomSalt();
unsigned char *deriveKey(const char *password, unsigned char *salt);
int encryptData(const char *plainText, int plainTextLen, const unsigned char *key, unsigned char *iv, unsigned char **outCipherText, int *outCipherTextLen);
int decryptData(const unsigned char *cipherText, int cipherTextLen, const unsigned char *key, unsigned char *iv, unsigned char **outPlainText, int *outPlainTextLen);

#endif
