#ifndef HEADER_CRYPTO_H_
#define HEADER_CRYPTO_H_

int hashData(const unsigned char *data, int dataLen, unsigned char **outHash);
unsigned char *getRandomIV();
unsigned char *getRandomSalt();
unsigned char *deriveKey(const char *password, unsigned char *salt);

#endif
