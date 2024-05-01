#ifndef CRYPTO_DEF_H_
#define CRYPTO_DEF_H_

//hashing
#define SHA256_LENGTH 32

//Key derivation and salt generation
#define KEY_SIZE 32 // AES-256 key size(Bytes)
#define SALT_SIZE 16 // Salt size(Bytes)
#define IV_SIZE 16

//aes encryption
#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 128

#define ITERATIONS 262144 // Number of iterations for key derivation

#endif
