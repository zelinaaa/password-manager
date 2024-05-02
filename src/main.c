#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../header/storage.h"
#include "../header/crypto.h"
#include "../header/encoding.h"
#include "../header/cryptodef.h"

int main(int argc, char **argv) {
	MasterEntry* entry = malloc(sizeof(MasterEntry));

	const char* randomPassword = "password123";
	entry->salt = base64Encode(getRandomSalt(), SALT_SIZE);
	entry->iv = base64Encode(getRandomIV(), AES_BLOCK_SIZE/8);
	unsigned char* key = deriveKey(randomPassword, entry->salt);
	unsigned char* hashedPassword;
	hashData(randomPassword, strlen(randomPassword), &hashedPassword);
	int cipherTextHashedPasswordLen;
	unsigned char* cipherTextHashedPassword;
	encryptData(hashedPassword, strlen(hashedPassword), key, entry->iv, &cipherTextHashedPassword, &cipherTextHashedPasswordLen);
	entry->hash = base64Encode(cipherTextHashedPassword, cipherTextHashedPasswordLen);

	createNewVault("testvault", entry);
	printf("test");
}
