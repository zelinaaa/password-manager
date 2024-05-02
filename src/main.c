#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../header/cryptodef.h"

int main() {
	unsigned char * key;
	unsigned char * iv;
	unsigned char * hash;
	unsigned char * salt;
	initVault("test");
	readMasterPassword("test", &key, &iv, &salt, &hash);

	int resultAuthentication = verifyHash(hash, salt);

	addPassword("test", key, iv);
	addPassword("test", key, iv);
	readPasswords("test");
	printAllPasswords();
	editPassword("test", key, iv, 1);
	readPasswords("test");
	printAllPasswords();
	showDecryptedPassword("test", key, iv, 1);

    return 0;
}
