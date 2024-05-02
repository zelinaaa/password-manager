#include <stdio.h>
#include <string.h>
#include <windows.h>
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


//funkce pro neviditelné zadávání znaků
int cbPemPassword(char *buf, int size, int rwflag, void *u){
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;

	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT));

	if (!fgets(buf, size, stdin)) {
		buf[0] = '\0';
	} else {
		char *pos;
		if ((pos = strchr(buf, '\n')) != NULL) {
			*pos = '\0';
		}
	}

	SetConsoleMode(hStdin, mode);
	return strlen(buf);
}
