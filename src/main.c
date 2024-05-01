#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <unistd.h>
#include "../header/cryptodef.h"

int main() {
	unsigned char * key;
	unsigned char * iv;
	//initVault("test");
	//readMasterPassword("test", &key, &iv); //aby slo addPassword tak se musi readMasterPassword pro ziskani derivovaneho key
	//addPassword("test", key, iv);
	readPasswords("test");
	printAllPasswords();

	/*Delete hesla by se mohl udelat tak, ze to co je ulozene v strukture tak ulozim do nejakohe temp
	 * souboru a pak vymazu hlavni soubor a temp soubor prejmenuji na vymazany soubor. Stejne by se udelal i edit.
	 * Jinak me to nenapada.*/

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









