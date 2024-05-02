#ifndef STORAGE_H_
#define STORAGE_H_

#define VAULT_SIZE 100

struct PasswordEntry {
	char service[1000];
	char login[1000];
	char password[1000];
};

struct PasswordEntry vaultCap[VAULT_SIZE];
int entryCount = 0;

#endif
