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

int initVault(const char * vaultName);
ssize_t myGetline(char **linePtr, size_t *n, FILE *stream);
int verifyHash(const unsigned char * hash, const unsigned char * salt);
int addPassword(const char *vaultName, unsigned char * key, unsigned char * iv);
int readMasterPassword(const char *vaultName, unsigned char **iv, unsigned char **key, unsigned char **salt, unsigned char **hash);
int readPasswords(const char *vaultName);
int editPassword(const char *vaultName, unsigned char *key, unsigned char *iv, int entryId);
void showDecryptedPassword(const char *vaultName, unsigned char *key, unsigned char *iv, int entryId);
int deletePassword(const char *vaultName, int entryId);
int handleRenameFile(const char * vaultName);
void printAllPasswords();
void decodePasswordMaster(char * line, unsigned char **readMasterPassword, unsigned char ** readIv, unsigned char ** readSalt);
void decodePassword(char * line);


#endif
