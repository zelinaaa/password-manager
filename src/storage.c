#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "../header/storage.h"
#include "../header/cryptodef.h"

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

ssize_t myGetline(char **linePtr, size_t *n, FILE *stream) {
    ssize_t numCharsRead = 0;
    int nextChar;
    size_t i = 0;

    if (*linePtr == NULL || *n == 0) {
        *n = 128;
        *linePtr = (char *)malloc(*n);
        if (*linePtr == NULL) {
            return -1;
        }
    }

    while ((nextChar = fgetc(stream)) != EOF) {
        if (i >= *n - 1) {
            *n *= 2;
            char *temp = (char *)realloc(*linePtr, *n);
            if (temp == NULL) {
                return -1;
            }
            *linePtr = temp;
        }

        (*linePtr)[i++] = (char)nextChar;
        numCharsRead++;

        if (nextChar == '\n') {
            break;
        }
    }

    (*linePtr)[i] = '\0';

    return numCharsRead == 0 ? -1 : numCharsRead;
}

int initVault(const char * vaultName){
	unsigned char masterPassword[1024];
	unsigned char *salt = getRandomSalt();
	unsigned char *iv = getRandomIV();

	printf("Zadej master heslo k nove klicence: ");
	cbPemPassword(masterPassword, sizeof(masterPassword), 0, NULL);
	masterPassword[sizeof(masterPassword) - 1] = '\0';
	system("clear");

	unsigned char *key = deriveKey(masterPassword, salt);

	size_t masterLen = strlen((char*)masterPassword);
	size_t concatLen = masterLen + SALT_SIZE;
	unsigned char* concatenated = (unsigned char*)malloc(concatLen);
	memcpy(concatenated, salt, SALT_SIZE);
	memcpy(concatenated + SALT_SIZE, masterPassword, masterLen);

	unsigned char *hashedData;
	hashData(concatenated, concatLen, &hashedData);

	unsigned char *cipherTextMasterPassword;
	int cipherTextMasterPasswordLen;
	encryptData(hashedData, SHA256_LENGTH, key, iv, &cipherTextMasterPassword, &cipherTextMasterPasswordLen);

	char * encodedMaster = base64Encode(cipherTextMasterPassword, cipherTextMasterPasswordLen);
	char * encodedIv = base64Encode(iv, IV_SIZE);
	char * encodedSalt = base64Encode(salt, SALT_SIZE);

	FILE *file = fopen(vaultName, "w");
	if (file == NULL) {
		printf("Error opening file for writing.\n");
		return 0;
	}

	fprintf(file, "$%s:%s:%s$\n", encodedMaster, encodedIv, encodedSalt);

	fclose(file);
	return 1;
}

int verifyHash(const unsigned char * hash, const unsigned char * salt){
	unsigned char masterPassword[1024];

	printf("Enter master password for authentication: ");
	cbPemPassword(masterPassword, sizeof(masterPassword), 0, NULL);
	system("clear");

	size_t masterLen = strlen((char*)masterPassword);
	size_t concatLen = masterLen + SALT_SIZE;
	unsigned char* concatenated = (unsigned char*)malloc(concatLen);
	memcpy(concatenated, salt, SALT_SIZE);
	memcpy(concatenated + SALT_SIZE, masterPassword, masterLen);

	unsigned char *hashedData;
	hashData(concatenated, concatLen, &hashedData);

	if (*hash == *hashedData){
		return 0;
	}
	return 1;
}

int addPassword(const char *vaultName, unsigned char * key, unsigned char * iv){
	if (entryCount >= VAULT_SIZE*3) {
		printf("Your password vault is at max capacity.\n");
		return 1;
	}

	const char servicepassword[1000];
	unsigned char login[1024];
	unsigned char name[1024];

	unsigned char *cipherTextServicePassword;
	int cipherTextServicePasswordLen;

	printf("\nNazev sluzby: ");
	fgets(name, sizeof(name), stdin);
	printf("\nLogin sluzby: ");
	fgets(login, sizeof(login), stdin);
	printf("\nHeslo sluzby: ");
	cbPemPassword(servicepassword, sizeof(servicepassword), 0, NULL);
	system("clear");

	encryptData(servicepassword, strlen(servicepassword), key, iv, &cipherTextServicePassword, &cipherTextServicePasswordLen);

	char * encodedServicePassword = base64Encode(cipherTextServicePassword, cipherTextServicePasswordLen);
	char * encodedServiceLogin = base64Encode(login, strlen(login));
	char * encodedServiceName = base64Encode(name, strlen(name));

	FILE *file = fopen(vaultName, "a");
	if (file == NULL) {
		printf("Error opening file for writing.\n");
		return 1;
	}

	fprintf(file, "@%s:%s:%s@\n", encodedServiceName, encodedServiceLogin, encodedServicePassword);

	fclose(file);

	return 0;
}

int readMasterPassword(const char *vaultName, unsigned char **iv, unsigned char **key, unsigned char **salt, unsigned char **hash){
	unsigned char masterPassword[1024];
	unsigned char * readMasterPassword;
	unsigned char * readIv;
	unsigned char * readSalt;

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *file = fopen(vaultName, "r");
	if (file == NULL) {
		printf("Error opening file for reading.\n");
		return 1;
	}

	if (myGetline(&line, &len, file) != -1) {
		decodePasswordMaster(line, &readMasterPassword, &readIv, &readSalt);
	}

	size_t decodedMasterLen;
	size_t decodedIvLen;
	size_t decodedSaltLen;

	unsigned char * decodedMasterPassword = base64Decode(readMasterPassword, &decodedMasterLen);
	*iv = base64Decode(readIv, &decodedIvLen);
	*salt = base64Decode(readSalt, &decodedSaltLen);

	printf("Zadej master heslo k desifrovani: ");
	cbPemPassword(masterPassword, sizeof(masterPassword), 0, NULL);
	system("clear");

	*key = deriveKey(masterPassword, *salt);
	unsigned char *decryptedMasterText;
	int decryptedMasterTextLen;
	decryptData(decodedMasterPassword, decodedMasterLen, *key, *iv, &decryptedMasterText, &decryptedMasterTextLen);

	*hash = decryptedMasterText;

	fclose(file);

	return 0;
}

int readPasswords(const char *vaultName){
	memset(vaultCap, 0, sizeof(vaultCap));
	entryCount = 0;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	FILE *file = fopen(vaultName, "r");
	if (file == NULL) {
		printf("Error opening file for reading.\n");
		return 1;
	}

	if (myGetline(&line, &len, file) == -1) {
		printf("Error reading first line from file.\n");
		fclose(file);
		return 1;
	}

	while ((read = myGetline(&line, &len, file)) != -1) {
		decodePassword(line);
	}
	fclose(file);
	free(line);

	return 0;
}

int editPassword(const char *vaultName, unsigned char *key, unsigned char *iv, int entryId){
	if (0 == entryCount) {
		printf("Your password vault is empty.\n");
		return 1;
	}

	const char servicepassword[1000];
	unsigned char login[1024];
	unsigned char name[1024];

	unsigned char *cipherTextServicePassword;
	int cipherTextServicePasswordLen;

	printf("\nNazev sluzby: ");
	fgets(name, sizeof(name), stdin);
	printf("\nLogin sluzby: ");
	fgets(login, sizeof(login), stdin);
	printf("\nHeslo sluzby: ");
	cbPemPassword(servicepassword, sizeof(servicepassword), 0, NULL);

	encryptData(servicepassword, strlen(servicepassword), key, iv, &cipherTextServicePassword, &cipherTextServicePasswordLen);

	char * encodedServicePassword = base64Encode(cipherTextServicePassword, cipherTextServicePasswordLen);
	char * encodedServiceLogin = base64Encode(login, strlen(login));
	char * encodedServiceName = base64Encode(name, strlen(name));

	char *buffer = NULL;
	size_t bufferSize = 0;
	int currentLineNumber = 0;

	FILE *originalFile = fopen(vaultName, "r");
	FILE *tempFile = fopen("tmp", "w");

	if (originalFile == NULL || tempFile == NULL) {
		printf("Error opening files.\n");
		return 1;
	}

	while (myGetline(&buffer, &bufferSize, originalFile) != -1) {
		currentLineNumber++;
		if (currentLineNumber == entryId+1) {
			fprintf(tempFile, "@%s:%s:%s@\n", encodedServiceName, encodedServiceLogin, encodedServicePassword);
		} else {
			fputs(buffer, tempFile);
		}
	}

	free(buffer);
	fclose(originalFile);
	fclose(tempFile);

	handleRenameFile(vaultName);

	return 0;
}

void showDecryptedPassword(const char *vaultName, unsigned char *key, unsigned char *iv, int entryId){
	for (int i = 0; i < entryCount / 3; i++){
		if (i+1 == entryId){
			unsigned char *decryptedServiceText;
			int decryptedServiceTextLen;
			decryptData(vaultCap[i].password, strlen(vaultCap[i].password), key, iv, &decryptedServiceText, &decryptedServiceTextLen);
			decryptedServiceText[decryptedServiceTextLen] = '\0';
			printf("Entry %d:\n", i+1);
			printf("Service: %s", vaultCap[i].service);
			printf("Login: %s", vaultCap[i].login);
			printf("Password: %s", decryptedServiceText);
			printf("\n\n");

			free(decryptedServiceText);
		}
	}
}

int deletePassword(const char *vaultName, int entryId){
	if (0 == entryCount) {
		printf("Your password vault is empty.\n");
		return 1;
	}
	char *buffer = NULL;
	size_t bufferSize = 0;
	int currentLineNumber = 0;

	FILE *originalFile = fopen(vaultName, "r");
	FILE *tempFile = fopen("tmp", "w");

	if (originalFile == NULL || tempFile == NULL) {
		printf("Error opening files.\n");
		return 1;
	}

	while (myGetline(&buffer, &bufferSize, originalFile) != -1) {
		currentLineNumber++;
		if (currentLineNumber == entryId+1) {
			fputs("", tempFile);
		} else {
			fputs(buffer, tempFile);
		}
	}

	free(buffer);
	fclose(originalFile);
	fclose(tempFile);

	handleRenameFile(vaultName);

	return 0;
}

int handleRenameFile(const char * vaultName){
	if (remove(vaultName) != 0) {
		printf("Error deleting the original file.\n");
		return 1;
	}

	if (rename("tmp", vaultName) != 0) {
		printf("Error renaming the temporary file.\n");
		return 1;
	}
	return 0;
}

void printAllPasswords(){
	for (int i = 0; i < entryCount / 3; i++) {
		printf("\nEntry %d:\n", i+1);
		printf("Service: %s", vaultCap[i].service);
		printf("Login: %s", vaultCap[i].login);
		printf("Password: %s", vaultCap[i].password);
		printf("\n\n");
	}
}

void decodePasswordMaster(char * line, unsigned char **readMasterPassword, unsigned char ** readIv, unsigned char ** readSalt){
	char *token;
	size_t decodedMasterLen;
	size_t decodedIvLen;
	size_t decodedSaltLen;

	if (line[0] == '$') {
		line++;
	}

	line[strlen(line)-2] = '\0';

	token = strtok(line, ":");
	if (token != NULL) {
		*readMasterPassword = token;
		token = strtok(NULL, ":");
		if (token != NULL) {
			*readIv = token;
			token = strtok(NULL, ":");
			if (token != NULL) {
				*readSalt = token;
			}
		}
	}
}

void decodePassword(char * line){
	char *token;
	size_t decodedLoginLen;
	size_t decodedServiceLen;
	size_t decodedPasswordLen;

	if (line[0] == '@') {
		line++;
	}

	line[strlen(line)-2] = '\0';

	token = strtok(line, ":");
	while (token != NULL) {
		if (entryCount >= VAULT_SIZE*3) {
			printf("Maximum number of entries reached.\n");
			break;
		}

		switch (entryCount % 3) {
			case 0:
				unsigned char * decodedService = base64Decode(token, &decodedServiceLen);
				decodedService[decodedServiceLen] = '\0';
				strcpy(vaultCap[entryCount / 3].service, decodedService);
				break;
			case 1:
				unsigned char * decodedLogin = base64Decode(token, &decodedLoginLen);
				decodedLogin[decodedLoginLen] = '\0';
				strcpy(vaultCap[entryCount / 3].login, decodedLogin);
				break;
			case 2:
				unsigned char * decodedPassword = base64Decode(token, &decodedPasswordLen);
				decodedPassword[decodedPasswordLen] = '\0';
				strcpy(vaultCap[entryCount / 3].password, decodedPassword);
				break;
		}
		token = strtok(NULL, ":");
		entryCount++;
	}
}


