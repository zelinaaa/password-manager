#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../header/storage.h"
#include "../header/cryptodef.h"

struct PasswordEntry {
	char service[1000];
	char login[1000];
	char password[1000];
};

struct PasswordEntry vaultCap[100];
int entry_count = 0;

ssize_t myGetline(char **lineptr, size_t *n, FILE *stream) {
    ssize_t num_chars_read = 0;
    int next_char;
    size_t i = 0;

    // Allocate initial buffer if needed
    if (*lineptr == NULL || *n == 0) {
        *n = 128; // Initial buffer size
        *lineptr = (char *)malloc(*n);
        if (*lineptr == NULL) {
            return -1; // Memory allocation failed
        }
    }

    // Read characters until newline or EOF
    while ((next_char = fgetc(stream)) != EOF) {
        // Resize buffer if needed
        if (i >= *n - 1) {
            *n *= 2; // Double the buffer size
            char *temp = (char *)realloc(*lineptr, *n);
            if (temp == NULL) {
                return -1; // Memory reallocation failed
            }
            *lineptr = temp;
        }

        (*lineptr)[i++] = (char)next_char;
        num_chars_read++;

        if (next_char == '\n') {
            break; // Stop reading at newline
        }
    }

    // Null-terminate the string
    (*lineptr)[i] = '\0';

    // Return the number of characters read
    return num_chars_read == 0 ? -1 : num_chars_read;
}

int initVault(const char * vaultName){
	unsigned char masterPassword[1024];
	unsigned char *salt = getRandomSalt();
	unsigned char *iv = getRandomIV();

	printf("Zadej master heslo k nove klicence: ");
	cbPemPassword(masterPassword, sizeof(masterPassword), 0, NULL);

	unsigned char *key = deriveKey(masterPassword, salt);

	//spojeni soli a masterPassword
	size_t masterLen = strlen(masterPassword);
	size_t concatLen = masterLen + SALT_SIZE + 1;
	char *concatenated = (char *)malloc(concatLen);
	strcpy(concatenated, salt);
	strcat(concatenated, masterPassword);

	//provedeni hashe
	unsigned char *hashedData;
	hashData(concatenated, strlen(concatenated), &hashedData);

	//zasifrovani
	unsigned char *cipherTextMasterPassword;
	int cipherTextMasterPasswordLen;
	encryptData(hashedData, SHA256_LENGTH, key, iv, &cipherTextMasterPassword, &cipherTextMasterPasswordLen);

	//encode do base64
	char * encodedMaster = base64Encode(cipherTextMasterPassword, cipherTextMasterPasswordLen);
	char * encodedIv = base64Encode(iv, IV_SIZE);
	char * encodedSalt = base64Encode(salt, SALT_SIZE);

	removeNewlines(encodedMaster);
	removeNewlines(encodedIv);
	removeNewlines(encodedSalt);

	FILE *file = fopen(vaultName, "w");
	if (file == NULL) {
		printf("Error opening file for writing.\n");
		return 0;
	}

	fprintf(file, "$%s:%s:%s$\n", encodedMaster, encodedIv, encodedSalt);

	fclose(file);
	return 1;
}

int addPassword(const char *vaultName, unsigned char * key, unsigned char * iv){
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

	//zasifrovani hesla sluzby
	encryptData(servicepassword, strlen(servicepassword), key, iv, &cipherTextServicePassword, &cipherTextServicePasswordLen);

	//encode do base64
	char * encodedServicePassword = base64Encode(cipherTextServicePassword, cipherTextServicePasswordLen);
	char * encodedServiceLogin = base64Encode(login, strlen(login));
	char * encodedServiceName = base64Encode(name, strlen(name));

	removeNewlines(encodedServicePassword);
	removeNewlines(encodedServiceLogin);
	removeNewlines(encodedServiceName);

	FILE *file = fopen(vaultName, "a");
	if (file == NULL) {
		printf("Error opening file for writing.\n");
		return 1;
	}

	// Write master password hash, initial vector, and salt
	fprintf(file, "@%s:%s:%s@\n", encodedServiceName, encodedServiceLogin, encodedServicePassword);

	fclose(file);
	return 0;
}

int readMasterPassword(const char *vaultName, unsigned char **iv, unsigned char **key){
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
	unsigned char * decodedSalt = base64Decode(readSalt, &decodedSaltLen);

	printf("Zadej master heslo k desifrovani: ");
	cbPemPassword(masterPassword, sizeof(masterPassword), 0, NULL);

	*key = deriveKey(masterPassword, decodedSalt);
	unsigned char *decryptedMasterText;
	int decryptedMasterTextLen;
	decryptData(decodedMasterPassword, decodedMasterLen, *key, *iv, &decryptedMasterText, &decryptedMasterTextLen);

	fclose(file);
}

int readPasswords(const char *vaultName){
	memset(vaultCap, 0, sizeof(vaultCap));
	entry_count = 0;
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
}

void printAllPasswords(){
	for (int i = 0; i < entry_count / 3; i++) {
		printf("Entry %d:\n", i + 1);
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
}}}

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
		if (entry_count >= 100) {
			printf("Maximum number of entries reached.\n");
			break;
		}

		switch (entry_count % 3) {
			case 0:
				unsigned char * decodedService = base64Decode(token, &decodedServiceLen);
				decodedService[decodedServiceLen] = '\0';
				strcpy(vaultCap[entry_count / 3].service, decodedService);
				break;
			case 1:
				unsigned char * decodedLogin = base64Decode(token, &decodedLoginLen);
				decodedLogin[decodedLoginLen] = '\0';
				strcpy(vaultCap[entry_count / 3].login, decodedLogin);
				break;
			case 2:
				unsigned char * decodedPassword = base64Decode(token, &decodedPasswordLen);
				decodedPassword[decodedPasswordLen] = '\0';
				strcpy(vaultCap[entry_count / 3].password, decodedPassword);
				break;
		}

		token = strtok(NULL, ":");
		entry_count++;
	}
}

void removeNewlines(char *str) {
    char *pos;
    if ((pos = strchr(str, '\n')) != NULL) {
        *pos = '\0';
    }
}
