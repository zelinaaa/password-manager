#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../header/manager.h"
#include "../header/cryptodef.h"
#include "../header/storage.h"
#include "../header/crypto.h"
#include "../header/encoding.h"
#include "../header/util.h"

int initVault(const char * fileName){
	unsigned char masterPassword[1024];
	unsigned char *salt = getRandomSalt();
	unsigned char *iv = getRandomIV();

	if (access(fileName, F_OK) == 0) {
		fprintf(stderr, "File exists.\n");
		return 1;
	}

	printf("Enter master password for vault: ");
	cbPemPassword(masterPassword, sizeof(masterPassword), 0, NULL);
	masterPassword[sizeof(masterPassword) - 1] = '\0';

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

	MasterEntry masterEntry = {
		.hash = encodedMaster,
		.iv = encodedIv,
		.salt = encodedSalt
	};

	if (createNewVault(fileName, &masterEntry) != 0) {
		fprintf(stderr, "Failed to create a new vault.\n");
		return 1;
	}

	return 0;
}

int deleteVault(const char *fileName){
	unsigned char *key;
	unsigned char *cipherTextServicePassword;
	int cipherTextServicePasswordLen;

	MasterEntry masterEntry;
	getMasterEntryByFilename(fileName, &masterEntry);

	size_t decodedMasterLen;
	size_t decodedIvLen;
	size_t decodedSaltLen;

	unsigned char *decodedHash = base64Decode(masterEntry.hash, &decodedMasterLen);
	unsigned char *decodedIv = base64Decode(masterEntry.iv, &decodedIvLen);
	unsigned char *decodedSalt = base64Decode(masterEntry.salt, &decodedSaltLen);

	if (authenticateUser(decodedHash, decodedMasterLen, decodedSalt, decodedIv, &key) != 0){
		return 1;
	}

	if (remove(fileName) != 0) {
		fprintf(stderr, "File delete failed.\n");
	}

	return 0;
}

int authenticateUser(const unsigned char *hashInput, size_t decodedMasterLen, const unsigned char *saltRead, const unsigned char *readIv, unsigned char **key){
	unsigned char masterPassword[1024];

	printf("Enter master password for authentication: ");
	cbPemPassword(masterPassword, sizeof(masterPassword), 0, NULL);

	*key = deriveKey(masterPassword, saltRead);
	unsigned char *decryptedMasterText;
	int decryptedMasterTextLen;
	decryptData(hashInput, decodedMasterLen, *key, readIv, &decryptedMasterText, &decryptedMasterTextLen);

	size_t masterLen = strlen((char*)masterPassword);
	size_t concatLen = masterLen + SALT_SIZE;
	unsigned char* concatenated = (unsigned char*)malloc(concatLen);
	memcpy(concatenated, saltRead, SALT_SIZE);
	memcpy(concatenated + SALT_SIZE, masterPassword, masterLen);

	unsigned char *hashedData;
	hashData(concatenated, concatLen, &hashedData);

	if (*decryptedMasterText == *hashedData){
		return 0;
	}
	return 1;
}

int addService(const char * fileName, const char * serviceName){
	const char servicepassword[1000];
	unsigned char login[1024];
	unsigned char name[1024];
	unsigned char *key;
	unsigned char *cipherTextServicePassword;
	int cipherTextServicePasswordLen;

	MasterEntry masterEntry;
	getMasterEntryByFilename(fileName, &masterEntry);

	size_t decodedMasterLen;
	size_t decodedIvLen;
	size_t decodedSaltLen;

	unsigned char *decodedHash = base64Decode(masterEntry.hash, &decodedMasterLen);
	unsigned char *decodedIv = base64Decode(masterEntry.iv, &decodedIvLen);
	unsigned char *decodedSalt = base64Decode(masterEntry.salt, &decodedSaltLen);

	if (authenticateUser(decodedHash, decodedMasterLen, decodedSalt, decodedIv, &key) != 0){
		return 1;
	}

	printf("\nEnter service login: ");
	fgets(login, sizeof(login), stdin);
	printf("\nEnter service password: ");
	cbPemPassword(servicepassword, sizeof(servicepassword), 0, NULL);

	removeNewlines(login);
	removeNewlines(servicepassword);

	encryptData(servicepassword, strlen(servicepassword), key, decodedIv, &cipherTextServicePassword, &cipherTextServicePasswordLen);

	char * encodedServicePassword = base64Encode(cipherTextServicePassword, cipherTextServicePasswordLen);
	char * encodedServiceLogin = base64Encode(login, strlen(login));
	char * encodedServiceName = base64Encode(serviceName, strlen(serviceName));

	ServiceEntry entry = {
		.serviceName = encodedServiceName,
		.login = encodedServiceLogin,
		.encryptedPassword = encodedServicePassword
	};

	if (addEntry(fileName, &entry) != 0){
		fprintf(stderr, "Failed to add entry to vault.\n");
		return 1;
	}
	return 0;
}

int editEntry(const char *fileName, const char * serviceName){
	const char servicepassword[1000];
	unsigned char login[1024];
	unsigned char name[1024];
	unsigned char service[1024];
	unsigned char *key;
	unsigned char *cipherTextServicePassword;
	int cipherTextServicePasswordLen;

	MasterEntry masterEntry;
	getMasterEntryByFilename(fileName, &masterEntry);

	size_t decodedMasterLen;
	size_t decodedIvLen;
	size_t decodedSaltLen;

	unsigned char *decodedHash = base64Decode(masterEntry.hash, &decodedMasterLen);
	unsigned char *decodedIv = base64Decode(masterEntry.iv, &decodedIvLen);
	unsigned char *decodedSalt = base64Decode(masterEntry.salt, &decodedSaltLen);

	if (authenticateUser(decodedHash, decodedMasterLen, decodedSalt, decodedIv, &key) != 0){
		return 1;
	}

	printf("\nEnter new service name: ");
	fgets(service, sizeof(service), stdin);
	printf("\nEnter new service login: ");
	fgets(login, sizeof(login), stdin);
	printf("\nEnter new service password: ");
	cbPemPassword(servicepassword, sizeof(servicepassword), 0, NULL);

	removeNewlines(service);
	removeNewlines(login);
	removeNewlines(servicepassword);

	encryptData(servicepassword, strlen(servicepassword), key, decodedIv, &cipherTextServicePassword, &cipherTextServicePasswordLen);

	char * encodedServicePassword = base64Encode(cipherTextServicePassword, cipherTextServicePasswordLen);
	char * encodedServiceName = base64Encode(service, strlen(service));
	char * encodedServiceLogin = base64Encode(login, strlen(login));

	ServiceEntry modifiedEntry = {
		.serviceName = encodedServiceName,
		.login = encodedServiceLogin,
		.encryptedPassword = encodedServicePassword
	};

	if (modifyEntry(fileName, base64Encode(serviceName, strlen(serviceName)), &modifiedEntry) != 0){
		fprintf(stderr, "Failed to edit entry in vault.\n");
		return 1;
	}

	return 0;
}

int editMaster(const char *fileName){
	unsigned char *key;
	unsigned char *cipherTextServicePassword;
	int cipherTextServicePasswordLen;

	MasterEntry masterEntry;
	getMasterEntryByFilename(fileName, &masterEntry);

	size_t decodedMasterLen;
	size_t decodedIvLen;
	size_t decodedSaltLen;

	unsigned char *decodedHash = base64Decode(masterEntry.hash, &decodedMasterLen);
	unsigned char *decodedIv = base64Decode(masterEntry.iv, &decodedIvLen);
	unsigned char *decodedSalt = base64Decode(masterEntry.salt, &decodedSaltLen);

	if (authenticateUser(decodedHash, decodedMasterLen, decodedSalt, decodedIv, &key) != 0){
		return 1;
	}

	unsigned char newMasterPassword[1000];
	unsigned char * newIv = getRandomIV();
	unsigned char * newSalt = getRandomSalt();

	printf("\nEnter new master password: ");
	cbPemPassword(newMasterPassword, sizeof(newMasterPassword), 0, NULL);
	newMasterPassword[sizeof(newMasterPassword) - 1] = '\0';

	int count;
	FILE *file = fopen(fileName, "r");
	if (!file) return -1;
	ServiceEntry *entries = readVaultEntries(file, &count, &masterEntry);

	for (int i = 0; i < count; i++){
		size_t decodedLen;
		unsigned char *decodedPassword = base64Decode(entries[i].encryptedPassword, &decodedLen);

		int decryptedLen;
		unsigned char *decryptedPassword;

		decryptData(decodedPassword, decodedLen, key, decodedIv, &decryptedPassword, &decryptedLen);

		entries[i].encryptedPassword = (char *)malloc(decryptedLen + 1);
		memcpy(entries[i].encryptedPassword, decryptedPassword, decryptedLen);
		entries[i].encryptedPassword[decryptedLen] = '\0';
	}

	unsigned char *newKey = deriveKey(newMasterPassword, newSalt);

	size_t masterLen = strlen((char*)newMasterPassword);
	size_t concatLen = masterLen + SALT_SIZE;
	unsigned char* concatenated = (unsigned char*)malloc(concatLen);
	memcpy(concatenated, newSalt, SALT_SIZE);
	memcpy(concatenated + SALT_SIZE, newMasterPassword, masterLen);

	unsigned char *hashedData;
	hashData(concatenated, concatLen, &hashedData);

	unsigned char *cipherTextMasterPassword;
	int cipherTextMasterPasswordLen;
	encryptData(hashedData, SHA256_LENGTH, newKey, newIv, &cipherTextMasterPassword, &cipherTextMasterPasswordLen);

	char * encodedMaster = base64Encode(cipherTextMasterPassword, cipherTextMasterPasswordLen);
	char * encodedIv = base64Encode(newIv, IV_SIZE);
	char * encodedSalt = base64Encode(newSalt, SALT_SIZE);

	MasterEntry newMasterEntry = {
		.hash = encodedMaster,
		.iv = encodedIv,
		.salt = encodedSalt
	};

	if (createNewVault(fileName, &newMasterEntry) != 0) {
		fprintf(stderr, "Failed to create a new vault.\n");
		return 1;
	}

	for (int i = 0; i < count; i++){
		unsigned char *cipherTextServicePassword;
		int cipherTextServicePasswordLen;

		encryptData(entries[i].encryptedPassword, strlen(entries[i].encryptedPassword), newKey, newIv, &cipherTextServicePassword, &cipherTextServicePasswordLen);

		char * encodedServicePassword = base64Encode(cipherTextServicePassword, cipherTextServicePasswordLen);

		entries[i].encryptedPassword = (char *)malloc(cipherTextServicePasswordLen + 1);
		memcpy(entries[i].encryptedPassword, encodedServicePassword, strlen(encodedServicePassword));
		entries[i].encryptedPassword[strlen(encodedServicePassword)] = '\0';

		if (addEntry(fileName, &entries[i]) != 0){
			fprintf(stderr, "Failed to add entry to vault.\n");
			return 1;
		}
	}

}

void removeNewlines(char *str) {
    char *pos;
    if ((pos = strchr(str, '\n')) != NULL) {
        *pos = '\0';
    }
}

int deleteEntry(const char *filename, const char *serviceName)
{
	unsigned char *key;
	MasterEntry masterEntry;
	getMasterEntryByFilename(filename, &masterEntry);

	size_t decodedMasterLen;
	size_t decodedIvLen;
	size_t decodedSaltLen;

	unsigned char *decodedHash = base64Decode(masterEntry.hash, &decodedMasterLen);
	unsigned char *decodedIv = base64Decode(masterEntry.iv, &decodedIvLen);
	unsigned char *decodedSalt = base64Decode(masterEntry.salt, &decodedSaltLen);

	if (authenticateUser(decodedHash, decodedMasterLen, decodedSalt, decodedIv, &key) != 0){
		return 1;
	}

	return removeEntry(filename, base64Encode(serviceName, strlen(serviceName)));
}

int listAllServices(const char *filename) {
	FILE* file = fopen(filename, "r");
    int count;
    MasterEntry masterEntry = {NULL, NULL, NULL};
    ServiceEntry *entries = readVaultEntries(file, &count, &masterEntry);
    //freeMasterEntry(masterEntry);
    fclose(file);

    if (entries == NULL) {
        return 1;
    }

    size_t decodedLen;
    for (int i = 0; i < count; i++) {
    	unsigned char* decodedServiceName = base64Decode(entries[i].serviceName, &decodedLen);
    	decodedServiceName[decodedLen] = '\0';
        printf("%s\n", decodedServiceName);
    }

    freeServiceEntries(entries, count);
    return 0;
}

int readServicePassword(const char *filename, const char *service)
{
	return -1;
}

