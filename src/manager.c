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

	printf("Service Name: %s\n", modifiedEntry.serviceName);
	printf("Login: %s\n", modifiedEntry.login);
	printf("Encrypted Password: %s\n", modifiedEntry.encryptedPassword);

	if (modifyEntry(fileName, base64Encode(serviceName, strlen(serviceName)), &modifiedEntry) != 0){
		fprintf(stderr, "Failed to edit entry in vault.\n");
		return 1;
	}

	return 0;
}

void removeNewlines(char *str) {
    char *pos;
    if ((pos = strchr(str, '\n')) != NULL) {
        *pos = '\0';
    }
}





