#include <stdio.h>
#include <string.h>
#include "../header/storage.h"
#include "../header/cryptodef.h"

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: %s -i <filename> (create new file to store passwords in)\n", argv[0]);
		printf("       %s -i <filename> -d (delete file containing passwords)\n", argv[0]);
		printf("       %s -f <filename> -a <service name> (add entry)\n", argv[0]);
		printf("       %s -f <filename> -d <service name> (delete entry)\n", argv[0]);
		printf("       %s -f <filename> -r (list all entries in the file with passwords)\n", argv[0]);
		printf("       %s -f <filename> -r <service name> (show decrypted password of an entry)\n", argv[0]);
		printf("       %s -f <filename> -e <service name> (edit entry)\n", argv[0]);
		printf("       %s -f <filename> -e (edit master password entry)\n", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-i") == 0) {
	        if (argc == 3) {
	            initVault(argv[2]);
	        } else if (argc == 4 && strcmp(argv[3], "-d") == 0) {
	            deleteVault(argv[2]);
	        } else {
	            printf("Invalid arguments for init vault operation\n");
	            return 1;
	        }
	} else if (strcmp(argv[1], "-f") == 0) {
		if (argc < 4) {
			printf("Invalid arguments for file operation\n");
			return 1;
		}
		char *fileName = argv[2];
		char *operation = argv[3];
		if (strcmp(operation, "-a") == 0) {
			if (argc != 5) {
				printf("Invalid arguments for add entry\n");
				return 1;
			}
			addService(argv[2], argv[4]);
		} else if (strcmp(operation, "-d") == 0) {
			if (argc != 5) {
				printf("Invalid arguments for delete entry\n");
				return 1;
			}
			deleteEntry(fileName, argv[4]); // implement
		} else if (strcmp(operation, "-r") == 0) {
			if (argc == 4) {
				listAllServices(fileName); //fix
				printf("%s - read file", argv[2]);
			} else if (argc == 5) {
				readServicePassword(fileName, argv[4]); //implement
			} else {
				printf("Invalid arguments for read operation\n");
				return 1;
			}
		} else if (strcmp(operation, "-e") == 0) {
			if (argc == 4) {
				editMaster(argv[2]);
			} else if (argc == 5) {
				editEntry(argv[2], argv[4]);
			} else {
				printf("Invalid arguments for read operation\n");
				return 1;
			}
		} else {
			printf("Invalid operation\n");
			return 1;
		}
	} else {
		printf("Invalid operation\n");
		return 1;
	}

	return 0;
}

