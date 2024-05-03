#include <stdio.h>
#include <stdlib.h>
#include "../header/storage.h"

// Write MasterPassword to file
int writeMasterEntry(FILE *file, const MasterEntry *entry) {
    fprintf(file, "$%s:%s:%s$\n", entry->hash, entry->iv, entry->salt);
    return 0;
}

// Write ServiceEntry to file
int writeServiceEntry(FILE *file, const ServiceEntry *entry) {
    fprintf(file, "@%s:%s:%s@\n", entry->serviceName, entry->login, entry->encryptedPassword);
    return 0;
}

// Read all service entries from file
ServiceEntry *readServiceEntries(FILE *file, int *count) {
    char line[1024];
    int capacity = 10;
    *count = 0;
    ServiceEntry *entries = malloc(capacity * sizeof(ServiceEntry));

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '@') {
            if (*count >= capacity) {
                capacity *= 2;
                entries = realloc(entries, capacity * sizeof(ServiceEntry));
            }
            char *token = strtok(line + 1, ":");
            entries[*count].serviceName = strdup(token);

            token = strtok(NULL, ":");
            entries[*count].login = strdup(token);

            token = strtok(NULL, "@");
            entries[*count].encryptedPassword = strdup(token);

            (*count)++;
        }
    }
    return entries;
}

// Free memory allocated for service entries
void freeServiceEntries(ServiceEntry *entries, int count) {
    for (int i = 0; i < count; i++) {
        free(entries[i].serviceName);
        free(entries[i].login);
        free(entries[i].encryptedPassword);
    }
    free(entries);
}

// Create a new vault file
int createNewVault(const char *filename, MasterEntry *entry) {
    FILE *file = fopen(filename, "w"); // Open file for writing
    if (file) {
        writeMasterEntry(file, entry); // Write the master password to file
        fclose(file);
    }
    return 0;
}

// Add a new service entry
int addEntry(const char *filename, ServiceEntry *entry) {
    FILE *file = fopen(filename, "a"); // Append to file
    if (file) {
        writeServiceEntry(file, entry);
        fclose(file);
    }

    return 0;
}

// Modify an existing entry
int modifyEntry(const char *filename, const char *serviceName, ServiceEntry *entry) {
	int count;
	ServiceEntry *entries = readServiceEntries(fopen(filename, "r"), &count);

	FILE *file = fopen(filename, "r+");
	if (file) {
	    for (int i = 0; i < count; i++) {
	        if (strcmp(entries[i].serviceName, serviceName) == 0) {
	            // Seek to the position of the entry to be modified
	            fseek(file, strlen(entries[i].serviceName) + strlen(entries[i].login) + strlen(entries[i].encryptedPassword) + 3, SEEK_SET);
	            writeServiceEntry(file, entry); // Write modified entry
	        } else {
	            writeServiceEntry(file, &entries[i]); // Write unmodified entry
	        }
	    }
	    fclose(file);
	}
	freeServiceEntries(entries, count);

	return 0;
}

// Remove an entry
int removeEntry(const char *filename, const char *serviceName) {
    int count;
    ServiceEntry *entries = readServiceEntries(fopen(filename, "r"), &count);

    FILE *file = fopen(filename, "w");
    if (file) {
        for (int i = 0; i < count; i++) {
            if (strcmp(entries[i].serviceName, serviceName) != 0) {
                writeServiceEntry(file, &entries[i]); // Write all except the one to remove
            }
        }
        fclose(file);
    }
    freeServiceEntries(entries, count);
    return 0;
}

// Modify the master password entry
int modifyMasterEntry(const char *filename, MasterEntry *entry) {
    FILE *file = fopen(filename, "r+");
    if (file) {
        writeMasterEntry(file, entry); // Overwrite the old master password
        fclose(file);
    }

    return 0;
}
