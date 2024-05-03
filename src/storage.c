#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../header/storage.h"
#include "../header/util.h"

int writeMasterEntry(FILE *file, const MasterEntry *masterEntry) {
    return fprintf(file, "$%s:%s:%s$\n", masterEntry->hash, masterEntry->iv, masterEntry->salt) < 0;
}

int writeServiceEntry(FILE *file, const ServiceEntry *serviceEntry) {
    return fprintf(file, "@%s:%s:%s@\n", serviceEntry->serviceName, serviceEntry->login, serviceEntry->encryptedPassword) < 0;
}

ServiceEntry* readVaultEntries(FILE *file, int *count, MasterEntry *masterEntry) {
    char *line = NULL;
    int capacity = 10;
    *count = 0;
    ServiceEntry *entries = malloc(capacity * sizeof(ServiceEntry));
    if (!entries) return NULL;

    //Master entry
    if((line = dynamicFGets(file))){
    	if (line[0] != '$'){
    		fprintf(stderr, "Failed to read master entry\n");
    		free(line);
    		free(entries);
    		return NULL;
    	}

    	char *masterComponents[MASTER_ENTRY_COMPONENT_COUNT] = {NULL, NULL, NULL};
    	char *ptr = strtok(line + 1, ":$");
    	int i = 0;
    	while (ptr && i < MASTER_ENTRY_COMPONENT_COUNT) {
    		masterComponents[i++] = ptr;
    		ptr = strtok(NULL, ":$");
    	}

    	if (i != MASTER_ENTRY_COMPONENT_COUNT) {
    		fprintf(stderr, "Failed to parse master entry\n");
    		free(line);
    		free(entries);
    		return NULL;
    	}

    	masterEntry->hash = strdup(masterComponents[0]);
    	masterEntry->iv = strdup(masterComponents[1]);
    	masterEntry->salt = strdup(masterComponents[2]);

    	if (!masterEntry->hash || !masterEntry->iv || !masterEntry->salt) {
    		fprintf(stderr, "Failed to allocate memory for master entry components\n");
    		free(masterEntry->hash);
    		free(masterEntry->iv);
    		free(masterEntry->salt);
    		free(line);
    		free(entries);
    		return NULL;
    	}

    	free(line);
    }

    while ((line = dynamicFGets(file)) && line[0] == '@') {
        if (*count >= capacity) {
        	capacity *= 2;
        	ServiceEntry *temp_entries = realloc(entries, capacity * sizeof(ServiceEntry));
        	if (!temp_entries) {
        		fprintf(stderr, "Failed to allocate memory for service entries\n");
            	freeServiceEntries(entries, *count);
            	free(entries);
            	free(line);
            	return NULL;
        	}
        	entries = temp_entries;
    	}

        char *serviceComponent[SERVICE_ENTRY_COMPONENT_COUNT] = {NULL, NULL, NULL};
        char *ptr = strtok(line + 1, ":@");
        int i = 0;
        while (ptr && i < SERVICE_ENTRY_COMPONENT_COUNT) {
        	serviceComponent[i++] = ptr;
            ptr = strtok(NULL, ":@");
        }

        if (i != SERVICE_ENTRY_COMPONENT_COUNT) {
            fprintf(stderr, "Failed to parse service entry\n");
            continue;
        }

        ServiceEntry *entry = &entries[*count];
        entry->serviceName = strdup(serviceComponent[0]);
        entry->login = strdup(serviceComponent[1]);
        entry->encryptedPassword = strdup(serviceComponent[2]);

        free(line);

        if (!entry->serviceName || !entry->login || !entry->encryptedPassword) {
            fprintf(stderr, "Failed to allocate memory for service entry components\n");
            free(entry->serviceName);
            free(entry->login);
            free(entry->encryptedPassword);
            continue;
        }
        (*count)++;
    }

    if(line)
    	free(line);

    return entries;
}

void freeServiceEntries(ServiceEntry *entries, int count) {
    for (int i = 0; i < count; i++) {
        free(entries[i].serviceName);
        free(entries[i].login);
        free(entries[i].encryptedPassword);
    }
    free(entries);
}

void freeMasterEntry(MasterEntry* masterEntry)
{
	free(masterEntry->hash);
	free(masterEntry->iv);
	free(masterEntry->salt);
}

int createNewVault(const char *filename, MasterEntry *masterEntry) {
    FILE *file = fopen(filename, "w");
    if (!file) return -1;
    int result = writeMasterEntry(file, masterEntry);
    fclose(file);
    return 0;
}

int addEntry(const char *filename, ServiceEntry *serviceEntry) {
    FILE *file = fopen(filename, "a");
    if (!file) return -1;
    int result = writeServiceEntry(file, serviceEntry);
    fclose(file);
    return 0;
}

int modifyEntry(const char *filename, const char *serviceName, ServiceEntry *newServiceEntry) {
    int count;
    MasterEntry masterEntry;
    FILE *file = fopen(filename, "r");
    if (!file) return -1;

    ServiceEntry *entries = readVaultEntries(file, &count, &masterEntry);
    fclose(file);

    file = fopen(filename, "w");
    if (!file) {
        freeServiceEntries(entries, count);
        return -1;
    }

    writeMasterEntry(file, &masterEntry);

    for (int i = 0; i < count; i++) {
        if (entries[i].serviceName) {
            if (strcmp(entries[i].serviceName, serviceName) == 0) {
                int result = writeServiceEntry(file, newServiceEntry);
                if (result != 0) {
                    fprintf(stderr, "Failed to write modified entry\n");
                    break;
                }
            } else {
                int result = writeServiceEntry(file, &entries[i]);
                if (result != 0) {
                    fprintf(stderr, "Failed to write service entry\n");
                    break;
                }
            }
        }
    }

    freeMasterEntry(&masterEntry);
    freeServiceEntries(entries, count);
    fclose(file);
    return 0;
}

int removeEntry(const char *filename, const char *serviceName) {
    int count;
    MasterEntry masterEntry;
    FILE *file = fopen(filename, "r");
    if (!file) return -1;

    ServiceEntry *entries = readVaultEntries(file, &count, &masterEntry);
    fclose(file);

    file = fopen(filename, "w");
    if (!file) {
        freeServiceEntries(entries, count);
        return -1;
    }

    writeMasterEntry(file, &masterEntry);
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].serviceName, serviceName) != 0) {
            writeServiceEntry(file, &entries[i]);
        }
    }
    fclose(file);
    freeServiceEntries(entries, count);
    return 0;
}

int modifyMasterEntry(const char *filename, MasterEntry *newMasterEntry) {
    int count;
    MasterEntry currentMasterEntry;
    FILE *file = fopen(filename, "r");
    if (!file) return -1;

    ServiceEntry *entries = readVaultEntries(file, &count, &currentMasterEntry);
    fclose(file);

    file = fopen(filename, "w");
    if (!file) {
        freeServiceEntries(entries, count);
        return -1;
    }

    if (writeMasterEntry(file, newMasterEntry) < 0) {
        fclose(file);
        freeServiceEntries(entries, count);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        if (writeServiceEntry(file, &entries[i]) < 0) {
            fprintf(stderr, "Failed to write service entry\n");
            fclose(file);
            freeServiceEntries(entries, count);
            return -1;
        }
    }

    fclose(file);
    freeServiceEntries(entries, count);
    return 0;
}
