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

/*Funkce pro precteni vsech sluzeb v vaultu. Nejprve se alokuje pamet velikosti entries na 10. Pozdeji pokud kapacita vaultu
 * presahuje 10 tak se velikost zdvojnasobi (alokuje se dvakrat tolik pameti) atd. Ukladame v podobe na prvnim radku ve formatu
 * $hash:iv:salt$ a na dalsim radku @sluzba:login:heslo@. Prvni nacteme do struktury masterEntry paramtery hash, iv a salt.
 * Mame jednotny system pro parsovani retezce, protoze vime ze znaky $ a : a @ se v base64 nenachazi tudiz nevznikne nikdy zadna
 * nerovnost. Po nacteni masterEntry struktury se postupne nactou sluzby po radcich.*/
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

/*Funkce pro nacteni pouze master hesla, iv a soli, tudiz prvniho radku.*/
int getMasterEntry(FILE *file, MasterEntry* outMasterEntry){
	char *line = NULL;

	if((line = dynamicFGets(file))){
		if (line[0] != '$'){
	    	fprintf(stderr, "Failed to read master entry\n");
	    	free(line);
	    	return -1;
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
	    	return -1;
	    }

	    outMasterEntry->hash = strdup(masterComponents[0]);
	    outMasterEntry->iv = strdup(masterComponents[1]);
	    outMasterEntry->salt = strdup(masterComponents[2]);

	    if (!outMasterEntry->hash || !outMasterEntry->iv || !outMasterEntry->salt) {
	    	fprintf(stderr, "Failed to allocate memory for master entry components\n");
	    	free(outMasterEntry->hash);
	    	free(outMasterEntry->iv);
	    	free(outMasterEntry->salt);
	    	free(line);
	    	return -1;
	    }

	    free(line);
	}

	return 0;
}

/*Pomocna funkce pro funkci getMasterEntry. Otevre soubor podle nazvu v parametru od uzivatele. */
int getMasterEntryByFilename(const char* filename, MasterEntry* outMasterEntry){
	FILE *file = fopen(filename, "r");
	if (!file) return -1;

	getMasterEntry(file, outMasterEntry);

	fclose(file);
	return 0;
}

/*Funkce pro nacteni sluzby.*/
int getServiceEntry(const char* filename, const char* serviceName, ServiceEntry* entry)
{
	int decodeLen;
	char* line = NULL;
	FILE* file = fopen(filename, "r");

	while ((line = dynamicFGets(file))) {
		if(line[0] == '@'){
			char *serviceComponent[SERVICE_ENTRY_COMPONENT_COUNT] = {NULL, NULL, NULL};
		    char *ptr = strtok(line + 1, ":@");

		    const char* decodedServiceName = base64Decode(ptr, &decodeLen);

		    if(strcmp(decodedServiceName, serviceName)){
		    	free(ptr);
		    	continue;
		    }

		    int i = 0;
		    while (ptr && i < SERVICE_ENTRY_COMPONENT_COUNT) {
		    	serviceComponent[i++] = ptr;
		        ptr = strtok(NULL, ":@");
		    }

		    entry->serviceName = strdup(serviceComponent[0]);
		    entry->login = strdup(serviceComponent[1]);
		    entry->encryptedPassword = strdup(serviceComponent[2]);

		    if (!entry->serviceName || !entry->login || !entry->encryptedPassword) {
		    	fprintf(stderr, "Failed to allocate memory for service entry components\n");
		    	free(entry->serviceName);
		    	free(entry->login);
		    	free(entry->encryptedPassword);
		    	free(line);
		    	return -1;
		    }

		    fclose(filename);
		    return 0;
		}
	}

	fclose(file);
	return -1;
}

/*Funkce pro uvolneni pameti v strukture ServiceEntry*/
void freeServiceEntries(ServiceEntry *entries, int count) {
    for (int i = 0; i < count; i++) {
        free(entries[i].serviceName);
        free(entries[i].login);
        free(entries[i].encryptedPassword);
    }
    free(entries);
}

/*Funkce pro uvolneni pameti v strukture MasterEntry*/
void freeMasterEntry(MasterEntry* masterEntry)
{
	free(masterEntry->hash);
	free(masterEntry->iv);
	free(masterEntry->salt);
}

/*Funkce pro vytvoreni noveho password vaultu, resp. jeho souboru. Pouzivana v jine funkci.*/
int createNewVault(const char *filename, MasterEntry *masterEntry) {
    FILE *file = fopen(filename, "w");
    if (!file) return -1;
    int result = writeMasterEntry(file, masterEntry);
    fclose(file);
    return 0;
}

/*Funkce pro pridani nove sluzby do vaultu, resp souboru. Pouzivana v jine funkci.*/
int addEntry(const char *filename, ServiceEntry *serviceEntry) {
    FILE *file = fopen(filename, "a");
    if (!file) return -1;
    int result = writeServiceEntry(file, serviceEntry);
    fclose(file);
    return 0;
}

/*Funkce pro editovani sluzby ve vaultu. Nejprve se prectou vsechny zaznamy ve vaultu. Pak se prepise soubor
 * a zapise se master heslo, iv a sul. Dale se zapisuji dalsi zaznamy a pokud se nejaky zaznam shoduje s
 * hledanym zaznamem tak se prepise. */
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

/*Funkce pro odstraneni zaznamu. Funguje na stejny princip jak modifyEntry, pokud se zaznam shoduje tak se nic neprovede, zbytek se zapise.*/
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

