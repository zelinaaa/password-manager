#ifndef STORAGE_H_
#define STORAGE_H_

#define MASTER_ENTRY_COMPONENT_COUNT 3
#define SERVICE_ENTRY_COMPONENT_COUNT 3

typedef struct {
    char *hash;
    char *iv;
    char *salt;
} MasterEntry;

typedef struct {
    char *serviceName;
    char *login;
    char *encryptedPassword;
} ServiceEntry;


int writeMasterEntry(FILE *file, const MasterEntry *masterEntry);
int writeServiceEntry(FILE *file, const ServiceEntry *serviceEntry);
ServiceEntry* readVaultEntries(FILE *file, int *count, MasterEntry *masterEntry);
void freeServiceEntries(ServiceEntry *entries, int count);
int createNewVault(const char *filename, MasterEntry *masterEntry);
int addEntry(const char *filename, ServiceEntry *serviceEntry);
int modifyEntry(const char *filename, const char *serviceName, ServiceEntry *newServiceEntry);
int removeEntry(const char *filename, const char *serviceName);
int modifyMasterEntry(const char *filename, MasterEntry *masterEntry);
int getMasterEntry(FILE *file, MasterEntry* outMasterEntry);
int getMasterEntryByFilename(const char* filename, MasterEntry* outMasterEntry);

#endif
