#ifndef STORAGE_H_
#define STORAGE_H_

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


int writeMasterPassword(FILE *file, const MasterEntry *entry);
int writeServiceEntry(FILE *file, const ServiceEntry *entry);
ServiceEntry *readServiceEntries(FILE *file, int *count);
void freeServiceEntries(ServiceEntry *entries, int count);
int createNewVault(const char *filename, MasterEntry *entry);
int addEntry(const char *filename, ServiceEntry *entry);
int modifyEntry(const char *filename, const char *serviceName, ServiceEntry *entry);
int removeEntry(const char *filename, const char *serviceName);
int modifyMasterEntry(const char *filename, MasterEntry *entry);

#endif
