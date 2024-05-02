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


void writeMasterPassword(FILE *file, const MasterEntry *entry);
void writeServiceEntry(FILE *file, const ServiceEntry *entry);
ServiceEntry *readServiceEntries(FILE *file, int *count);
void freeServiceEntries(ServiceEntry *entries, int count);
void createNewVault(const char *filename, MasterEntry *entry);
void addEntry(const char *filename, ServiceEntry *entry);
void modifyEntry(const char *filename, const char *serviceName, ServiceEntry *entry);
void removeEntry(const char *filename, const char *serviceName);
void modifyMasterEntry(const char *filename, MasterEntry *entry);

#endif
