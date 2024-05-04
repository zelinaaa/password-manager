#ifndef MANAGER_H_
#define MANAGER_H_

int initVault(const char * fileName);
int deleteVault(const char *fileName);
int authenticateUser(const unsigned char *hashInput, size_t decodedMasterLen, const unsigned char *saltRead, const unsigned char *readIv, unsigned char **key);
int addService(const char * fileName, const char * serviceName);
int editEntry(const char *fileName, const char * serviceName);
void removeNewlines(char *str);

#endif
