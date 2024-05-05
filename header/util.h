#ifndef UTIL_H_
#define UTIL_H_

char* dynamicFGets(FILE* file);
int cbPemPassword(char *buf, int size, int rwflag, void *u);
void displayAndErase(const char* buffer, int bufferLen);

#endif
