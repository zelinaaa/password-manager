#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "../header/util.h"

int cbPemPassword(char *buf, int size, int rwflag, void *u){
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;

	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT));

	if (!fgets(buf, size, stdin)) {
		buf[0] = '\0';
	} else {
		char *pos;
		if ((pos = strchr(buf, '\n')) != NULL) {
			*pos = '\0';
		}
	}

	SetConsoleMode(hStdin, mode);
	return strlen(buf);
}


char* dynamicFGets(FILE* file) {
    char *buffer = NULL;
    char tempBuffer[128];
    size_t bufferLength = 0;
    size_t totalReadLength = 0;
    const size_t MAX_LINE_LENGTH = 4096;

    while (fgets(tempBuffer, sizeof(tempBuffer), file)) {
        size_t chunkLength = strlen(tempBuffer);
        if (totalReadLength + chunkLength > MAX_LINE_LENGTH) {
            free(buffer);
            fprintf(stderr, "Error: Line too long. Exceeds maximum allowed length.\n");
            return NULL;
        }

        char *newBuffer = realloc(buffer, bufferLength + chunkLength + 1);
        if (!newBuffer) {
            free(buffer);
            fprintf(stderr, "Error: Memory allocation failed.\n");
            return NULL;
        }
        buffer = newBuffer;
        memcpy(buffer + bufferLength, tempBuffer, chunkLength + 1);
        bufferLength += chunkLength;
        totalReadLength += chunkLength;

        if (buffer[bufferLength - 1] == '\n') {
            break;
        }
    }

    if (buffer && bufferLength > 0 && buffer[bufferLength - 1] != '\n') {
        buffer = realloc(buffer, bufferLength + 2);
        if (!buffer) {
            fprintf(stderr, "Error: Memory reallocation failed.\n");
            return NULL;
        }
        buffer[bufferLength] = '\n';
        buffer[bufferLength + 1] = '\0';
    }

    return buffer;
}
