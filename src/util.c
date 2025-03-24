#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <conio.h>
#include "../header/util.h"


/*Funkce pro zadavani neviditelnych znaku do konzole.*/
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

/*Funkce pro cteni zaznamu v souboru. V while cyklu se ctou radky. Pokud je prekrocena velikost
 * MAX_LINE_LENGTH tak je cteni ukonceno. V newBuffer je alokovana nova velikost chunku.
 * Do bufferu je nakopirovan chunk. Pokud je posledni znak novy radek tak je nacteny cely radek,
 * pokud ne tak se dal pokruje v cyklu v dalsim chunku. Nakonec pokud buffer neni prazdny a posledni
 * znak neni novy radek tak je nastaven novy radek na konec a nulovy znak.*/
char* dynamicFGets(FILE* file) {
    char *buffer = NULL;
    char tempBuffer[128];
    size_t bufferLength = 0;
    size_t totalReadLength = 0;
    const size_t MAX_LINE_LENGTH = 65536;

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

/*Funkce pro zobrazeni symbolu do konzole a nasledne po stisknuti klavesy jsou vymazany z konzole. Pro vetsi bezpecnost.*/
void displayAndErase(const char* buffer, int bufferLen) {
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	    CONSOLE_SCREEN_BUFFER_INFO csbi;
	    DWORD written;

	    if (!GetConsoleScreenBufferInfo(hStdout, &csbi)) {
	        fprintf(stderr, "Error getting console info.\n");
	        return;
	    }
	    DWORD originalAttributes = csbi.wAttributes;

	    SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);

	    fwrite(buffer, sizeof(char), bufferLen, stdout);
	    fflush(stdout);

	    SetConsoleTextAttribute(hStdout, originalAttributes);

	    printf("\n");

	    printf("Press any key to continue...");
	    _getch();

	    if (!GetConsoleScreenBufferInfo(hStdout, &csbi)) {
	        fprintf(stderr, "Error getting console info.\n");
	        return;
	    }
	    csbi.dwCursorPosition.X = 0;
	    FillConsoleOutputCharacter(hStdout, ' ', csbi.dwSize.X, csbi.dwCursorPosition, &written);

	    csbi.dwCursorPosition.Y--;
	    SetConsoleCursorPosition(hStdout, csbi.dwCursorPosition);

	    FillConsoleOutputCharacter(hStdout, ' ', csbi.dwSize.X, csbi.dwCursorPosition, &written);

	    csbi.dwCursorPosition.Y += 2;
	    SetConsoleCursorPosition(hStdout, csbi.dwCursorPosition);
}
