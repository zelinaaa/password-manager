#ifndef ENCODING_H_
#define ENCODING_H_

unsigned char *base64Decode(char* encodedInput, size_t *outDecodeLen);
char *base64Encode(unsigned char *buffer, size_t bufferLen);

#endif
