#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

unsigned char *base64Decode(char* encodedInput, size_t *decodeLen)
{
    BIO *bio = NULL, *b64 = NULL;
    unsigned char *buffer = NULL;

    size_t inputLen = strlen(encodedInput);

    char *inputWithNewline = malloc(inputLen + 2);
	if (!inputWithNewline) return NULL;

	strcpy(inputWithNewline, encodedInput);
	strcat(inputWithNewline, "\n");

    if(inputLen == 0){
    	BIO_free_all(bio);
		return buffer;
    }

    bio = BIO_new_mem_buf(inputWithNewline, -1);
    if(bio == NULL){
    	BIO_free_all(bio);
		return buffer;
    }
    b64 = BIO_new(BIO_f_base64());
    if(b64 == NULL){
    	BIO_free_all(bio);
		return buffer;
    }

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_push(b64, bio);

    buffer = (unsigned char*) malloc(sizeof(char)*(inputLen*3)/4);
    if (buffer == NULL){
    	BIO_free_all(bio);
		return buffer;
    }

    *decodeLen = (size_t) BIO_read(bio, buffer, (int) inputLen);

    BIO_free_all(bio);
	return buffer;
}

char *base64Encode(unsigned char *buffer, size_t bufferLen)
{
    BIO *bio = NULL, *b64Alg = NULL;
    BUF_MEM *bufferPointer = NULL;
    char *encodedText = NULL;

    if(bufferLen <= 0){
    	BIO_free_all(bio);
		return encodedText;
    }

    b64Alg = BIO_new(BIO_f_base64());
    if(b64Alg == NULL){
    	BIO_free_all(bio);
		return encodedText;
    }

    bio = BIO_new(BIO_s_mem());
    if(bio == NULL){
    	BIO_free_all(bio);
		return encodedText;
    }

    bio = BIO_push(b64Alg, bio);

    if(BIO_write(bio, buffer, (int)bufferLen) <= 0){
    	BIO_free_all(bio);
		return encodedText;
    }

    if(BIO_flush(bio) != 1){
    	BIO_free_all(bio);
		return encodedText;
    }

    BIO_get_mem_ptr(bio, &bufferPointer);

    encodedText = (char*) malloc((bufferPointer->length + 1) * sizeof(char));
    if(encodedText == NULL){
    	BIO_free_all(bio);
		return encodedText;
    }

    memcpy(encodedText, bufferPointer->data, bufferPointer->length);
    if(bufferPointer->length > 0){
    	encodedText[bufferPointer->length - 1] = '\0';
    }
    BIO_set_close(bio, BIO_NOCLOSE);

    BIO_free_all(bio);
	return encodedText;
}
