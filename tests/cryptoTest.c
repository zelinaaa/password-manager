#include "CUnit/Basic.h"
#include "../header/cryptodef.h"

/*
 * This file contains all the tests related to cryptographic functionalities
 */

void encryptData_test(){
	const char *plainText = "The OpenSSL Project develops and maintains the OpenSSL software";
	int plainTextLen = strlen(plainText);
	unsigned char *key = (unsigned char*)"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50";
	unsigned char *iv = "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50";
	unsigned char *cipherText;
	unsigned char* expectedCipherText = "\x12\x6D\x44\xC6\x89\x3D\x66\x55\xA5\xBB\x30\x77\x96\xC1\x8C\xBD\x33\x37\x10\x96\xA7\x5E\x3F\x0D\x62\x29\x4A\x87\xCC\x2D\xA9\xF5\xD7\x7F\x15\xEB\x81\x5E\x32\xB4\x5A\x5F\x72\x3F\x2A\xFE\x16\x44\xEB\xB9\xD6\x8A\x9A\xC4\x85\xD3\x0B\x8E\x63\x2E\x53\xAE\xF5\x56";
	int cipherTextLen = 0;

	CU_ASSERT_EQUAL(encryptData(plainText, plainTextLen, key, iv, &cipherText, &cipherTextLen), 0);
	CU_ASSERT(cipherTextLen > 0);
	CU_ASSERT_NSTRING_EQUAL(cipherText, expectedCipherText, strlen(expectedCipherText));
}

void decryptData_test(){
	const char *cipherText = "\x12\x6D\x44\xC6\x89\x3D\x66\x55\xA5\xBB\x30\x77\x96\xC1\x8C\xBD\x33\x37\x10\x96\xA7\x5E\x3F\x0D\x62\x29\x4A\x87\xCC\x2D\xA9\xF5\xD7\x7F\x15\xEB\x81\x5E\x32\xB4\x5A\x5F\x72\x3F\x2A\xFE\x16\x44\xEB\xB9\xD6\x8A\x9A\xC4\x85\xD3\x0B\x8E\x63\x2E\x53\xAE\xF5\x56";
	int cipherTextLen = strlen(cipherText);
	unsigned char *key = (unsigned char*)"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50";
	unsigned char *iv = "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50";
	unsigned char *plainText;
	unsigned char *expectedPlainText = "The OpenSSL Project develops and maintains the OpenSSL software";
	int plainTextLen = 0;

	CU_ASSERT_EQUAL(decryptData(cipherText, cipherTextLen, key, iv, &plainText, &plainTextLen), 0);
	CU_ASSERT(plainTextLen > 0);
	CU_ASSERT_NSTRING_EQUAL(plainText, expectedPlainText, strlen(expectedPlainText));
}

void deriveKey_test(){
	const char *password = "VeryLongAndSafeMasterPassword123!";
	const char *salt = "16BytesLongSalt!";
	unsigned char* expectedKey = (unsigned char*)"\xBF\x46\x3E\x76\x3B\x3A\x96\xD6\x83\xBF\x65\x17\x14\x83\x3A\x84\x42\xA8\x80\x05\xF8\x47\x45\x60\x31\xF5\x48\xFF\xA8\x99\xA9\x15";
	unsigned char *key = (unsigned char*)deriveKey(password, salt);

	CU_ASSERT_PTR_NOT_NULL(key);
	CU_ASSERT_NSTRING_EQUAL(key, expectedKey, KEY_SIZE);
}

void hashData_test(){

	const char *plainText = "The OpenSSL Project develops and maintains the OpenSSL software - a robust, commercial-grade, full-featured toolkit for general-purpose cryptography and secure communication. The project’s technical decision making is managed by the OpenSSL Technical Committee (OTC) and the project governance is managed by the OpenSSL Management Committee (OMC). The project operates under formal Bylaws. For more information about the team and community around the project, or to start making your own contributions, start with the community page. To get the latest news, download the source, and so on, please see the sidebar or the buttons at the top of every page.";
	const char* expectedHash = "\x75\xF6\x0B\xA9\x06\xFD\x40\x8B\xF6\x77\xC3\x5A\x96\xC2\x5A\x56\x1B\xA8\x38\x65\x28\xC0\x4C\x45\xAA\x48\xB5\x36\x49\xC8\x1F\xF0";
	unsigned char* hash = NULL;

	CU_ASSERT_EQUAL(hashData(plainText, strlen(plainText), &hash), 0);
	CU_ASSERT_NSTRING_EQUAL(hash, expectedHash, SHA256_LENGTH);
}

void getRandomIV_test(){
	unsigned char* IV = NULL;
	IV = getRandomIV();

	CU_ASSERT_PTR_NOT_NULL(IV);
}

void getRandomSalt_test(){
	unsigned char* salt = NULL;
	salt = getRandomSalt();

	CU_ASSERT_PTR_NOT_NULL(salt);
}

int cryptoTest() {
	CU_pSuite pSuite = NULL;
	CU_pTest pTest = NULL;

	if ((pSuite = CU_add_suite("crypto functions", 0, 0)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "encryptData_test", encryptData_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "decryptData_test", decryptData_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "hashData_test", hashData_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "getRandomIV_test", getRandomIV_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "getRandomSalt_test", getRandomSalt_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "deriveKey_test", deriveKey_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}
}

