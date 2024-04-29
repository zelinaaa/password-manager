#include "CUnit/Basic.h"
#include "../header/cryptodef.h"

void base64Encode_test(){
	const char * toEncode = "TestHeslo123$&";
	const char * expectedEncodedStr = "VGVzdEhlc2xvMTIzJCY=";
	char *encoded = base64Encode((unsigned char *) toEncode, strlen(toEncode));

	CU_ASSERT_NSTRING_EQUAL(encoded, expectedEncodedStr, strlen(expectedEncodedStr));
}

void base64Decode_test(){
	const char * toDecode = "VGVzdEhlc2xvMTIzJCY=";
	const char * expectedDecodedStr = "TestHeslo123$&";
	size_t decodedLen;
	char *decoded = base64Decode(toDecode, &decodedLen);

	CU_ASSERT(decodedLen > 0);
	CU_ASSERT_NSTRING_EQUAL(decoded, expectedDecodedStr, strlen(expectedDecodedStr));
}

int encodingTest() {
	CU_pSuite pSuite = NULL;
	CU_pTest pTest = NULL;

	if ((pSuite = CU_add_suite("encoding functions", 0, 0)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "base64Encode_test", base64Encode_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((pTest = CU_add_test(pSuite, "base64Decode_test", base64Decode_test)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}
}
