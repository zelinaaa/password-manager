#include "CUnit/Basic.h"

//TODO: define cryptoTest
int cryptoTest();
int encodingTest();

int main()
{
	if(CUE_SUCCESS != CU_initialize_registry())
	{
		return CU_get_error();
	}

	cryptoTest();
	encodingTest();

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	return CU_get_error();
}
