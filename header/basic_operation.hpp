/**
 * This program is an attempt to show the basic common operations required in the implementatoin of the other
 * programs in this PKCS #11 demonstration
 * 
 *      1. Load the HSM library by setting an environment variable SOFTHSM2_LIB in order to use PKCS #11 functions
 *      2. Check the PKCS #11 operation status i.e., CKR_OK
 *      3. Free the resources/memory
 *      4. Check to ensure null pointer is not used to call
 * 
*/


#ifndef BASIC_OPERATION_HPP
#define BASIC_OPERATION_HPP

#include <iostream>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include


int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);


#endif