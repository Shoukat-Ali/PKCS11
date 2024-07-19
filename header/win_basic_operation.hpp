/**
 * This program is an attempt to show the basic common operations required in the implementatoin of the other
 * programs in this PKCS #11 demonstration
 * 
 *      1. Load the HSM library by setting an environment variable SOFTHSM2_LIB in order to use PKCS #11 functions
 *      2. Free the resources/memory
 *      
 * 
*/


#ifndef WIND_BASIC_OPERATION_HPP
#define WIND_BASIC_OPERATION_HPP

#include <iostream>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include
#include <windows.h>

int load_library_HSM(HINSTANCE& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

void free_resource(HINSTANCE& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

#endif