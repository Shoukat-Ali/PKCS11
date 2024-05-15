/**
 * This program is an attempt to show the following operations
 * 
 *      1. Load the HSM library by setting an environment variable SOFTHSM2_LIB in order to use PKCS #11 functions
 *      2. Show list of all slots (initialized or not) using C_GetSlotList() function
 *      3. Display some slot information using C_GetSlotInfo() function
 * 
*/


#ifndef SLOTS_LIST_HPP
#define SLOTS_LIST_HPP

#include <string>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int check_Operation(const CK_RV rv, const char* message);

int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

void free_Resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr, std::string& usrPIN);

#endif