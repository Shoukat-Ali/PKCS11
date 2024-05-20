/**
 * This program is an attempt to show the following operations
 * 
 *  
*/


#ifndef ECDSA_KEYPAIR_HPP
#define ECDSA_KEYPAIR_HPP

#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int check_operation(const CK_RV rv, const char* message);

int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

#endif