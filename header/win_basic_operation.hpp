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


#ifndef WIND_BASIC_OPERATION_HPP
#define WIND_BASIC_OPERATION_HPP

#include <iostream>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include
#include <windows.h>

// Operating system check
int load_library_HSM(HINSTANCE& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

int check_operation(const CK_RV rv, const char* message);

void free_resource(HINSTANCE& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);


/**
 * This function checks whether a given pointer is null or not.
 * 
 * ptr is a constant pointer to void type
 * 
 * If given pointer is null, then return true. Otherwise, faluse is returned.
 * 
*/
inline bool is_nullptr(void * const ptr)
{
	if (ptr) {
		return false;
	}
	std::cout << "Error, pointer is NULL\n";
	return true;
}



#endif