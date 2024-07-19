/**
 * This program is an attempt to show the basic common operations required in the implementatoin of the other
 * programs in this PKCS #11 demonstration
 * 
 *      1. Check the PKCS #11 operation status i.e., CKR_OK
 *      2. Check to ensure null pointer is not used to call
 * 
*/


#ifndef COMMON_BASIC_OPERATION_HPP
#define COMMON_BASIC_OPERATION_HPP

#include <iostream>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

/**
 * The function checks if a requested Cryptoki (PKCS #11) operation was a success or not.
 * 
 */
int check_operation(const CK_RV rv, const char* message);


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