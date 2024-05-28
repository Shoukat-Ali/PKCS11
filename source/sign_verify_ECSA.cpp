#include <iostream>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/sign_verify_ECDSA.hpp" 

using std::cout; 
using std::cin;
using std::endl;



/**
 * The function checks if a requested Cryptoki (PKCS #11) operation was a success or not.
 * 
 * rv represents the CK_RV value returned by Cryptoki function
 * message represent the Cryptoki operation 
 * 
 * If the CK_RV value is CKR_OK, then the operation was success and 0 is returned. 
 * Otherwise, non-zero integer is returned on failure.
 *  
*/
int check_operation(const CK_RV rv, const char* message)
{
	if (rv != CKR_OK) {
		cout << "Error, " << message << " failed with RV : " << rv << endl;
		return 1;
	}
	return 0;
}



/**
 * This function checks whether a given pointer is null of not.
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
	cout << "Error, pointer is NULL\n";
	return true;
}
