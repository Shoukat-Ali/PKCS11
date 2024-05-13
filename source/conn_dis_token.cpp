#include <iostream>
#include <stdlib.h>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/conn_dis_token.hpp"
 

using std::cout, std::cin, std::endl;



/**
 * The function checks if a requested Cryptoki (PKCS #11) operation was a success or not.
 * rv represents the CK_RV value returned by Cryptoki function
 * message represent the Cryptoki operation 
 * 
 * If the CK_RV value is CKR_OK, then success and 0 is returned. 
 * Otherwise, non-zero integer is returned on failure.
 *  
*/
int check_Operation(const CK_RV rv, const char* message)
{
	if (rv != CKR_OK) {
		cout << "Error, " << message << " failed with : " << rv << endl
			 << "RV : " << rv << endl;
		return 1;
	}
	return 0;
}

