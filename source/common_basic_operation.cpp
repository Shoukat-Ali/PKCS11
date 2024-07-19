#include <iostream>
#ifdef WIND
    #include "..\header\common_basic_operaiton.hpp"
#else
    #include "../header/common_basic_operaiton.hpp"
#endif 

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
		std::cout << "Error, " << message << " failed with RV : " << rv << std::endl;
		return 1;
	}
	return 0;
}


