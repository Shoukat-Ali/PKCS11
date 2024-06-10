/**
 * This program is an attempt to show the following operations
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB in order to use PKCS #11 functions
 *      2. Connect to valid slot using the followings
 *          i.      C_Initialize() 
 *          ii.     C_OpenSession() 
 *          iii.    C_Login()
 * 		3. Generate Elliptic Curve (EC) keypair (Public and Private keys) by invoking
 *          i.      C_GenerateKeyPair() 
 * 		4. Disconnect from a connect slot using the followings
 *          i.      C_Logout() 
 *          ii.     C_CloseSession() 
 *          iii.    C_Finalize()
 * 
 *  
*/


#ifndef EC_KEYPAIR_HPP
#define EC_KEYPAIR_HPP

#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include


int gen_EC_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
					CK_BYTE_PTR const ecPara, const size_t ecParaSZ,
					CK_OBJECT_HANDLE_PTR hPubPtr, CK_OBJECT_HANDLE_PTR hPrvPtr);


#endif