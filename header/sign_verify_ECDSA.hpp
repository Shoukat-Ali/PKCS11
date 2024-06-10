/**
 * This program is an attempt to show the following operations
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB in order to use PKCS #11 functions
 *      2. Connect to valid slot using the followings
 *          i.      C_Initialize() 
 *          ii.     C_OpenSession() 
 *          iii.    C_Login()
 * 		3. Generate Elliptic Curve Digital Signature Algorithm (ECDSA) keypair (Public and Private keys) by invoking
 *          i.      C_GenerateKeyPair()
 *          ii.     Sign
 *          ii.     Verify 
 * 		4. Disconnect from a connect slot using the followings
 *          i.      C_Logout() 
 *          ii.     C_CloseSession() 
 *          iii.    C_Finalize()
 * 
 *  
*/


#ifndef SIGN_VERIFY_ECDSA_HPP
#define SIGN_VERIFY_ECDSA_HPP

#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int gen_ECDSA_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession,
					    CK_BYTE_PTR const ecPara, const CK_ULONG ecParaSZ,
					    CK_OBJECT_HANDLE_PTR hPubPtr, CK_OBJECT_HANDLE_PTR hPrvPtr);


int sign_data_no_hashing(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession,
						const CK_OBJECT_HANDLE& hPrv, CK_BYTE_PTR dataPtr, const CK_ULONG dataLen,
						CK_BYTE_PTR sigPtr, CK_ULONG sigLen);

int verify_data_no_hashing(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession,
							const CK_OBJECT_HANDLE& hPub, CK_BYTE_PTR dataPtr, const CK_ULONG dataLen,
							CK_BYTE_PTR sigPtr, CK_ULONG sigLen);


#endif