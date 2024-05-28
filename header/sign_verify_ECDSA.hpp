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

#include <string>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int check_operation(const CK_RV rv, const char* message);

int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

int connect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession, std::string& usrPIN);

int disconnect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession);

int gen_ECDSA_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession,
					    CK_BYTE_PTR const ecPara, const size_t ecParaSZ,
					    CK_OBJECT_HANDLE_PTR hPubPtr, CK_OBJECT_HANDLE_PTR hPrvPtr);

void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr, std::string& usrPIN);

#endif