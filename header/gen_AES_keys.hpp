/**
 * This program is an attempt to generate Advanced Encryption Standard (AES) keys of sizes;
 * (a) 128-bit (16-byte), (b) 194-bit (24-byte), and (c) 256-bit (32-byte). 
 * The following operations will be performed
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB 
 *      in order to use PKCS #11 functions
 *      2. Connect to valid slot using the followings
 *          i.      C_Initialize() 
 *          ii.     C_OpenSession() 
 *          iii.    C_Login()
 * 		3. Generate AES key (symmetric key) by invoking
 *          i.      C_() 
 * 		4. Disconnect from a connect slot using the followings
 *          i.      C_Logout() 
 *          ii.     C_CloseSession() 
 *          iii.    C_Finalize()
 * 
 *  
*/


#ifndef AES_KEY_HPP
#define AES_KEY_HPP

#include <string>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int check_operation(const CK_RV rv, const char* message);

int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

int connect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession, std::string& usrPIN);

int disconnect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession);

void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr, std::string& usrPIN);

#endif