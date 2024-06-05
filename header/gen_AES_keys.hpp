/**
 * This program is an attempt to generate Advanced Encryption Standard (AES) keys of sizes;
 * (a) 128-bit (16-byte), (b) 192-bit (24-byte), and (c) 256-bit (32-byte). 
 * The following operations will be performed
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB 
 *      in order to use PKCS #11 functions
 *      2. Connect to valid slot using the followings
 *          i.      C_Initialize() 
 *          ii.     C_OpenSession() 
 *          iii.    C_Login()
 * 		3. Generate AES key (symmetric key) by invoking
 *          i.      C_GenerateKey() 
 * 		4. Disconnect from a connect slot using the followings
 *          i.      C_Logout() 
 *          ii.     C_CloseSession() 
 *          iii.    C_Finalize()
 * 
 *  
*/


#ifndef AES_KEYS_HPP
#define AES_KEYS_HPP

#include <string>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int check_operation(const CK_RV rv, const char* message);

int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr);

int connect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession, std::string& usrPIN);

int gen_AES_key(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
				CK_OBJECT_HANDLE_PTR hkeyPtr, CK_ULONG& keyLen,
                const CK_UTF8CHAR_PTR keyLabel, const size_t klLen);

int disconnect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession);

void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr, std::string& usrPIN);


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
	std::cout << "Error, pointer is NULL\n";
	return true;
}


#endif