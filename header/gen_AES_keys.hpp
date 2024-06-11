/**
 * This program is an attempt to generate Advanced Encryption Standard (AES) keys of sizes;
 * (a) 128-bit (16-byte), (b) 192-bit (24-byte), and (c) 256-bit (32-byte). 
 * The following operations will be performed
 * 
 * 		1. Generate AES key (symmetric key) by invoking
 *          i.      C_GenerateKey() 
 * 		
 *  
*/


#ifndef AES_KEYS_HPP
#define AES_KEYS_HPP

#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int gen_AES_key(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
				CK_OBJECT_HANDLE_PTR hkeyPtr, CK_ULONG& keyLen, const std::string& keyLabel);



#endif