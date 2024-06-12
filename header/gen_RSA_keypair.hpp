/**
 * This program is an attempt to generate Rivest–Shamir–Adleman (RSA) keypair 
 * using the following operations
 * 
 * 		1. Generate RSA Public and Private keys by invoking
 *          i.      C_GenerateKeyPair() 
 * 		
 *  
*/


#ifndef RSA_KEYPAIR_HPP
#define RSA_KEYPAIR_HPP

#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include


int gen_RSA_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
					size_t modBitSz, CK_BYTE_PTR const pubExpn, const size_t pubExpnSz,
					CK_OBJECT_HANDLE_PTR hPubPtr, CK_OBJECT_HANDLE_PTR hPrvPtr);


#endif