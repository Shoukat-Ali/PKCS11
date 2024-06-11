/**
 * This program is an attempt to show the following operations
 * 
 * 		1. Generate Elliptic Curve (EC) keypair (Public and Private keys) by invoking
 *          i.      C_GenerateKeyPair() 
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