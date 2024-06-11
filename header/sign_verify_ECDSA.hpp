/**
 * This program is an attempt to show the following operations
 * 
 * 		1. Generate Elliptic Curve Digital Signature Algorithm (ECDSA) keypair (Public and Private keys) by invoking
 *          i.		C_GenerateKeyPair()
 * 		2. Sign data using private key of ECDSA by invoking
 *          i.		C_SignInit()
 *          ii.		C_Sign () 
 * 		3. Verify given signature on data using public key of ECDSA by invoking
 *          i.      C_VerifyInit()
 *          ii.     C_Verify() 
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