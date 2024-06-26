/**
 * This program is an attempt to perform RSA encryption scheme using the 
 * Optimal Asymmetric Encryption Padding (OAEP) padding scheme i.e., RSA-OAEP.
 * The following operations are performed
 * 
 * 		1. Encrypt given plaintext/data using 
 *          i.      C_EncryptInit()
 *          ii.     C_Encrypt()     // For now
 *      2. Decrypt given ciphertext/data using
 *          i.      C_DecryptInit() 
 *          ii.     C_Decrypt()     // For now
 * 		
 *  
*/


#ifndef RSA_OAEP_ES_HPP
#define RSA_OAEP_ES_HPP

#include <string>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int encrypt_plaintext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                    const CK_OBJECT_HANDLE& hPub, const std::string& plaintext,
                    std::string& ciphertext);


int decrypt_ciphertext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hPrv, const std::string& ciphertext,
                        std::string& plaintext);

#endif