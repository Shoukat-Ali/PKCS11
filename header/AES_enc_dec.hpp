/**
 * This program is an attempt to encrypt and decrypt data using Advanced Encryption Standard (AES).
 * For the secret key, this program uses the functionalities of gen_AES_keys program. 
 * The following operations are be performed in this program
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


#ifndef AES_ENC_DEC_HPP
#define AES_ENC_DEC_HPP

#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int encrypt_plaintext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hSecretkey,
                        CK_CHAR_PTR ptPtr, const size_t ptLen, 
                        CK_BYTE_PTR ctPtr, size_t ctLen);


int decrypt_ciphertext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hSecretkey,
                        CK_CHAR_PTR ctPtr, const size_t ctLen, 
                        CK_BYTE_PTR ptPtr, size_t ptLen);

#endif