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

#include <string>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int init_Mech(CK_SESSION_HANDLE& hSession, CK_BYTE_PTR const ptrIV, const size_t lenIV);

int encrypt_plaintext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hSecretkey,
                        const std::string& plaintext, std::string& ciphertext);


int decrypt_ciphertext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hSecretkey,
                        const std::string& ciphertext, std::string& decryptext);

#endif