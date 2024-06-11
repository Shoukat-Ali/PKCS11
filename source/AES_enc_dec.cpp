#include <iostream>
#include <iterator>
#include "../header/basic_operation.hpp"
#include "../header/gen_AES_keys.hpp" 

using std::cout; 


// For now, to set IV length
// #define BYTE_LEN 16


/**
 * An initialization vector (IV) is used by several modes to randomize the encryption 
 * such that if the same plaintext is encrypted multiple times, then distinct ciphertexts
 * are produced. Usually, an IV usually does not need to be secret. 
 * For most block cipher modes, it is important that an IV is never reused under the same key.
 * 
 * TODO: generate random IV  
*/
CK_BYTE IV[] = "UTf34-ijhy;it1MB";


/**
 * 
 * CK_MECHANISM is a structure that specifies a particular mechanism and any parameters it requires.
 * 
 * typedef struct CK_MECHANISM {
 *              CK_MECHANISM_TYPE mechanism;
 *              CK_VOID_PTR pParameter;
 *              CK_ULONG ulParameterLen;
 * } CK_MECHANISM;
 * 
 * mechanismthe type of mechanism;
 * pParameterpointer to the parameter if required by the mechanism;
 * ulParameterLen length in bytes of the parameter
 * 
 * AES-CBC with PKCS padding, denoted CKM_AES_CBC_PAD, is a mechanism for
 * single- and multiple-part encryption and decryption.
 * It has a parameter, a 16-byte initialization vector.

*/
CK_MECHANISM encMech = {CKM_AES_CBC_PAD, IV, sizeof(IV)-1};



/**
 * The function encrypts given data using Advanced Encryption Standard (AES) with 
 * Cipher block chaining (CBC) mode i.e., CKM_AES_CBC_PAD
 * 
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * hSecretkey is an alias of secret key handle
 * ptPtr is a pointer to array of unsinged 8-bit character representing plaintext (source)
 * ptLen represents the byte-length of plaintext
 * ctPtr is a pointer to array of unsinged 8-bit character representing ciphertext (destination)
 * ctLen represents the byte-length of ciphertext
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int encrypt_plaintext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hSecretkey,
                        const std::string& plaintext, std::string& ciphertext)
{
    int retVal = 0;
    CK_BYTE_PTR ctPtr = NULL_PTR;
    size_t ctLen = 0;

    // Checking given pointers is null or not 
	if (is_nullptr(funclistPtr)) {
		return 4;
	}

    /**
     * CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
     *                      CK_MECHANISM_PTR pMechanism,
     *                      CK_OBJECT_HANDLE hKey);
     * 
     * C_EncryptInit() initializes an encryption operation. 
     * 
     * hSession is the session’s handle;
     * pMechanism points to the encryption mechanism; 
     * hKey is the handle of the encryption key.
     * 
     * After calling C_EncryptInit(), the application can either call C_Encrypt() to encrypt data
     * in a single part; or call C_EncryptUpdate() zero or more times, followed by
     * C_EncryptFinal(), to encrypt data in multiple parts. The encryption operation is active
     * until the application uses a call to C_Encrypt() or C_EncryptFinal() to actually obtain the
     * final piece of ciphertext.
    */
	retVal = check_operation(funclistPtr->C_EncryptInit(hSession, &encMech, hSecretkey), "C_EncryptInit()");
    if (!retVal) {
        // The encryption operation successfully initialized
        /**
         * CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
         *                          CK_BYTE_PTR pPart,
         *                          CK_ULONG ulPartLen,
         *                          CK_BYTE_PTR pEncryptedPart,
         *                          CK_ULONG_PTR pulEncryptedPartLen);
         * 
         * C_EncryptUpdate() continues a multiple-part encryption operation, processing another
         * data part. 
         * 
         * hSession is the session’s handle; 
         * pPart points to the data part; 
         * ulPartLen is the length of the data part; 
         * pEncryptedPart points to the location that receives the encrypted data part; 
         * pulEncryptedPartLen points to the location that holds the length in bytes of the encrypted data part.
         * 
        */
    //    retVal = check_operation(funclistPtr->C_EncryptUpdate(hSession, ptPtr, ptLen, ctPtr, &ctLen), "C_EncryptUpdate()");
       
       /**
        * CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
        *                   CK_BYTE_PTR pData,
        *                   CK_ULONG ulDataLen,
        *                   CK_BYTE_PTR pEncryptedData,
        *                   CK_ULONG_PTR pulEncryptedDataLen);
        * 
        * C_Encrypt() encrypts single-part data. 
        * 
        * hSession is the session’s handle; 
        * pData points to the data; 
        * ulDataLen is the length in bytes of the data; 
        * pEncryptedData points to the location that receives the encrypted data; 
        * pulEncryptedDataLen points to the location that holds the length in bytes of the encrypted data.
       */
      
    //   cout << "Plaintext byte-length :: " << plaintext.length() << endl
    //         << "Ciphertext byte-length :: " << ciphertext.length() << endl;

      retVal = check_operation(funclistPtr->C_Encrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(plaintext.c_str())), 
                                                        plaintext.length(), NULL_PTR, &ctLen), "C_Encrypt()");
    //   cout << "Required ciphertext byte-length :: " << ctLen << endl;
      ctPtr = new CK_BYTE[ctLen]; // Memory allocated

      retVal = check_operation(funclistPtr->C_Encrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(plaintext.c_str())), 
                                                        plaintext.length(), ctPtr, &ctLen), "C_Encrypt()");
      ciphertext.assign(ctPtr, ctPtr + ctLen);

      delete[] ctPtr;   // Memory de-allocated
    }

	return retVal;
}


/**
 * The function decrypts given ciphertext using Advanced Encryption Standard (AES) with 
 * Cipher block chaining (CBC) mode i.e., CKM_AES_CBC_PAD
 * 
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * hSecretkey is an alias of secret key handle
 * ctPtr is a pointer to array of unsinged 8-bit character representing ciphertext (source)
 * ctLen represents the byte-length of ciphertext
 * ptPtr is a pointer to array of unsinged 8-bit character representing plaintext (destination)
 * ptLen represents the byte-length of plaintext
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int decrypt_ciphertext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hSecretkey,
                        const std::string& ciphertext, std::string& decryptext)
{
	int retVal = 0;
    CK_BYTE_PTR dtPtr = NULL_PTR;
    size_t dtLen = 0;

    // Checking given pointers is null or not 
	if (is_nullptr(funclistPtr)) {
		return 5;
	}
    /**
     * CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
     *                      CK_MECHANISM_PTR pMechanism,
     *                      CK_OBJECT_HANDLE hKey);
     * 
     * C_DecryptInit() initializes a decryption operation. 
     * 
     * hSession is the session’s handle;
     * pMechanism points to the decryption mechanism; 
     * hKey is the handle of the decryption key.
     * 
     * After calling C_DecryptInit(), the application can either call C_Decrypt() to decrypt data
     * in a single part; or call C_DecryptUpdate() zero or more times, followed by
     * C_DecryptFinal(), to decrypt data in multiple parts.
    */
	retVal = check_operation(funclistPtr->C_DecryptInit(hSession, &encMech, hSecretkey), "C_DecryptInit()");
	if (!retVal) {
        // Decryption operation successfully initialized
        /**
         * CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
         *                  CK_BYTE_PTR pEncryptedData,
         *                  CK_ULONG ulEncryptedDataLen,
         *                  CK_BYTE_PTR pData,
         *                  CK_ULONG_PTR pulDataLen);
         * 
         * C_Decrypt() decrypts encrypted data in a single part. 
         * 
         * hSession is the session’s handle;
         * pEncryptedData points to the encrypted data; 
         * ulEncryptedDataLen is the length of the encrypted data; 
         * pData points to the location that receives the recovered data; 
         * pulDataLen points to the location that holds the length of the recovered data.
         * 
         * 
        */
        // cout << "Ciphertext byte-length :: " << ciphertext.length() << endl
        //      << "Decryptedtext byte-length :: " << decryptext.length() << endl;

        retVal = check_operation(funclistPtr->C_Decrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(ciphertext.c_str())), 
                                                        ciphertext.length(), NULL_PTR, &dtLen), "C_Decrypt()");
                                                        
        // cout << "Required decryptedtext byte-length :: " << dtLen << endl;
        dtPtr = new CK_BYTE[dtLen]; // Memory allocated
        
        retVal = check_operation(funclistPtr->C_Decrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(ciphertext.c_str())), 
                                                        ciphertext.length(), dtPtr, &dtLen), "C_Decrypt()");
                                                        
        decryptext.assign(dtPtr, dtPtr + dtLen);
        delete[] dtPtr;   // Memory de-allocated
    }
	return retVal;
}