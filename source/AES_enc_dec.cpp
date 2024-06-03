#include <iostream>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/gen_AES_keys.hpp" 

using std::cout; 
using std::cin;
using std::endl;


/**
 * An initialization vector (IV) is used by several modes to randomize the encryption 
 * such that if the same plaintext is encrypted multiple times, then distinct ciphertexts
 * are produced. Usually, an IV usually does not need to be secret. 
 * For most block cipher modes, it is important that an IV is never reused under the same key.
 * 
 * TODO: generate random IV  
*/
CK_BYTE IV[] = {"UTf34-ijhy;it1MM"};


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
 * ptPtr is a pointer to array of unsinged 8-bit character representing plaintext
 * ctPtr is a pointer to array of unsinged 8-bit character representing ciphertext
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int encrypt_data(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                const CK_OBJECT_HANDLE& hSecretkey,
                CK_CHAR_PTR ptPtr, CK_BYTE_PTR ctPtr)
{
    int retVal = 0;

    // Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr) || is_nullptr(ptPtr)) {
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

    }
	return retVal;
}

