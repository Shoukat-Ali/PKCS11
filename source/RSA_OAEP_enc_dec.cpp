#include <iostream>
#include "../header/basic_operation.hpp"
#include "../header/RSA_OAEP_enc_dec.hpp"

/**
 * CK_RSA_PKCS_OAEP_PARAMS is a structure that provides the parameters to the
 * CKM_RSA_PKCS_OAEP mechanism. The structure is defined as follows:
 *      
 *      typedef struct CK_RSA_PKCS_OAEP_PARAMS {CK_MECHANISM_TYPE hashAlg;
 *                                              CK_RSA_PKCS_MGF_TYPE mgf;
 *                                              CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
 *                                              CK_VOID_PTR pSourceData;
 *                                              CK_ULONG ulSourceDataLen;
 *                                              } CK_RSA_PKCS_OAEP_PARAMS;
 * 
 * The fields of the structure have the following meanings:
 * hashAlg; mechanism ID of the message digest algorithm used to
 *          calculate the digest of the encoding parameter
 * mgf; mask generation function (MGF) to use on the encoded block 
 * source; source of the encoding parameter 
 * pSourceData; data used as the input for the encoding parameter source
 * ulSourceDataLen; length of the encoding parameter source input
 * 
 */
CK_RSA_PKCS_OAEP_PARAMS paramOAEP;

/**
 * The function initializes the Optimal Asymmetric Encryption Padding (OAEP)
 * parameters to be used in the CKM_RSA_PKCS_OAEP mechanism
 * 
 * The function does not return anything.
 * 
 * TODO: this function might be moved to main() for direct initialization
 */
inline void init_OAEP()
{
    paramOAEP.hashAlg = CKM_SHA_1;
    paramOAEP.mgf = CKG_MGF1_SHA1;
    /**
     * CKZ_DATA_SPECIFIED is an array of CK_BYTE containing the value
     * of the encoding parameter. If the parameter is empty, 
     * pSourceData must be NULL and ulSourceDataLen must be zero.
     */
    paramOAEP.source = CKZ_DATA_SPECIFIED;
    paramOAEP.pSourceData = NULL;
    paramOAEP.ulSourceDataLen = 0;
    
}


/**
 * The function encrypts given plaintext using RAS-OAEP
 * 
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * hPub is an alias of public key handle
 * plaintext is an alias of plaintext (source) to be encrypted
 * ciphertext is an alias ciphertext (destination) to be returned
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned. 
 */
int encrypt_plaintext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                    const CK_OBJECT_HANDLE& hPub, const std::string& plaintext,
                    std::string& ciphertext)
{
    int retVal = 0;
    CK_BYTE_PTR ctPtr = NULL_PTR;
    size_t ctLen = 0;
    
    // Checking given pointers is null or not 
	if (is_nullptr(funclistPtr)) {
		return 4;
	}
	init_OAEP();
	CK_MECHANISM encMech = {CKM_RSA_PKCS_OAEP, &paramOAEP, sizeof(paramOAEP)};
	
    retVal = check_operation(funclistPtr->C_EncryptInit(hSession, &encMech, hPub), "C_EncryptInit()");
    
	if (!retVal) {
        // The encryption operation successfully initialized
        retVal = check_operation(funclistPtr->C_Encrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(plaintext.c_str())),
                                            plaintext.length(), NULL_PTR, &ctLen), "C_Encrypt()");
                                            
        ctPtr = new CK_BYTE[ctLen];
        retVal = check_operation(funclistPtr->C_Encrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(plaintext.c_str())),
                                            plaintext.length(), ctPtr, &ctLen), "C_Encrypt()");

        ciphertext.assign(ctPtr, ctPtr + ctLen);
        delete[] ctPtr;   // Memory de-allocated
    }
    return retVal;
}



/**
 * The function encrypts given plaintext using RAS-OAEP
 * 
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * hPrv is an alias of private key handle
 * ciphertext is an alias ciphertext (source) to be decrypted
 * plaintext is an alias of plaintext (destination) to be returned
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned. 
 */
int decrypt_ciphertext(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
                        const CK_OBJECT_HANDLE& hPrv, const std::string& ciphertext,
                        std::string& plaintext)
{
    int retVal = 0;
    CK_BYTE_PTR dtPtr = NULL_PTR;
    size_t dtLen = 0;
    
    // Checking given pointers is null or not 
	if (is_nullptr(funclistPtr)) {
		return 4;
	}
	CK_MECHANISM encMech = {CKM_RSA_PKCS_OAEP, &paramOAEP, sizeof(paramOAEP)};
	
    retVal = check_operation(funclistPtr->C_DecryptInit(hSession, &encMech, hPrv), "C_DecryptInit()");
    
	if (!retVal) {
        // The encryption operation successfully initialized
        retVal = check_operation(funclistPtr->C_Decrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(ciphertext.c_str())),
                                            ciphertext.length(), NULL_PTR, &dtLen), "C_Decrypt()");
                                            
        dtPtr = new CK_BYTE[dtLen];
        retVal = check_operation(funclistPtr->C_Decrypt(hSession, reinterpret_cast<CK_CHAR_PTR>(const_cast<char*>(ciphertext.c_str())),
                                            ciphertext.length(), dtPtr, &dtLen), "C_Decrypt()");

        plaintext.assign(dtPtr, dtPtr + dtLen);
        delete[] dtPtr;   // Memory de-allocated
    }
    return retVal;
}