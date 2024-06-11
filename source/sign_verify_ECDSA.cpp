#include <iostream>
#include <limits>
#include "../header/basic_operation.hpp"
#include "../header/sign_verify_ECDSA.hpp" 

using std::cout; 

/**
 * The CKM_ECDSA denotes ECDSA without hashing mechanism.
 * It is a mechanism for single-part signatures and verification for ECDSA
 * This mechanism does not have a parameter
 * 
 * */
CK_MECHANISM signMech = {CKM_ECDSA};





/**
 * The function generates Elliptic Curve Digital Signature Algorithm (ECDSA) keypair 
 * based on the given parameters.
 * 
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * ecPara is a const pointer to CK_BYTE
 * ecParaSZ represents the byte-length of ecPara
 * hPubPtr is a pointer to public key handle
 * hPrvPtr is a pointer to private key handle
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
 *  
*/
int gen_ECDSA_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession,
						CK_BYTE_PTR const ecPara, const CK_ULONG ecParaSZ,
						CK_OBJECT_HANDLE_PTR hPubPtr, CK_OBJECT_HANDLE_PTR hPrvPtr)
{
	int retVal = 0;

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 5;
	}

	CK_MECHANISM mech = {CKM_ECDSA_KEY_PAIR_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR pubLabel[] = "ECDSA public key";
    CK_UTF8CHAR prvLabel[] = "ECDSA private key";
	

	CK_ATTRIBUTE attribPub[] = {
        {CKA_TOKEN,				&no,			sizeof(no)},
        {CKA_PRIVATE,			&no,			sizeof(no)},
        {CKA_VERIFY,			&yes,			sizeof(yes)},
        {CKA_ENCRYPT,			&yes,			sizeof(yes)},
        {CKA_ECDSA_PARAMS,		ecPara,			ecParaSZ},
        {CKA_LABEL,				&pubLabel,		sizeof(pubLabel)}
    };
    
    CK_ATTRIBUTE attribPrv[] = {
        {CKA_TOKEN,				&no,			sizeof(no)},
        {CKA_PRIVATE,			&yes,			sizeof(yes)},
        {CKA_SIGN,				&yes,			sizeof(yes)},
        {CKA_DECRYPT,			&yes,			sizeof(yes)},
        {CKA_SENSITIVE,			&yes,			sizeof(yes)},
        {CKA_LABEL,				&prvLabel,		sizeof(prvLabel)}
    };
    
	retVal = check_operation(funclistPtr->C_GenerateKeyPair(hSession, &mech, 
											attribPub, sizeof(attribPub) / sizeof(*attribPub),
											attribPrv, sizeof(attribPrv) / sizeof(*attribPrv),
											hPubPtr, hPrvPtr), "C_GenerateKeyPair()");

    if (!retVal) {
		cout << "Elliptic Curve Digital Signature Algorithm (ECDSA) keypair successfully generated\n";
	}
	return retVal;    
}



/**
 * The function signs given data using CKM_ECDSA
 * Note that private key should be used for signing
 * 
 * funclistPtr is a pointer to the const list of functions i.e., CK_FUNCTION_LIST_PTR 
 * hSession is an alias of constant session ID/handle
 * Prv is an alias of constant private key handle 
 * dataPtr is a pointer to byte array of data to be signed
 * dataLen is a constant unsigned long representing byte-length of data
 * sigPtr is a pointer to byte array of signature to be produced
 * sigLen is an unsigned long representing the byte-length of array where signature will be saved
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
 * 
 * Note that the signature byte-length (sigLen) should be set according to respective ECDSA
 * If one doesn't want to set sigLen in advance, then one can call C_Sign() twice
 * and in that case make sure that sigLen gets updated after returing to calling function
 * The first call should be used to set sigLen where sigPtr will be NULL
 * The second call should be used to compute the signature 
*/
int sign_data_no_hashing(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession,
						const CK_OBJECT_HANDLE& hPrv, CK_BYTE_PTR dataPtr, const CK_ULONG dataLen,
						CK_BYTE_PTR sigPtr, CK_ULONG sigLen)
{
	int retVal = 0;

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 6;
	}

	/**
	 * CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	 * 
	 * C_SignInit() initializes a signature operation, where the signature is an appendix to the data. 
	 * 
	 * hSession is the session’s handle; 
	 * pMechanism points to the signature mechanism;
	 * hKey is the handle of the signature key.
	 * 
	 * The CKA_SIGN attribute of the signature key, which indicates whether the key supports
	 * signatures with appendix, must be CK_TRUE.
	 * 
	 * After calling C_SignInit(), the application can either call C_Sign() to sign in a single part;
	 * or call C_SignUpdate() one or more times, followed by C_SignFinal(), to sign data in
	 * multiple parts.
	 * 
	*/
	retVal = check_operation(funclistPtr->C_SignInit(hSession, &signMech, hPrv), "C_SignInit()");
	if (!retVal) {
		// Signature mechnism has been successfully initialized
		/**
		 * CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		 * 				CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		 * 				CK_ULONG_PTR pulSignatureLen);
		 * 
		 * C_Sign() signs data in a single part, where the signature is an appendix to the data.
		 * 
		 * hSession is the session’s handle; 
		 * pData points to the data; 
		 * ulDataLen is the length of the data; 
		 * pSignature points to the location that receives the signature; 
		 * pulSignatureLen points to the location that holds the length of the signature.
		 * 
		*/
		retVal = check_operation(funclistPtr->C_Sign(hSession, dataPtr, dataLen, sigPtr, &sigLen), "C_Sign()");
	}
	return retVal;
}



/**
 * The function verifies the signed data using CKM_ECDSA
 * Note that public key should be used for verifying the signature
 * 
 * funclistPtr is a pointer to the constant list of functions i.e., CK_FUNCTION_LIST_PTR 
 * hSession is an alias of constant session ID/handle
 * Prv is an alias of constant public key handle 
 * dataPtr is a pointer to byte array of data that was signed
 * dataLen is a constant unsigned long representing byte-length of data
 * sigPtr is a pointer to byte array of given signature
 * sigLen is an unsigned long representing the byte-length of array where signature was stored
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
 * 
*/
int verify_data_no_hashing(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession,
							const CK_OBJECT_HANDLE& hPub, CK_BYTE_PTR dataPtr, const CK_ULONG dataLen,
							CK_BYTE_PTR sigPtr, CK_ULONG sigLen)
{
	int retVal = 0;
	
	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 7;
	}
	
	/**
	 * CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	 * 
	 * C_VerifyInit() initializes a verification operation, where the signature is an appendix to
	 * the data. 
	 * 
	 * hSession is the session’s handle; 
	 * pMechanism points to the structure that specifies the verification mechanism; 
	 * hKey is the handle of the verification key.
	 * 
	 * The CKA_VERIFY attribute of the verification key, which indicates whether the key
	 * supports verification where the signature is an appendix to the data, must be CK_TRUE.
	 * 
	 * After calling C_VerifyInit(), the application can either call C_Verify() to verify a signature
	 * on data in a single part; or call C_VerifyUpdate() one or more times, followed by
	 * C_VerifyFinal(), to verify a signature on data in multiple parts.
	 * 
	*/
	retVal = check_operation(funclistPtr->C_VerifyInit(hSession, &signMech, hPub), "C_VerifyInit()");
	if (!retVal) {
		// Signature verification operation successfully initialized
		/**
		 * CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		 * 					CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		 * 					CK_ULONG ulSignatureLen);
		 * 
		 * C_Verify() verifies a signature in a single-part operation, where the signature is an
		 * appendix to the data. 
		 * 
		 * hSession is the session’s handle; 
		 * pData points to the data;
		 * ulDataLen is the length of the data; 
		 * pSignature points to the signature; 
		 * ulSignatureLen is the length of the signature.
		 * 
		 * 
		*/
		retVal = check_operation(funclistPtr->C_Verify(hSession, dataPtr, dataLen, sigPtr, sigLen), "C_Verify");
	}
	return retVal;
}
