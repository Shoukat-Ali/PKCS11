#include <iostream>
#ifdef WIND
	#include "..\header\common_basic_operation.hpp"
	#include "..\header\gen_EC_keypair.hpp"
#else
	#include "../header/common_basic_operation.hpp"
	#include "../header/gen_EC_keypair.hpp"
#endif





/**
 * The function generates Elliptic Curve (EC) keypair 
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
int gen_EC_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
					CK_BYTE_PTR const ecPara, const size_t ecParaSZ,
					CK_OBJECT_HANDLE_PTR hPubPtr, CK_OBJECT_HANDLE_PTR hPrvPtr)
{
	int retVal = 0;

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 5;
	}

	/**
	 * A mechanism specifies precisely how a certain cryptographic process is to be performed.
	 * CK_MECHANISM is a structure that specifies a particular mechanism and any
	 * parameters it requires. It is defined as follows:
	 * 		typedef struct CK_MECHANISM {
	 * 						CK_MECHANISM_TYPE mechanism;
	 * 						CK_VOID_PTR pParameter;
	 * 						CK_ULONG ulParameterLen;
	 * 						} CK_MECHANISM;
	 * 
	 * The fields of the structure have the following meanings:
	 * mechanism is the type of mechanism e.g., CKM_ECDSA_KEY_PAIR_GEN or CKM_EC_KEY_PAIR_GEN
	 * pParameter is a pointer to the parameter if required by the mechanism
	 * ulParameterLen is the length in bytes of the parameter
	*/

    CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR pubLabel[] = "EC public key";
    CK_UTF8CHAR prvLabel[] = "EC private key";
	

	/**
	 * CK_ATTRIBUTE is a structure that includes the type, value, and length of an attribute.
	 * It is defined as follows:
	 * 		typedef struct CK_ATTRIBUTE {
	 * 					CK_ATTRIBUTE_TYPE type;
	 * 					CK_VOID_PTR pValue;
	 * 					CK_ULONG ulValueLen;
	 * 					} CK_ATTRIBUTE;
	 * 
	 * The fields of the structure have the following meanings:
	 * type represents the attribute type
	 * pValue is a pointer to the value of the attribute
	 * ulValueLen is the length in bytes of the value
	 * 
	 * If an attribute has no value, then ulValueLen = 0, and the value of pValue is irrelevant.
	 * An array of CK_ATTRIBUTEs is called a “template” and is used for creating,
	 * manipulating and searching for objects
	*/

    CK_ATTRIBUTE attribPub[] = {
        {CKA_TOKEN,				&yes,			sizeof(yes)},
        {CKA_PRIVATE,			&no,			sizeof(no)},
        {CKA_VERIFY,			&yes,			sizeof(yes)},
        {CKA_ENCRYPT,			&yes,			sizeof(yes)},
        {CKA_EC_PARAMS,			ecPara,			ecParaSZ},
        {CKA_LABEL,				&pubLabel,		sizeof(pubLabel)}
    };
    
    CK_ATTRIBUTE attribPrv[] = {
        {CKA_TOKEN,				&yes,			sizeof(yes)},
        {CKA_PRIVATE,			&yes,			sizeof(yes)},
        {CKA_SIGN,				&yes,			sizeof(yes)},
        {CKA_DECRYPT,			&yes,			sizeof(yes)},
        {CKA_SENSITIVE,			&yes,			sizeof(yes)},
        {CKA_LABEL,				&prvLabel,		sizeof(prvLabel)}
    };
    
	/**
	 * CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
	 * 							CK_MECHANISM_PTR pMechanism,
	 * 							CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	 * 							CK_ULONG ulPublicKeyAttributeCount,
	 * 							CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	 * 							CK_ULONG ulPrivateKeyAttributeCount,
	 * 							CK_OBJECT_HANDLE_PTR phPublicKey,
	 * 							CK_OBJECT_HANDLE_PTR phPrivateKey);
	 * 
	 * C_GenerateKeyPair() generates a public/private key pair, creating new key objects.
	 * 
	 * hSession is the session’s handle; 
	 * pMechanism points to the key generation mechanism;
	 * pPublicKeyTemplate points to the template for the public key;
	 * ulPublicKeyAttributeCount is the number of attributes in the public-key template;
	 * pPrivateKeyTemplate points to the template for the private key;
	 * ulPrivateKeyAttributeCount is the number of attributes in the private-key template;
	 * phPublicKey points to the location that receives the handle of the new public key;
	 * phPrivateKey points to the location that receives the handle of the new private key.
	 * 
	 * A call to C_GenerateKeyPair() will never create just one key and return. A call can fail,
	 * and create no keys; or it can succeed, and create a matching public/private key pair.
	 * 
	 * Since the types of keys to be generated are implicit in the key pair generation mechanism,
	 * the templates do not need to supply key types. If one of the templates does supply a key
	 * type which is inconsistent with the key generation mechanism, then C_GenerateKeyPair() 
	 * fails and returns an error.
	 * 
	*/
	retVal = check_operation(funclistPtr->C_GenerateKeyPair(hSession, &mech, 
											attribPub, sizeof(attribPub) / sizeof(*attribPub),
											attribPrv, sizeof(attribPrv) / sizeof(*attribPrv),
											hPubPtr, hPrvPtr), "C_GenerateKeyPair()");

	return retVal;    
}