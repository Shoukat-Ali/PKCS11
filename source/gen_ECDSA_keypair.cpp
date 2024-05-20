#include <iostream>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
 

using std::cout; 
using std::cin;
using std::endl;



/**
 * The function checks if a requested Cryptoki (PKCS #11) operation was a success or not.
 * 
 * rv represents the CK_RV value returned by Cryptoki function
 * message represent the Cryptoki operation 
 * 
 * If the CK_RV value is CKR_OK, then the operation was success and 0 is returned. 
 * Otherwise, non-zero integer is returned on failure.
 *  
*/
int check_operation(const CK_RV rv, const char* message)
{
	if (rv != CKR_OK) {
		cout << "Error, " << message << " failed with : " << rv << endl
			 << "RV : " << rv << endl;
		return 1;
	}
	return 0;
}



/**
 * 
*/
void generateECDSAKeyPair()
{
    CK_MECHANISM mech = {CKM_ECDSA_KEY_PAIR_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR pubLabel[] = "ecdsa_public";
    CK_UTF8CHAR priLabel[] = "ecdsa_private";
	// 06 05 2b 81 04 00 22
    CK_BYTE curve[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}; // hex representation for secp384r1 curve.

    CK_ATTRIBUTE attribPub[] = 
    {
        {CKA_TOKEN,             &yes,               sizeof(CK_BBOOL)},
        {CKA_PRIVATE,           &no,                sizeof(CK_BBOOL)},
        {CKA_VERIFY,            &yes,               sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,           &yes,               sizeof(CK_BBOOL)},
        {CKA_EC_PARAMS,		&curve,		    sizeof(curve)},
        {CKA_LABEL,             &pubLabel,          sizeof(pubLabel)}
    };
    CK_ULONG attribLenPub = sizeof(attribPub) / sizeof(*attribPub);

    CK_ATTRIBUTE attribPri[] = 
    {
        {CKA_TOKEN,             &yes,                sizeof(CK_BBOOL)},
        {CKA_PRIVATE,           &yes,               sizeof(CK_BBOOL)},
        {CKA_SIGN,              &yes,               sizeof(CK_BBOOL)},
        {CKA_DECRYPT,           &yes,               sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,         &yes,               sizeof(CK_BBOOL)},
        {CKA_LABEL,             &priLabel,          sizeof(priLabel)}
    };
    CK_ULONG attribLenPri = sizeof(attribPri) / sizeof(*attribPri);

    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, &hPublic, &hPrivate), "C_GenerateKeyPair");    
    cout << "ECDSA keypair generated as handle #" << hPublic << " for public key and handle #" << hPrivate << " for a private key." << endl;
    
}