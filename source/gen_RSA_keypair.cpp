#include <iostream>
#include "../header/basic_operation.hpp"

/**
 * The function attempts to generate RSA keypair (i.e., public and private keys) 
 * based on given bit size.
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
 * 
 */
int gen_RSA_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
					size_t modBitSz, CK_BYTE_PTR const pubExpn, const size_t pubExpnSz,
					CK_OBJECT_HANDLE_PTR hPubPtr, CK_OBJECT_HANDLE_PTR hPrvPtr)
{
    int retVal = 0;
    // Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 5;
	}
    /**
     * The CKM_RSA_PKCS_KEY_PAIR_GEN is a key pair generation mechanism based on
     * the RSA public-key cryptosystem, as defined in PKCS #1.
     * It does not have a parameter. The mechanism generates RSA public/private key 
     * pairs with a particular modulus length in bits and public exponent, 
     * as specified in the CKA_MODULUS_BITS and CKA_PUBLIC_EXPONENT attributes 
     * of the template for the public key. The CKA_PUBLIC_EXPONENT may be omitted 
     * in which case the mechanism shall supply the public exponent attribute 
     * using the default value of 0x10001 (65537).
     * 
    */
    CK_MECHANISM mechKey = {CKM_RSA_PKCS_KEY_PAIR_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR pubLabel[] = "RSA public key";
    CK_UTF8CHAR prvLabel[] = "RSA private key";

    /**
     * Defining the RSA public key attributes template
     */
    CK_ATTRIBUTE attribPub[] = {
        {CKA_TOKEN,             &yes,               sizeof(yes)},
        {CKA_PRIVATE,           &no,                sizeof(no)},
        {CKA_VERIFY,            &yes,               sizeof(yes)},
        {CKA_ENCRYPT,           &yes,               sizeof(yes)},
        {CKA_MODULUS_BITS,      &modBitSz,          sizeof(modBitSz)},      //RSA keypair bit-length
        {CKA_PUBLIC_EXPONENT,   pubExpn,            pubExpnSz},
        {CKA_LABEL,             &pubLabel,          sizeof(pubLabel)}
    };

    /**
     * Defining the RSA private key attributes template
     */
    CK_ATTRIBUTE attribPrv[] = {
        {CKA_TOKEN,             &yes,               sizeof(yes)},
        {CKA_PRIVATE,           &yes,               sizeof(yes)},
        {CKA_SIGN,              &yes,               sizeof(yes)},
        {CKA_DECRYPT,           &yes,               sizeof(yes)},
        {CKA_SENSITIVE,         &yes,               sizeof(yes)},
        {CKA_LABEL,             &prvLabel,          sizeof(prvLabel)}
    };


    return retVal;
}