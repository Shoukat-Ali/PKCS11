#include <iostream>
#include "../header/basic_operation.hpp"
#include "../header/conn_dis_token.hpp"
#include "../header/gen_RSA_keypair.hpp"


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
 */
void init_OAEP()
{
    paramOAEP.hashAlg = CKM_SHA256;
    paramOAEP.mgf = CKG_MGF1_SHA256;
    /**
     * CKZ_DATA_SPECIFIED is an array of CK_BYTE containing the value
     * of the encoding parameter. If the parameter is empty, 
     * pSourceData must be NULL and ulSourceDataLen must be zero.
     */
    paramOAEP.source = CKZ_DATA_SPECIFIED;
    paramOAEP.pSourceData = NULL;
    paramOAEP.ulSourceDataLen = 0;
    
}