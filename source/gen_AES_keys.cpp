#include <iostream>
#include "../header/basic_operation.hpp"
#include "../header/gen_AES_keys.hpp" 


/**
 * This mechanism does not have a parameter
 * 
 * */
CK_MECHANISM keyMech = {CKM_AES_KEY_GEN};



/**
 * The function generates AES secret key based on given parameters
 * 
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * keyhandPtr is a pointer to secret key handle
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int gen_AES_key(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
				CK_OBJECT_HANDLE_PTR hkeyPtr, CK_ULONG& keyLen,
				const std::string& keyLabel)
{
	int retVal = 0;
	CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 4;
	}
    

    CK_ATTRIBUTE keyAttrb[] = {
		{CKA_TOKEN,				&yes,									sizeof(yes)},
        {CKA_PRIVATE,			&yes,									sizeof(yes)},
        {CKA_SENSITIVE,			&yes,									sizeof(yes)},
        {CKA_EXTRACTABLE,		&yes,									sizeof(yes)},
        {CKA_MODIFIABLE,		&no,									sizeof(no)},
        {CKA_ENCRYPT,			&yes,									sizeof(yes)},
        {CKA_DECRYPT,			&yes,									sizeof(yes)},
        {CKA_LABEL,				const_cast<char*>(keyLabel.c_str()),	keyLabel.length()},
		{CKA_VALUE_LEN,			&keyLen,								sizeof(keyLen)}
    };

    /**
	 * CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, 
	 * 						CK_MECHANISM_PTR pMechanism,
	 * 						CK_ATTRIBUTE_PTR pTemplate,
	 * 						CK_ULONG ulCount,
	 * 						CK_OBJECT_HANDLE_PTR phKey);
	 * 
	 * C_GenerateKey() generates a secret key or set of domain parameters, creating a new object. 
	 * 
	 * hSession is the session’s handle; 
	 * pMechanism points to the generation mechanism; 
	 * pTemplate points to the template for the new key or set of domain parameters; 
	 * ulCount is the number of attributes in the template; 
	 * phKey points to the location that receives the handle of the new key or set of domain parameters.
	 * 
	 * Since the type of key or domain parameters to be generated is implicit in the generation
	 * mechanism, the template does not need to supply a key type. The CKA_CLASS attribute is
	 * treated similarly.
	*/
    retVal = check_operation(funclistPtr->C_GenerateKey(hSession, &keyMech, keyAttrb, 
														sizeof(keyAttrb) / sizeof(*keyAttrb), 
														hkeyPtr), "C_GenerateKey()");

    return retVal;
}



