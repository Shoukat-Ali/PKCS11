#include <iostream>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/gen_EC_keypair.hpp" 

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
		cout << "Error, " << message << " failed with RV : " << rv << endl;
		return 1;
	}
	return 0;
}



/**
 * The function attempts to load SoftHSM library in order to use PKCS# 11 functions/API.
 * 
 * libHandle is a void pointer for SoftHSM library handle
 * funclistPtr is an alias of pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 *  
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	const char *libPath = nullptr;
	
	libPath = getenv("SOFTHSM2_LIB");
	if(libPath == nullptr) {
		cout << "Error, SOFTHSM2_LIB environment variable is not set" << endl;
		return 2;
	}
	
	libHandle = dlopen(libPath, RTLD_NOW);
	if (!libHandle) {
		cout << "Error, failed to load SoftHSM library into memory from path " << libPath << endl;
		return 2;
	}
	
    CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(libHandle, "C_GetFunctionList");
	if (!C_GetFunctionList) {
		cout << "Error, dlsym() failed to find loaded SoftHSM library" << endl;
		return 2;
	}
	
    return check_operation(C_GetFunctionList(&funclistPtr), "C_GetFunctionList()");
	
}


/**
 * This function attempts to connect to a token. 
 * 
 * First, it initializes the Cryptoki/SoftHSM library; 
 * Second, attempts to open a new session by taking solt ID from the user;
 * Finally, attempts to perform login based on user inputs.
 * 
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * usrPIN is an alias to user PIN as string
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int connect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession, std::string& usrPIN)
{
	CK_SLOT_ID slotID = 0;
	int retVal = 0;

	retVal = check_operation(funclistPtr->C_Initialize(NULL_PTR), "C_Initialize()");
	if (!retVal) {
		// C_Initialize() was successful
		cout << "\tPlease enter the slot ID (integer): ";
		cin >> slotID;
		if (!cin.good()) {
			cout << "Error, slot ID is not integer\n";
			cin.clear();  //clearing all error state flags.
			cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n'); // skip/ignore bad input
			return 3;  
		}
		retVal = check_operation(funclistPtr->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
															NULL_PTR, NULL_PTR, &hSession), 
															"C_OpenSession()");
		if (!retVal) {
			// Session opened successfully
			cout << "\tPlease enter the User PIN: ";
			cin >> usrPIN;

			retVal = check_operation(funclistPtr->C_Login(hSession, CKU_USER,
														reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(usrPIN.c_str())),
														usrPIN.length()), "C_Login()");
		}
	}
	
	return retVal;
}



/**
 * This function attempts to disconnects from a token.
 * First, logs out the user from the token/slot; 
 * Second, closes the current session and; 
 * Finally, finalizes the SoftHSM library to indicate that application is finished with the Cryptoki library
 * 
 * funclistPtr is a const pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * hSession is an alias of session ID/handle
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int disconnect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession)
{
	int retVal = 0;
	retVal = check_operation(funclistPtr->C_Logout(hSession), "C_Logout()");
	if (!retVal) {
		// C_Logout() was successful
		retVal = check_operation(funclistPtr->C_CloseSession(hSession), "C_CloseSesion()");
		retVal = check_operation(funclistPtr->C_Finalize(NULL_PTR), "C_Finalize()");
	}
	
	return retVal;
}


/**
 * The functions attempts to perform cleanup by freeing memory/resources
 * First, decrements the reference count on SoftHSM library handle
 * Second, assigning null to the pointer to the list of PKCS #11 function
 * Lastily, removing/clearing the user PIN
 * 
 * libHandle is an alias of void pointer for SoftHSM library handle
 * funclistPtr is an alias of pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * usrPIN is an alias of user PIN
 * 
 * The function does not return anything 
*/
void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr, std::string& usrPIN)
{
	cout << "Clean up and free the resources\n";
	if (dlclose(libHandle)) {
		cout << "Error, dlclose() on softHSM library reference count\n";
	}
    funclistPtr = NULL_PTR;
    // Removes all characters from the usrPIN string and all pointers, references, and iterators are invalidated. 
    usrPIN.clear();
}



/**
 * The function generates Elliptic Curve (EC) keypair 
 * based on the given parameters.
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
 *  
*/
int gen_ECDSA_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SESSION_HANDLE& hSession)
{
	int retVal = 0;
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
    CK_UTF8CHAR pubLabel[] = "ecdsa_public";
    CK_UTF8CHAR priLabel[] = "ecdsa_private";
	// 06 05 2b 81 04 00 22
	/**
	 * To choose Elliptic Curve (EC) parameters, one can use openssl
	 * To get the list of EC, run the following command in a terminal
	 * 		openssl ecparam -list_curves 
	 * 
	 * To obtain the EC parameter in hexadecimal form, run the following command in a terminal
	 * 		openssl ecparam -name <name> -outform <PEM|DER> | xxd
	 * 
	 * For the secp521r1, we have 
	 * 		openssl ecparam -name secp521r1 -outform DER | xxd
	 * Output:
	 * 		0605 2b81 0400 23
	 * 
	*/
    CK_BYTE curve[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

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

    CK_ATTRIBUTE attribPub[] = 
    {
        {CKA_TOKEN,             &yes,               sizeof(CK_BBOOL)},
        {CKA_PRIVATE,           &no,                sizeof(CK_BBOOL)},
        {CKA_VERIFY,            &yes,               sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,           &yes,               sizeof(CK_BBOOL)},
        {CKA_EC_PARAMS,			&curve,		    sizeof(curve)},
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

	/**
	 * CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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

    check_operation(funclistPtr->C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, &hPublic, &hPrivate), "C_GenerateKeyPair");    
    cout << "ECDSA keypair generated as handle #" << hPublic << " for public key and handle #" << hPrivate << " for a private key." << endl;
    
}