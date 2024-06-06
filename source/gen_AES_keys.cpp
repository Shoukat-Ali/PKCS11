#include <iostream>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/gen_AES_keys.hpp" 

using std::cout; 
using std::cin;
using std::endl;
using std::string;

/**
 * This mechanism does not have a parameter
 * 
 * */
CK_MECHANISM keyMech = {CKM_AES_KEY_GEN};



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
	char* libError;
	
	const char* libPath = getenv("SOFTHSM2_LIB");
	if(!libPath) {
		cout << "Error, SOFTHSM2_LIB environment variable is not set" << endl;
		return 2;
	}
	
	libHandle = dlopen(libPath, RTLD_NOW);
	if (!libHandle) {
		cout << "Error, failed to load SoftHSM library into memory from path " << libPath << endl;
		return 2;
	}
	dlerror();	// Required before calling dlsym() to clear any existing error
	
	CK_C_GetFunctionList C_GetFunctionList = reinterpret_cast<CK_C_GetFunctionList> (dlsym(libHandle, "C_GetFunctionList"));
	libError = dlerror();		// Recommended to save dlerror() return value
	if (libError) {
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

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 3;
	}

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
				const string& keyLabel)
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
	
	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 4;
	}
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
void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	cout << "Clean up and free the resources\n";
	if (dlclose(libHandle)) {
		cout << "Error, dlclose() on softHSM library reference count\n";
	}
    funclistPtr = NULL_PTR;
    
}