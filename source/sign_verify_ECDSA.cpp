#include <iostream>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/sign_verify_ECDSA.hpp" 

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
 * This function checks whether a given pointer is null of not.
 * 
 * ptr is a constant pointer to void type
 * 
 * If given pointer is null, then return true. Otherwise, faluse is returned.
 * 
*/
inline bool is_nullptr(void * const ptr)
{
	if (ptr) {
		return false;
	}
	cout << "Error, pointer is NULL\n";
	return true;
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
 * The function generates Elliptic Curve Digital Signature Algorithm (ECDSA) keypair 
 * based on the given parameters.
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
 *  
*/
int gen_ECDSA_keypair(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession,
						CK_BYTE_PTR const ecPara, const size_t ecParaSZ,
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
        {CKA_TOKEN,             &yes,               sizeof(yes)},
        {CKA_PRIVATE,           &no,                sizeof(no)},
        {CKA_VERIFY,            &yes,               sizeof(yes)},
        {CKA_ENCRYPT,           &yes,               sizeof(yes)},
        {CKA_EC_PARAMS,			ecPara,		    	ecParaSZ},
        {CKA_LABEL,             &pubLabel,          sizeof(pubLabel)}
    };
    
    CK_ATTRIBUTE attribPri[] = {
        {CKA_TOKEN,             &yes,               sizeof(yes)},
        {CKA_PRIVATE,           &yes,               sizeof(yes)},
        {CKA_SIGN,              &yes,               sizeof(yes)},
        {CKA_DECRYPT,           &yes,               sizeof(yes)},
        {CKA_SENSITIVE,         &yes,               sizeof(yes)},
        {CKA_LABEL,             &prvLabel,          sizeof(prvLabel)}
    };
    
	retVal = check_operation(funclistPtr->C_GenerateKeyPair(hSession, &mech, 
											attribPub, sizeof(attribPub) / sizeof(*attribPub),
											attribPri, sizeof(attribPri) / sizeof(*attribPri),
											hPubPtr, hPrvPtr), "C_GenerateKeyPair()");

    if (!retVal) {
		cout << "Elliptic Curve Digital Signature Algorithm (ECDSA) keypair successfully generated\n";
	}
	return retVal;    
}