#include <iostream>
#include <stdlib.h>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/conn_dis_token.hpp"
 

using std::cout, std::cin, std::endl;



/**
 * The function checks if a requested Cryptoki (PKCS #11) operation was a success or not.
 * rv represents the CK_RV value returned by Cryptoki function
 * message represent the Cryptoki operation 
 * 
 * If the CK_RV value is CKR_OK, then success and 0 is returned. 
 * Otherwise, non-zero integer is returned on failure.
 *  
*/
int check_Operation(const CK_RV rv, const char* message)
{
	if (rv != CKR_OK) {
		cout << "Error, " << message << " failed with : " << rv << endl
			 << "RV : " << rv << endl;
		return 1;
	}
	return 0;
}



/**
 * The function attempts to load SoftHSM library in order to use PKCS# 11 functions/API.
 * The function asks the user to input the full path to SoftHSM library
 * 
 * libHandle is a void pointer for SoftHSM library handle
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST
 *  
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	const char *libPath = nullptr;
	/**
	 * Instead of reading the SoftHSM full path from user every time,
	 * it's better to set an environment variable 
	 * Defining an environment variable (SOFTHSM2_LIB) for the SoftHSM library path by adding
	 *      export SOFTHSM2_LIB=/full/path/to/libsofthsm2.so
     * 
     *  1. Open .profile file in your home directory
     *  2. Simple run the command in the working terminal
	 * */
	
	libPath = getenv("SOFTHSM2_LIB");
	if(libPath == nullptr) {
		cout << "Error, SOFTHSM2_LIB environment variable is not set" << endl;
		return 2;
	}
	
	
	/**
	 * void *dlopen(const char *filename, int flags);
	 * loads the dynamic shared object (shared library) file named by the null-terminated string filename
	 * returns an opaque "handle" for the loaded object
	 * 
	 * RTLD_NOW :: Relocations are performed when the object is loaded.
	 * 
	 */

	libHandle = dlopen(libPath, RTLD_NOW);
	if (!libHandle) {
		cout << "Error, failed to load SoftHSM library into memory from path " << libPath << endl;
		return 3;
	}
	
    /**
	 * dlsym, dlvsym - obtain address of a symbol in a shared object or executable
	 * 
	 * void *dlsym(void *restrict handle, const char *restrict symbol);
	 * 
	 * The function dlsym() takes a "handle" of a dynamic loaded shared object 
	 * returned by dlopen(3) along with a null-terminated symbol name, 
	 * and returns the address where that symbol is loaded into memory. 
	 * If the symbol is not found, in the specified object or any of the shared objects 
	 * that were automatically loaded by dlopen(3) when that object was loaded, dlsym() returns NULL
	 * 
	 * On success, these functions return the address associated with symbol. 
	 * On failure, they return NULL; the cause of the error can be diagnosed using dlerror(3).
	*/
	CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(libHandle, "C_GetFunctionList");
	if (!C_GetFunctionList) {
		cout << "Error, dlsym() failed to find loaded SoftHSM library" << endl;
		return 3;
	}
	
    /**
	 * CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);
	 * 
	 * C_GetFunctionList is the only Cryptoki function which an application may call before
	 * calling C_Initialize. It is provided to make it easier and faster for applications to use
	 * shared Cryptoki libraries and to use more than one Cryptoki library simultaneously.
	 * 
	 * C_GetFunctionList obtains a pointer to the Cryptoki library’s list of function pointers.
	*/
	return check_Operation(C_GetFunctionList(&funclistPtr), "C_GetFunctionList");
	
}




/**
 * This function attempts to connect to a token. 
 * First, it initializes the Cryptoki/SoftHSM library; 
 * Second, attempts to open a new session by taking solt ID from the user;
 * Finally, attempts to perform login based on user inputs.
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int connect_Slot(CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession, std::string& usrPIN)
{
	/**
	 * CK_SLOT_ID is a Cryptoki-assigned value that identifies a slot.
	 * It is defined as follows: 
	 * 			typedef CK_ULONG CK_SLOT_ID;
	 * 
	 * A priori, any value of CK_SLOT_ID can be a valid slot identifier — in particular, 
	 * a system may have a slot identified by the value 0.
	*/
	CK_SLOT_ID slotID = 0;

	/**
	 * CK_RV C_Initialize(CK_VOID_PTR pInitArgs); 
	 * 
	 * C_Initialize() initializes the Cryptoki library. pInitArgs either has the value NULL_PTR
	 * or points to a CK_C_INITIALIZE_ARGS structure containing information on how the
	 * library should deal with multi-threaded access. If an application will not be accessing
	 * Cryptoki through multiple threads simultaneously, it can generally supply the value NULL_PTR to C_Initialize().
	 * Cryptoki defines a C-style NULL pointer, which is distinct from any valid pointeri.e., NULL_PTR
	 * */
	if (check_Operation(funclistPtr->C_Initialize(NULL_PTR), "C_Initialize")) {
		// Operation failed
		return 4;
	}

	
	cout << "Please enter the slot ID (integer): ";
	cin >> slotID;
	if (!cin.good()) {
		cout << "Error, slot ID is not integer\n";
		cin.clear();  //clearing all error state flags.
		cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n'); // skip/ignore bad input  
	}

	
	/**
	 * CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
	 * 						CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
	 * 
	 * C_OpenSession() opens a session between an application and a token in a particular slot. 
	 * slotID is the slot’s ID; 
	 * flags indicates the type of session; 
	 * pApplication is an application-defined pointer to be passed to the notification callback; 
	 * Notify is the address of the notification callback function; 
	 * phSession points to the location that receives the handle for the new session.
	 * 
	 * More parameter explanation:
	 * 
	 * The flags is logical OR of zero or more bit flags defined in the CK_SESSION_INFO data type. 
	 * For legacy reasons, the CKF_SERIAL_SESSION bit must always be set;
	 * 
	 * The Notify callback function is used by Cryptoki to notify the application of certain
	 * events. If the application does not wish to support callbacks, it should pass a value of
	 * NULL_PTR as the Notify parameter.
	*/
	if (check_Operation(funclistPtr->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
											NULL_PTR, NULL_PTR, &hSession), 
											"C_OpenSession")) {
											// Operation failed
											return 4;
	}
	
	
	cout << "Please enter the User PIN: ";
	cin >> usrPIN;
	
	/**
	 * CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
	 * 
	 * C_Login logs a user into a token. 
	 * hSession is a session handle; 
	 * userType is the user type; (CKU_SO or CKU_USER)
	 * pPin points to the user’s PIN; 
	 * ulPinLen is the length of the PIN. 
	 * This standard allows PIN values to contain any valid UTF8 character, but the token may impose subset restrictions.
	 * 
	 * Call C_Login to log the user into the token. Since all sessions an application has
	 * with a token have a shared login state, C_Login only needs to be called for one of the sessions.
	 * 
	 * Parameter details
	 * To log into a token with a protected authentication path, the pPin parameter to C_Login should be NULL_PTR. 
	 * When C_Login returns, whatever authentication method supported by the token will have been performed; 
	 * a return value of CKR_OK means that the user was successfully authenticated
	*/
	if (check_Operation(funclistPtr->C_Login(hSession, CKU_USER,
											reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(usrPIN.c_str())),
											usrPIN.length()), "C_Login")) {
												// Operation failed
												return 4;
											}

	return 0;
}