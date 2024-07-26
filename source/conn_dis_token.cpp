#include <iostream>
#include <limits>
#ifdef WIND
	#include "..\header\common_basic_operation.hpp"
	#include "..\header\conn_dis_token.hpp"
#else
	#include "../header/common_basic_operation.hpp"
	#include "../header/conn_dis_token.hpp"
#endif
 

using std::cout; 
using std::cin;
using std::endl;




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
	int retVal = 0;
	/**
	 * CK_SLOT_ID is a Cryptoki-assigned value that identifies a slot.
	 * It is defined as follows: 
	 * 			typedef CK_ULONG CK_SLOT_ID;
	 * 
	 * A priori, any value of CK_SLOT_ID can be a valid slot identifier — in particular, 
	 * a system may have a slot identified by the value 0.
	*/
	CK_SLOT_ID slotID = 0;

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 3;
	}

	/**
	 * CK_RV C_Initialize(CK_VOID_PTR pInitArgs); 
	 * 
	 * C_Initialize() initializes the Cryptoki library. pInitArgs either has the value NULL_PTR
	 * or points to a CK_C_INITIALIZE_ARGS structure containing information on how the
	 * library should deal with multi-threaded access. If an application will not be accessing
	 * Cryptoki through multiple threads simultaneously, it can generally supply the value NULL_PTR to C_Initialize().
	 * Cryptoki defines a C-style NULL pointer, which is distinct from any valid pointeri.e., NULL_PTR
	 * */
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
		retVal = check_operation(funclistPtr->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
															NULL_PTR, NULL_PTR, &hSession), 
															"C_OpenSession()");
		if (!retVal) {
			// Session opened successfully
			cout << "\tPlease enter the User PIN: ";
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

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 4;
	}

	/**
	 * CK_RV C_Logout(CK_SESSION_HANDLE hSession);
	 * 
	 * C_Logout logs a user out from a token. hSession is the session’s handle.
	 * If there are any active cryptographic or object-finding operations in an application’s
	 * session, and then C_Logout is successfully executed by that application, it may or may
	 * not be the case that those operations are still active. Therefore, before logging out, 
	 * any active operations should be finished.
	*/
	retVal = check_operation(funclistPtr->C_Logout(hSession), "C_Logout()");
	if (!retVal) {
		// C_Logout() was successful
		/**
		 * CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
		 * 
		 * C_CloseSession closes a session between an application and a token. 
		 * hSession is the session’s handle.
		 * 
		 * When a session is closed, all session objects created by the session are destroyed
		 * automatically, even if the application has other sessions “using” the objects
		*/
		retVal = check_operation(funclistPtr->C_CloseSession(hSession), "C_CloseSesion()");
		
		/**
		 * CK_RV C_Finalize(CK_VOID_PTR pReserved);
		 * 
		 * C_Finalize is called to indicate that an application is finished with the Cryptoki library.
		 * It should be the last Cryptoki call made by an application. The pReserved parameter is
		 * reserved for future versions; for this version, it should be set to NULL_PTR 
		 * (if C_Finalize is called with a non-NULL_PTR value for pReserved, it should return the
		 * value CKR_ARGUMENTS_BAD.
		 * If several applications are using Cryptoki, each one should call C_Finalize. Each
		 * application’s call to C_Finalize should be preceded by a single call to C_Initialize;
		*/
		retVal = check_operation(funclistPtr->C_Finalize(NULL_PTR), "C_Finalize()");
	}
	
	return retVal;
}

