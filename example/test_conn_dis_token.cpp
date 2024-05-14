/**
 * This program was built and executed on Ubuntu 22.04.4 LTS
 * 
 * To build the program using Makefile, run the following command
 * 		make
 * 
 * To build the program directly, one can run the following command
 *      g++ -Wall -Werror test_conn_dis_token.cpp ../source/conn_dis_token.cpp -o prog -I../include
 * 
 * To see the list of slots, run the following command
 *      softhsm2-util --show-slots
 * 
 * If a slot has not initialized, then to initialize a token slot, one can run the following command
 *      softhsm2-util --init-token --slot <slot_number> --label <text>
 * 
*/


#include <iostream>
#include "../header/conn_dis_token.hpp"

using std::cout;


int main()
{
	int retVal = 0;
	void *libHandle = nullptr;

	/**
	 * CK_* represents Data type or general constant
	 * For quick reference, see Table 2, Prefixes
	 * For more information, see pkcs-11v2 pdf file
	 * 
	 * CK_FUNCTION_LIST is a structure which contains a Cryptoki version and a function
	 * pointer to each function in the Cryptoki API.
	 * CK_FUNCTION_LIST_PTR is a pointer to a CK_FUNCTION_LIST
	 * CK_FUNCTION_LIST_PTR_PTR is a pointer to a CK_FUNCTION_LIST_PTR
	 * */
	CK_FUNCTION_LIST_PTR funclistPtr = NULL_PTR;

	/**
	 * typedef CK_ULONG CK_SESSION_HANDLE;
	 * CK_SESSION_HANDLE is a Cryptoki-assigned value that identifies a session.
	 * Valid session handles in Cryptoki always have nonzero values
	 * */
	CK_SESSION_HANDLE hSession = 0; 
	
	std::string usrPIN;
	
	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		if (!(retVal = connect_Slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			if (!(retVal = disconnect_Slot(funclistPtr, hSession))) {
				cout << "Disconnected from token successfully\n";
			}
		}
	}
	free_Resource(libHandle, funclistPtr, usrPIN);
	
	return retVal;
}