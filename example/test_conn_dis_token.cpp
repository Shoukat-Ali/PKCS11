/**
 * This program was built and executed on Ubuntu 22.04.4 LTS. The following operations are perfromed
 * in this program.
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB 
 *      in order to use PKCS #11 functions
 *      2. Connect to valid slot
 *      3. Disconnect from a connect slot
 * 
 * To use the Makefile, make sure you're in the same directory of Makefile
 * To build the program using Makefile, run the following command
 * 		make test_ConnDis
 * 
 * If Makefile was used to build, then to execute the program, run the following command
 *      ./test_ConnDis
 * 
 * If Makefile was used to build, then run to following command to remove the binary and object files
 *      make clean_test_ConnDis
 * 
 * To build the program in the example directory, one can run the following command
 *      g++ -Wall -Werror test_conn_dis_token.cpp ../source/conn_dis_token.cpp ../source/basic_operation.cpp -o test_ConnDis -I../include
 * 
 * To see the list of slots, run the following command
 *      softhsm2-util --show-slots
 * 
 * If a slot has not initialized, then to initialize a token slot, one can run the following command
 *      softhsm2-util --init-token --slot <slot_number> --label <text>
 * 
*/


#include <iostream>
#include "../header/basic_operation.hpp"
#include "../header/conn_dis_token.hpp"

using std::cout;


int main()
{
	int retVal = 0;
	#ifdef WIN
		/**
		 * HINSTANCE is the handle to an instance or handle to a module. 
		 * The operating system uses this value to identify the executable or EXE 
		 * when it's loaded in memory. Certain Windows functions need the instance handle, 
		 * for example to load icons or bitmaps.
		 * 
		 * HINSTANCE is a handle to identify your application for others WINAPI calls. 
		 * But actually, it is not even to identify your application from other instances, 
		 * but to identify it from others applications executable files inside 
		 * your applications e.g., DLLs.
		 */
		HINSTANCE libHandle = 0;
	#else
		void *libHandle = nullptr;
	#endif

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
		if (!(retVal = connect_slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			if (!(retVal = disconnect_slot(funclistPtr, hSession))) {
				cout << "Disconnected from token successfully\n";
			}
		}
	}
	free_resource(libHandle, funclistPtr);
	// Removes all characters from the usrPIN string and all pointers, references, and iterators are invalidated. 
    usrPIN.clear();
	
	return retVal;
}