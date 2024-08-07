/**
 * This program was built and executed on Ubuntu 22.04.4 LTS. The following operations are perfromed
 * in this program.
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB 
 *      in order to use PKCS #11 functions
 *      2. Show list of all slots and tokens (initialized or not)
 *      3. Display some slot and token information
 * 
 * 
 * A slot is a logical reader that potentially contains a token. 
 * A token is typically “present in the slot” when a cryptographic device is present in the reader.
 * 
 * Initializing slot
 *      softhsm2-util --init-token --free --so-pin <so_pin> --pin <user_pin> --label <token_label>
 * 
 * Directly removing tokens from the tokens directory
 *      /opt/softhsm2/var/lib/softhsm
 * 
 * To use the Makefile, make sure you're in the same directory of Makefile 
 * To build the program using Makefile, run the following command
 * 		make test_STList
 * 
 * If Makefile was used to build, then to execute the program, run the following command
 *      ./test_STList
 * 
 * If Makefile was used to build, then run to following command to remove the binary and object files
 *      make clean_test_STList
 * 
 * To build the program in the example directory, one can run the following command
 * On Linux
 *      g++ -Wall -Werror test_slots_token_list.cpp ../source/slots_token_list.cpp ../source/basic_operation.cpp ../source/common_basic_operation.cpp -o test_STList -I../include
 * 
 * On Windows
 * 		g++ -Wall -Werror test_slots_token_list.cpp ..\source\slots_token_list.cpp ..\source\win_basic_operation.cpp ..\source\common_basic_operation.cpp -o test_STList.exe -I../include -DWIND
 * 
 * To see the list of slots, run the following command
 *      softhsm2-util --show-slots
 * 
 * 
*/


#include <iostream>
#ifdef WIND
	#include "..\header\win_basic_operation.hpp"
	#include "..\header\slots_token_list.hpp"
#else
	#include "../header/basic_operation.hpp"
	#include "../header/slots_token_list.hpp"
#endif


using std::cout;


int main()
{
	int retVal = 0;
	#ifdef WIND
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
	
	
	CK_FUNCTION_LIST_PTR funclistPtr = NULL_PTR;
	
	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		retVal = display_all_slot_token(funclistPtr);
	}

	free_resource(libHandle, funclistPtr);
	
	return retVal;
}