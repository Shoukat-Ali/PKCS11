/**
 * This program was built and executed on Ubuntu 22.04.4 LTS
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
 * To build the program using Makefile, run the following command
 * 		make test_SlotList
 * 
 * If Makefile was used to build, then run to following command to remove the binary and object files
 *      make clean
 * 
 * To build the program in the example directory, one can run the following command
 *      g++ -Wall -Werror test_slots_list.cpp ../source/slots_list.cpp -o test_SlotList -I../include
 * 
 * To see the list of slots, run the following command
 *      softhsm2-util --show-slots
 * 
 * 
*/


#include <iostream>
#include "../header/slots_list.hpp"

using std::cout;


int main()
{
	int retVal = 0;
	void *libHandle = nullptr;

	CK_FUNCTION_LIST_PTR funclistPtr = NULL_PTR;
	CK_SESSION_HANDLE hSession = 0; 
	
	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		
	}
	free_resource(libHandle, funclistPtr);
	
	return retVal;
}