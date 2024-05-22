/**
 * This program was built and executed on Ubuntu 22.04.4 LTS
 * 
 * To use the Makefile, make sure you're in the same directory of Makefile
 * To build the program using Makefile, run the following command
 * 		make test_ECKeypair
 * 
 * If Makefile was used to build, then to execute the program, run the following command
 *      ./test_ECKeypair
 * 
 * If Makefile was used to build, then run to following command to remove the binary and object files
 *      make clean_test_ECKeypair
 * 
 * To build the program in the example directory, one can run the following command
 *      g++ -Wall -Werror test_gen_EC_keypair.cpp ../source/gen_EC_keypair.cpp -o test_ECKeypair -I../include
 * 
 * To see the list of slots, run the following command
 *      softhsm2-util --show-slots
 * 
 * If a slot has not initialized, then to initialize a token slot, one can run the following command
 *      softhsm2-util --init-token --slot <slot_number> --label <text>
 * 
*/


#include <iostream>
#include "../header/gen_EC_keypair.hpp"

using std::cout;


int main()
{
	int retVal = 0;
	void *libHandle = nullptr;
	CK_FUNCTION_LIST_PTR funclistPtr = NULL_PTR;
	CK_SESSION_HANDLE hSession = 0; 
	std::string usrPIN;

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

    CK_OBJECT_HANDLE hPublic = 0;   // Public key handle
    CK_OBJECT_HANDLE hPrivate = 0;  // Private key handle
	
	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		if (!(retVal = connect_slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			if (!(retVal = disconnect_slot(funclistPtr, hSession))) {
				cout << "Disconnected from token successfully\n";
			}
		}
	}
	free_resource(libHandle, funclistPtr, usrPIN);
	
	return retVal;
}