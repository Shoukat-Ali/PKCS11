/**
 * This program was built and executed on Ubuntu 22.04.4 LTS
 * 
 * To use the Makefile, make sure you're in the same directory of Makefile
 * To build the program using Makefile, run the following command
 * 		make test_ECDSA
 * 
 * If Makefile was used to build, then to execute the program, run the following command
 *      ./test_ECDSA
 * 
 * If Makefile was used to build, then run to following command to remove the binary and object files
 *      make clean_test_ECDSA
 * 
 * To build the program in the example directory, one can run the following command
 *      g++ -Wall -Werror test_sign_verify_ECDSA.cpp ../source/sign_verify_ECDSA.cpp -o test_ECDSA -I../include
 * 
 * To see the list of slots, run the following command
 *      softhsm2-util --show-slots
 * 
 * If a slot has not initialized, then to initialize a token slot, one can run the following commands
 * 		softhsm2-util --init-token --free --so-pin <so_pin> --pin <user_pin> --label <token_label>
 * OR
 *      softhsm2-util --init-token --slot <slot_number> --label <text>
 * 
 * Using p11tool to see list of tokens, run the following command
 * 		p11tool --provider </full/path/to/libsofthsm2.so>  --list-tokens
 * 
 * Using p11tool to see the generated public/private key, run the following command
 * 		p11tool --provider </full/path/to/libsofthsm2.so> --login --list-all <TOKEN-URL>
 * 		 
 * To delete public/private key, run the following command
 * 		p11tool --provider </full/path/to/libsofthsm2.so> --delete <TOKEN-URL>
 * 
 * One can directly delete the keys in the tokens sub-directory where softhsm2 library is installed on one's system
 *
*/


#include <iostream>
#include <limits>
#include "../header/sign_verify_ECDSA.hpp"


using std::cout;
using std::endl;
using std::cin;






int main()
{
	int retVal = 0;
	int choice = -1;
	void *libHandle = nullptr;
	CK_FUNCTION_LIST_PTR funclistPtr = NULL_PTR;
	CK_SESSION_HANDLE hSession = 0; 
	std::string usrPIN;

    CK_OBJECT_HANDLE hPublic = 0;   // Public key handle
    CK_OBJECT_HANDLE hPrivate = 0;  // Private key handle
    CK_BYTE_PTR ecparaPtr = NULL_PTR;
    CK_BYTE_PTR dataPtr = NULL_PTR;
    CK_BYTE_PTR sigPtr = NULL_PTR;
    CK_ULONG paraLen = 0;       // ECDSA parameter byte-length
    CK_ULONG sigLen = 0;        // ECDSA signature byte-length
    

	cout << "For ECDSA, we have\n"
		 << "\t1. secp521r1\n"
		 << "\t2. prime256v1\n"
		 << "\t3. sect571k1\n"
		 << "\t4. c2tnb431r1\n"
		 << "\t5. brainpoolP512t1\n";

	cout << "please enter 1 to 5 :: "; 
	cin >> choice;
	if (!cin.good()) {
		cout << "Error not an integer\n";
		cin.clear();  //clearing all error state flags.
		cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n'); // skip/ignore bad input  
	}

	switch (choice) {
	case 1:
		paraLen = 7;
		ecparaPtr = new CK_BYTE[paraLen]{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};
        sigLen = 132;
        sigPtr = new CK_BYTE[sigLen];
		break;
	case 2:
		paraLen = 10;
		ecparaPtr = new CK_BYTE[paraLen]{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
        sigLen = 64;
        sigPtr = new CK_BYTE[sigLen];
		break;
	case 3:
		paraLen = 7;
		ecparaPtr = new CK_BYTE[paraLen]{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x26};
        sigLen = 144;
        sigPtr = new CK_BYTE[sigLen];
		break;
	case 4:
		paraLen = 10;
		ecparaPtr = new CK_BYTE[paraLen]{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x14};
        sigLen = 106;
        sigPtr = new CK_BYTE[sigLen];
		break;
	case 5:
		paraLen = 11;
		ecparaPtr = new CK_BYTE[paraLen]{0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0e};
        sigLen = 128;
        sigPtr = new CK_BYTE[sigLen];
		break;
	default:
		cout << "Sorry, incorrect choice\n";
		return -1;
	}


	CK_ULONG dataLen = sizeof("This data is for testing only") - 1;
    dataPtr = new CK_BYTE[dataLen];

	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		if (!(retVal = connect_slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			retVal = gen_ECDSA_keypair(funclistPtr, hSession, ecparaPtr, paraLen,
									&hPublic, &hPrivate);
            if (!retVal) {
                // Private and Public keys were successfully generated
                retVal = sign_data_no_hashing(funclistPtr, hSession, hPrivate, dataPtr, 
                                                dataLen, sigPtr, sigLen);
                if (!retVal) {
                    // Signature was successfully generated
                    retVal = verify_data_no_hashing(funclistPtr, hSession, hPublic, dataPtr,
                                                    dataLen, sigPtr, sigLen);
                }
            }
			if (!(retVal = disconnect_slot(funclistPtr, hSession))) {
				cout << "Disconnected from token successfully\n";
			}
		}
	}
	free_resource(libHandle, funclistPtr, usrPIN);
    dataLen = 0;
    sigLen = 0;
    delete[] dataPtr;
    delete[] sigPtr;
    
    paraLen = 0;
    delete[] ecparaPtr;
	
	return retVal;
}