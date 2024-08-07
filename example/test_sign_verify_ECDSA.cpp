/**
 * This program was built and executed on Ubuntu 22.04.4 LTS. The following operations are perfromed
 * in this program.
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB 
 *      in order to use PKCS #11 functions
 *      2. Connect to valid slot
 * 		3. Generate Elliptic Curve Digital Signature Algorithm (ECDSA) key pair (Public and Private keys)
 * 		4. Sign data using private key of ECDSA
 * 		5. Verify given signature on data using public key of ECDSA
 *      6. Disconnect from a connect slot
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
 * On Linux
 *      g++ -Wall -Werror test_sign_verify_ECDSA.cpp ../source/sign_verify_ECDSA.cpp ../source/conn_dis_token.cpp ../source/basic_operation.cpp ../source/common_basic_operation.cpp -o test_ECDSA -I../include
 * 
 * On Windows
 * 
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
 * Using p11tool to see the generated public/private key on token, run the following command.
 * Note that session keys exist only during the session
 * 		p11tool --provider </full/path/to/libsofthsm2.so> --login --list-all <TOKEN-URL>
 * 		 
 * To delete public/private key, run the following command
 * 		p11tool --provider </full/path/to/libsofthsm2.so> --delete <TOKEN-URL>
 * 
 * One can directly delete the persistant keys (token object) in the tokens sub-directory 
 * where softhsm2 library is installed on one's system
 * 
*/


#include <iostream>
#include <limits>
#ifdef WIND
	#include "..\header\win_basic_operation.hpp"
	#include "..\header\conn_dis_token.hpp"
	#include "..\header\sign_verify_ECDSA.hpp"
#else
	#include "../header/basic_operation.hpp"
	#include "../header/conn_dis_token.hpp"
	#include "../header/sign_verify_ECDSA.hpp"
#endif


using std::cout;
using std::endl;
using std::cin;


/**
 * The function prints given byte array data in hexadecimal format
*/
inline void print_hex(CK_BYTE* data, size_t byteLen)
{
	for(size_t i = 0; i < byteLen; ++i) 
        cout << std::hex << std::uppercase << (data[i] & 0xFF);
    cout << endl;
}



int main()
{
	int retVal = 0;
	int choice = -1;
	#ifdef WIND
		HINSTANCE libHandle = 0;
	#else
		void *libHandle = nullptr;
	#endif

	CK_FUNCTION_LIST_PTR funclistPtr = NULL_PTR;
	CK_SESSION_HANDLE hSession = 0; 
	std::string usrPIN;

    CK_OBJECT_HANDLE hPublic = 0;   // Public key handle
    CK_OBJECT_HANDLE hPrivate = 0;  // Private key handle
    CK_BYTE_PTR ecparaPtr = NULL_PTR;
    CK_BYTE_PTR sigPtr = NULL_PTR;
    CK_ULONG paraLen = 0;       // ECDSA parameter byte-length
    CK_ULONG sigLen = 0;        // ECDSA signature byte-length
    CK_BYTE data[] = "This data is for testing only";
    CK_ULONG dataLen = sizeof(data) - 1;    // Excluding the null character

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


	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		if (!(retVal = connect_slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			retVal = gen_ECDSA_keypair(funclistPtr, hSession, ecparaPtr, paraLen,
									&hPublic, &hPrivate);
            if (!retVal) {
                // Private and Public keys were successfully generated
                cout << "\tData to be signed (hex):: ";
                print_hex(data, dataLen);
                retVal = sign_data_no_hashing(funclistPtr, hSession, hPrivate, data, 
                                                dataLen, sigPtr, sigLen);
                if (!retVal) {
                    // Signature was successfully generated
                    cout << "\tProduced signature (hex) :: ";
                    print_hex(sigPtr, sigLen);
                    // For testing, changing one byte of signature only
                    // sigPtr[0] ^= 0xFF;
                    retVal = verify_data_no_hashing(funclistPtr, hSession, hPublic, data,
                                                    dataLen, sigPtr, sigLen);
                    if (!retVal) {
                        cout << "\tSignature correctly verified!!!\n";
                    }
                }
            }
			if (!(retVal = disconnect_slot(funclistPtr, hSession))) {
				cout << "Disconnected from token successfully\n";
			}
		}
	}
	free_resource(libHandle, funclistPtr);
    dataLen = 0;
    sigLen = 0;
	usrPIN.clear();
    delete[] sigPtr;
    paraLen = 0;
    delete[] ecparaPtr;
	
	return retVal;
}