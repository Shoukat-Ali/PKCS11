/**
 * This program was built and executed on Ubuntu 22.04.4 LTS. The following operations are perfromed
 * in this program.
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB 
 *      in order to use PKCS #11 functions
 *      2. Connect to valid slot
 * 		3. Generate Elliptic Curve (EC) key pair (Public and Private keys)
 *      4. Disconnect from a connect slot
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
 * On Linux
 *      g++ -Wall -Werror test_gen_EC_keypair.cpp ../source/gen_EC_keypair.cpp ../source/conn_dis_token.cpp ../source/basic_operation.cpp ../source/common_basic_operation.cpp -o test_ECKeypair -I../include
 * 
 * On Windows
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
*/


#include <iostream>
#include <limits>
#ifdef WIND
	#include "..\header\win_basic_operation.hpp"
	#include "..\header\conn_dis_token.hpp"
	#include "..\header\gen_EC_keypair.hpp"
#else
	#include "../header/basic_operation.hpp"
	#include "../header/conn_dis_token.hpp"
	#include "../header/gen_EC_keypair.hpp"
#endif


using std::cout;
using std::cin;


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
	size_t byteLen = 0;

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
	 * For the prime256v1, we have 
	 * 		openssl ecparam -name prime256v1 -outform DER | xxd
	 * Output:
	 * 		0608 2a86 48ce 3d03 0107
	 * 
	 * For the sect571k1, we have 
	 * 		openssl ecparam -name sect571k1 -outform DER | xxd
	 * Output:
	 * 		0605 2b81 0400 26
	 * 
	 * For the c2tnb431r1, we have 
	 * 		openssl ecparam -name c2tnb431r1 -outform DER | xxd
	 * Output:
	 * 		0608 2a86 48ce 3d03 0014
	 * 
	 * For the brainpoolP512t1, we have 
	 * 		openssl ecparam -name brainpoolP512t1 -outform DER | xxd
	 * Output:
	 * 		0609 2b24 0303 0208 0101 0e
	 * 
	*/
    CK_BYTE_PTR ecparaPtr = NULL_PTR;

    CK_OBJECT_HANDLE hPublic = 0;   // Public key handle
    CK_OBJECT_HANDLE hPrivate = 0;  // Private key handle

	cout << "For Elliptic Curve (EC) curve, we have\n"
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
		byteLen = 7;
		ecparaPtr = new CK_BYTE[byteLen]{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};
		break;
	case 2:
		byteLen = 10;
		ecparaPtr = new CK_BYTE[byteLen]{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
		break;
	case 3:
		byteLen = 7;
		ecparaPtr = new CK_BYTE[byteLen]{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x26};
		break;
	case 4:
		byteLen = 10;
		ecparaPtr = new CK_BYTE[byteLen]{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x14};
		break;
	case 5:
		byteLen = 11;
		ecparaPtr = new CK_BYTE[byteLen]{0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0e};
		break;
	default:
		cout << "Sorry, incorrect choice\n";
		return -1;
	}


	
	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		if (!(retVal = connect_slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			if(!(retVal = gen_EC_keypair(funclistPtr, hSession, ecparaPtr, byteLen,
									&hPublic, &hPrivate))) {
				cout << "\tElliptic Curve (EC) keypair successfully generated\n";
			}

			if (!(retVal = disconnect_slot(funclistPtr, hSession))) {
				cout << "Disconnected from token successfully\n";
			}
		}
	}
	free_resource(libHandle, funclistPtr);
	usrPIN.clear();
	byteLen = 0;
    delete[] ecparaPtr;
	
	return retVal;
}