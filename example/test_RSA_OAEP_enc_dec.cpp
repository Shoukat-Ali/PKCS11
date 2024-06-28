/**
 * This program was built and executed on Ubuntu 22.04.4 LTS. The following operations are perfromed
 * in this program.
 * 
 * 		1. Load the HSM library by setting an environment variable SOFTHSM2_LIB 
 *      in order to use PKCS #11 functions
 *      2. Connect to valid slot
 * 		3. Generate RSA key pair (Public and Private keys)
 *      4. Encrypt plaintext using RAS-OAEP encryption scheme
 *      5. Decrypt ciphertext using RAS-OAEP encryption scheme
 *      4. Disconnect from a connect slot
 * 
 * To use the Makefile, make sure you're in the same directory of Makefile
 * To build the program using Makefile, run the following command
 * 		make test_RSAEncDec
 * 
 * If Makefile was used to build, then to execute the program, run the following command
 *      ./test_RSAEncDec
 * 
 * If Makefile was used to build, then run to following command to remove the binary and object files
 *      make clean_test_RSAEncDec
 * 
 * To build the program in the example directory, one can run the following command
 *      g++ -Wall -Werror test_RSA_OAEP_enc_dec.cpp ../source/RSA_OAEP_enc_dec.cpp ../source/gen_RSA_keypair.cpp ../source/conn_dis_token.cpp ../source/basic_operation.cpp -o test_RSAEncDec -I../include
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
#include "../header/basic_operation.hpp"
#include "../header/conn_dis_token.hpp"
#include "../header/gen_RSA_keypair.hpp"
#include "../header/RSA_OAEP_enc_dec.hpp"


using std::cout;
using std::cin;


int main()
{
	int retVal = 0;
	int choice = -1;
	void *libHandle = nullptr;
	CK_FUNCTION_LIST_PTR funclistPtr = NULL_PTR;
	CK_SESSION_HANDLE hSession = 0; 
	std::string usrPIN;
	size_t modBitLen = 0;

    std::string plaintext("This is to test our RSA-OAEO encryption scheme implementation.");
    std::string ciphertext;
    std::string dectext;
    
    /**
     * 
     */
    CK_BYTE pubExpn[] = {0x01, 0x00, 0x01};  // value = 65537;

    CK_OBJECT_HANDLE hPublic = 0;   // Public key handle
    CK_OBJECT_HANDLE hPrivate = 0;  // Private key handle

	cout << "For RSA, we have\n"
		 << "\t1. 2048-bit\n"
		 << "\t2. 3072-bit\n"
		 << "\t3. 4096-bit\n";

	cout << "please enter an integer (1 to 3) :: "; 
	cin >> choice;
	if (!cin.good()) {
		cout << "Error not an integer\n";
		cin.clear();  //clearing all error state flags.
		cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n'); // skip/ignore bad input  
	}

	switch (choice) {
	case 1:
		modBitLen = 2048;
		break;
	case 2:
		modBitLen = 3072;
		pubExpn[sizeof(pubExpn) - 1] += 2;  // value = 65539
		break;
	case 3:
		modBitLen = 4096;
		pubExpn[sizeof(pubExpn) - 1] += 64;  // value = 65601
		break;
	default:
		cout << "Sorry, incorrect choice\n";
		return -1;
	}


	
	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		if (!(retVal = connect_slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			if(!(retVal = gen_RSA_keypair(funclistPtr, hSession, modBitLen, 
                                        pubExpn, sizeof(pubExpn), &hPublic, &hPrivate))) {
				cout << "\tRSA " << modBitLen << "-bit modulus key pair successfully generated\n";

                // Encrypt plaintext
                retVal = encrypt_plaintext(funclistPtr, hSession, hPublic,
                                            plaintext, ciphertext);
                if (!retVal) {
                    cout << "\tData successfully encrypted\n";
                    // Decrypt ciphertext
                    retVal = decrypt_ciphertext(funclistPtr, hSession, hPrivate,
                                                ciphertext, dectext);
                                                
                    // Comparing plaintext to decrypted text
                    if (!plaintext.compare(dectext)) {
                        cout << "\tAfter decryption, plaintext matches decrypted text!!!\n";
                    }
                }

			}

			if (!(retVal = disconnect_slot(funclistPtr, hSession))) {
				cout << "Disconnected from token successfully\n";
			}
		}
	}
	free_resource(libHandle, funclistPtr);
	usrPIN.clear();
	
	return retVal;
}