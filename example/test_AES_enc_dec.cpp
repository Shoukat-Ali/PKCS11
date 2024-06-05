/**
 * This program was built and executed on Ubuntu 22.04.4 LTS
 * 
 * To use the Makefile, make sure you're in the same directory of Makefile
 * To build the program using Makefile, run the following command
 * 		make test_AESEncDec
 * 
 * If Makefile was used to build, then to execute the program, run the following command
 *      ./test_AESEncDec
 * 
 * If Makefile was used to build, then run to following command to remove the binary and object files
 *      make clean_test_AESEncDec
 * 
 * To build the program in the example directory, one can run the following command
 *      g++ -Wall -Werror test_AES_enc_dec.cpp ../source/gen_AES_keys.cpp ../source/AES_enc_dec.cpp -o test_AESEncDec -I../include
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
#include <string>
#include "../header/gen_AES_keys.hpp"
#include "../header/AES_enc_dec.hpp"

// AES uses 128-bit (16-byte) block
#define AES_BLOCK_BYTE_LEN 16


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
    CK_ULONG keyLen = 0;
    
    CK_CHAR Label[] = "AES xxx-bit key";
    std::string plaintext("This is to test our AES encryption scheme implementation and we are adding some texts on line #2");
    std::string ciphertext;
    std::string dectext;

    /**
     * typedef CK_ULONG CK_OBJECT_HANDLE;
     * 
     * CK_OBJECT_HANDLE is a token-specific identifier for an object.
     * When an object is created or found on a token by an application, Cryptoki assigns it an
     * object handle for that application’s sessions to use to access it. A particular object on a
     * token does not necessarily have a handle which is fixed for the lifetime of the object;
    */
   CK_OBJECT_HANDLE keyHandle;

    cout << "For AES keys, we have\n"
		 << "\t1. 128-bit (16-byte)\n"
		 << "\t2. 192-bit (24-byte)\n"
		 << "\t3. 256-bit (32-byte)\n";

	cout << "please enter 1 to 3 :: "; 
	cin >> choice;
	if (!cin.good()) {
		cout << "Error not an integer\n";
		cin.clear();  //clearing all error state flags.
		cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n'); // skip/ignore bad input  
	}

	switch (choice) {
	case 1:
		keyLen = 16;        // byte-length
        Label[4] = '1';
        Label[5] = '2';
        Label[6] = '8';
		break;
	case 2:
		keyLen = 24;        // byte-length
        Label[4] = '1';
        Label[5] = '9';
        Label[6] = '2';
		break;
	case 3:
		keyLen = 32;        // byte-length
        Label[4] = '2';
        Label[5] = '5';
        Label[6] = '6';
		break;
	default:
		cout << "Sorry, incorrect choice\n";
		return -1;
	}


	if (!(retVal = load_library_HSM(libHandle, funclistPtr))) {
		cout << "HSM PKCS #11 library loaded successfully\n";
		if (!(retVal = connect_slot(funclistPtr, hSession, usrPIN))) {
			cout << "Connected to token successfully\n";
			retVal = gen_AES_key(funclistPtr, hSession, &keyHandle, keyLen, Label, sizeof(Label));
            if (!retVal) {
                // AES secret key successfully generated
                cout << "\t"<< Label << " successfully generated\n";
                // Encrypt plaintext
                retVal = encrypt_plaintext(funclistPtr, hSession, keyHandle,
                                            plaintext, ciphertext);
                if (!retVal) {
                    cout << "\tData successfully encrypted\n";
                    // Decrypt ciphertext
                    retVal = decrypt_ciphertext(funclistPtr, hSession, keyHandle,
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
	free_resource(libHandle, funclistPtr, usrPIN);
    keyLen = 0;
    
	return retVal;
}