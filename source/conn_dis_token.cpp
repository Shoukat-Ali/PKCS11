#include <iostream>
#include <stdlib.h>
#include <limits>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/conn_dis_token.hpp"
 

using std::cout, std::cin, std::endl;



/**
 * The function checks if a requested Cryptoki (PKCS #11) operation was a success or not.
 * rv represents the CK_RV value returned by Cryptoki function
 * message represent the Cryptoki operation 
 * 
 * If the CK_RV value is CKR_OK, then success and 0 is returned. 
 * Otherwise, non-zero integer is returned on failure.
 *  
*/
int check_Operation(const CK_RV rv, const char* message)
{
	if (rv != CKR_OK) {
		cout << "Error, " << message << " failed with : " << rv << endl
			 << "RV : " << rv << endl;
		return 1;
	}
	return 0;
}



/**
 * The function attempts to load SoftHSM library in order to use PKCS# 11 functions/API.
 * The function asks the user to input the full path to SoftHSM library
 * 
 * libHandle is a void pointer for SoftHSM library handle
 * funclistPtr is a pointer to the list of functions i.e., CK_FUNCTION_LIST
 *  
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	const char *libPath = nullptr;
	/**
	 * Instead of reading the SoftHSM full path from user every time,
	 * it's better to set an environment variable 
	 * Defining an environment variable (SOFTHSM2_LIB) for the SoftHSM library path by adding
	 *      export SOFTHSM2_LIB=/full/path/to/libsofthsm2.so
     * 
     *  1. Open .profile file in your home directory
     *  2. Simple run the command in the working terminal
	 * */
	
	libPath = getenv("SOFTHSM2_LIB");
	if(libPath == nullptr) {
		cout << "Error, SOFTHSM2_LIB environment variable is not set" << endl;
		return 1;
	}
	
	
	/**
	 * void *dlopen(const char *filename, int flags);
	 * loads the dynamic shared object (shared library) file named by the null-terminated string filename
	 * returns an opaque "handle" for the loaded object
	 * 
	 * RTLD_NOW :: Relocations are performed when the object is loaded.
	 * 
	 */

	libHandle = dlopen(libPath, RTLD_NOW);
	if (!libHandle) {
		cout << "Error, failed to load SoftHSM library into memory from path " << libPath << endl;
		return 2;
	}
	
    /**
	 * dlsym, dlvsym - obtain address of a symbol in a shared object or executable
	 * 
	 * void *dlsym(void *restrict handle, const char *restrict symbol);
	 * 
	 * The function dlsym() takes a "handle" of a dynamic loaded shared object 
	 * returned by dlopen(3) along with a null-terminated symbol name, 
	 * and returns the address where that symbol is loaded into memory. 
	 * If the symbol is not found, in the specified object or any of the shared objects 
	 * that were automatically loaded by dlopen(3) when that object was loaded, dlsym() returns NULL
	 * 
	 * On success, these functions return the address associated with symbol. 
	 * On failure, they return NULL; the cause of the error can be diagnosed using dlerror(3).
	*/
	CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(libHandle, "C_GetFunctionList");
	if (!C_GetFunctionList) {
		cout << "Error, dlsym() failed to find loaded SoftHSM library" << endl;
		return 3;
	}
	
    /**
	 * CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);
	 * 
	 * C_GetFunctionList is the only Cryptoki function which an application may call before
	 * calling C_Initialize. It is provided to make it easier and faster for applications to use
	 * shared Cryptoki libraries and to use more than one Cryptoki library simultaneously.
	 * 
	 * C_GetFunctionList obtains a pointer to the Cryptoki library’s list of function pointers.
	*/
	return check_Operation(C_GetFunctionList(&funclistPtr), "C_GetFunctionList");
	
}