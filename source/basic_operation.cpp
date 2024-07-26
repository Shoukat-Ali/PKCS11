#include <iostream>
#include <dlfcn.h>		// On Linux, required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/basic_operation.hpp"
#include "../header/common_basic_operation.hpp"
 

using std::cout; 
using std::cin;
using std::endl;



/**
 * The function attempts to load SoftHSM library in order to use PKCS# 11 functions/API.
 * 
 * libHandle is a void pointer for SoftHSM library handle
 * funclistPtr is an alias of pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 *  
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	char* libError;
	/**
	 * Instead of reading the SoftHSM full path from user every time,
	 * it's better to set an environment variable 
	 * Defining an environment variable (SOFTHSM2_LIB) for the SoftHSM library path by adding
	 * 
	 * On Linux, performe the following operations
	 *      export SOFTHSM2_LIB=/full/path/to/libsofthsm2.so
     * 
     *  1. Open .profile file in your home directory
     *  2. Simple run the command in the working terminal
	 * 
	 * 
	 * char *getenv(const char *name);
	 * 
	 * The getenv() function searches the environment list to find the
	 * environment variable name, and returns a pointer to the corresponding value string.
	 * 
	 * The function returns a pointer to the value in the 
	 * environment, or NULL if there is no match.
	 * 
	 * */

	const char* libPath = getenv("SOFTHSM2_LIB");
	if(!libPath) {
		cout << "Error, SOFTHSM2_LIB environment variable is not set" << endl;
		return 2;
	}
	
	/**
	 * void *dlopen(const char *filename, int flags);
	 * 
	 * loads the dynamic shared object (shared library) file named by the null-terminated 
	 * string filename.
	 * returns an opaque "handle" for the loaded object
	 * 
	 * RTLD_NOW :: Relocations are performed when the object is loaded.
	 * If dlopen() fails for any reason, it returns NULL.
	 * 
	 * */
	libHandle = dlopen(libPath, RTLD_NOW);

	if (!libHandle) {
		cout << "Error, failed to load SoftHSM library into memory from path " << libPath << endl;
		return 3;
	}

	/**
	 * char *dlerror(void);
	 * 
	 * The function dlerror() returns a human readable string describing the most recent error 
	 * that occurred from dlopen(), dlsym() or dlclose() since the last call to dlerror(). 
	 * It returns NULL if no errors have occurred since initialization or since it was last called. 
	 * 
	 * */    
	dlerror();	// This call is required before calling dlsym() to clear any existing error

	/**
	 * dlsym, dlvsym - obtain address of a symbol in a shared object or executable
	 * 
	 * void *dlsym(void *restrict handle, const char *restrict symbol);
	 * 
	 * The function dlsym() takes a "handle" of a dynamic library returned by dlopen() 
	 * and the null-terminated symbol name, returning the address where that symbol is 
	 * loaded into memory. If the symbol is not found, in the specified library or 
	 * any of the libraries that were automatically loaded by dlopen() when that library 
	 * was loaded, dlsym() returns NULL. (The search performed by dlsym() is breadth first 
	 * through the dependency tree of these libraries.) Since the value of the symbol could actually 
	 * be NULL (so that a NULL return from dlsym() need not indicate an error), 
	 * the correct way to test for an error is to call dlerror() to clear any old error conditions, 
	 * then call dlsym(), and then call dlerror() again, saving its return value into a variable, 
	 * and check whether this saved value is not NULL. 
	 * 
	 * On success, these functions return the address associated with symbol. 
	 * On failure, they return NULL; the cause of the error can be diagnosed using dlerror(3).
	 * */

	// CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(libHandle, "C_GetFunctionList");
	CK_C_GetFunctionList C_GetFunctionList = reinterpret_cast<CK_C_GetFunctionList> (dlsym(libHandle, "C_GetFunctionList"));
	libError = dlerror();		// Recommended to save dlerror() return value
	if (libError) {
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
	return check_operation(C_GetFunctionList(&funclistPtr), "C_GetFunctionList()");
	
}




/**
 * The functions attempts to perform cleanup by freeing memory/resources
 * First, decrements the reference count on SoftHSM library handle
 * Second, assigning null to the pointer to the list of PKCS #11 function
 * Lastily, removing/clearing the user PIN
 * 
 * libHandle is an alias of void pointer for SoftHSM library handle
 * funclistPtr is an alias of pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * usrPIN is an alias of user PIN
 * 
 * The function does not return anything 
*/
void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	cout << "Clean up and free the resources\n";
	/**
	 * int dlclose(void *handle); 
	 * The function dlclose() decrements the reference count on the dynamic library handle. 
	 * If the reference count drops to zero and no other loaded libraries use symbols in it, 
	 * then the dynamic library is unloaded.
	 * The function dlclose() returns 0 on success, and nonzero on error. 
	*/
	if (dlclose(libHandle)) {
		cout << "Error, dlclose() on softHSM library reference count\n";
	}
	
    funclistPtr = NULL_PTR;
}