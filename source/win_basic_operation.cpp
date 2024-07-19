#include "..\header\common_basic_operation.hpp"
#include "..\header\win_basic_operation.hpp"
#include <iostream>
#include <windows.h>	// On Windows, required for WinAPI

 

using std::cout; 
using std::cin;
using std::endl;




/**
 * The function attempts to load SoftHSM library in order to use PKCS# 11 functions/API.
 * 
 * libHandle is an alias of HINSTANCE for SoftHSM library handle
 * funclistPtr is an alias of pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 *  
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int load_library_HSM(HINSTANCE& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	/**
	 * Instead of reading the SoftHSM full path from user every time,
	 * it's better to set an environment variable 
	 * Defining an environment variable (SOFTHSM2_LIB) for the SoftHSM library path by adding
	 * 
	 * On Windows, go to "Advance system settings" and click the "environment variables" button.
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
	 * The LoadLibrary() function maps the specified DLL file into the address space 
	 * of the calling process.
	 * 		HINSTANCE LoadLibrary(lpLibFileName);
	 * 
	 * lpLibFileName is a pointer to a null-terminated string that names the DLL file.
	 * The name specified is the file name of the module and is not related to the name 
	 * stored in the library module itself, as specified by the LIBRARY keyword 
	 * in the module-definition (.def) file. If the string specifies a path but the file 
	 * does not exist in the specified directory, the function fails.
	 * When specifying a path, be sure to use backslashes (\), not forward slashes (/).
	 * If the string does not specify a path, the function uses a standard search strategy 
	 * to find the file.
	 * 
	 * Return
	 * A handle to the module indicates success. NULL indicates failure.
	 * 
	 * LoadLibrary can be used to doing the following:
	 * 		1. Map a DLL module and return a handle that can be used in GetProcAddress 
	 * 		to get the address of a DLL function. 
	 * 		You need to use FreeLibrary on the handle later.
	 * 		2. Map other executable modules. For example, the function can specify an .exe file 
	 * 		to get a handle that can be used in FindResource or LoadResource.
	 * 
	 * Do not use LoadLibrary to run a .exe file. Use the CreateProcess function.
	 */
	libHandle = LoadLibrary(libPath);
	
	if (!libHandle) {
		cout << "Error, failed to load SoftHSM library into memory from path " << libPath << endl;
		return 3;
	}

	CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle,"C_GetFunctionList");
	// CK_C_GetFunctionList C_GetFunctionList = reinterpret_cast<CK_C_GetFunctionList> (GetProcAddress(libHandle, "C_GetFunctionList"));
	
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
void free_resource(HINSTANCE& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	cout << "Clean up and free the resources\n";
	/**
	 * 
	 */
	FreeLibrary(libHandle);
	
    funclistPtr = NULL_PTR;
}