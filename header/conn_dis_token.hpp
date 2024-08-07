/**
 * This program is an attempt to show the following operations
 * 
 *      1. Load the HSM library by setting an environment variable SOFTHSM2_LIB in order to use PKCS #11 functions
 *      2. Connect to valid slot using the followings
 *          i.      C_Initialize() 
 *          ii.     C_OpenSession() 
 *          iii.    C_Login()
 *      3. Disconnect from a connect slot using the followings
 *          i.      C_Logout() 
 *          ii.     C_CloseSession() 
 *          iii.    C_Finalize()
 * 
*/


#ifndef CONN_DISCONN_HPP
#define CONN_DISCONN_HPP

#include <string>
#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include


int connect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession, std::string& usrPIN);

int disconnect_slot(const CK_FUNCTION_LIST_PTR funclistPtr, CK_SESSION_HANDLE& hSession);


#endif