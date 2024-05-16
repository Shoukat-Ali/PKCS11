#include <iostream>
#include <dlfcn.h>		// Required for dynamic loading, linking e.g., dlopen(), dlclose(), dlsym(), etc.
#include "../header/slots_list.hpp"
 

using std::cout; 
using std::cin;
using std::endl;



/**
 * The function checks if a requested Cryptoki (PKCS #11) operation was a success or not.
 * 
 * rv represents the CK_RV value returned by Cryptoki function
 * message represent the Cryptoki operation 
 * 
 * If the CK_RV value is CKR_OK, then the operation was success and 0 is returned. 
 * Otherwise, non-zero integer is returned on failure.
 *  
*/
int check_operation(const CK_RV rv, const char* message)
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
 * 
 * libHandle is a void pointer for SoftHSM library handle
 * funclistPtr is an alias of pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 *  
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int load_library_HSM(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	const char *libPath = nullptr;
	
	libPath = getenv("SOFTHSM2_LIB");
	if(libPath == nullptr) {
		cout << "Error, SOFTHSM2_LIB environment variable is not set" << endl;
		return 2;
	}
	
	libHandle = dlopen(libPath, RTLD_NOW);
	if (!libHandle) {
		cout << "Error, failed to load SoftHSM library into memory from path " << libPath << endl;
		return 3;
	}
	
    CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(libHandle, "C_GetFunctionList");
	if (!C_GetFunctionList) {
		cout << "Error, dlsym() failed to find loaded SoftHSM library" << endl;
		return 3;
	}
	
    return check_operation(C_GetFunctionList(&funclistPtr), "C_GetFunctionList()");
	
}




/**
 * The functions attempts to perform clean-up by freeing memory/resources
 * First, decrements the reference count on SoftHSM library handle
 * Second, assigning null to the pointer to the list of PKCS #11 function
 * 
 * The function does not return anything 
*/
void free_resource(void*& libHandle, CK_FUNCTION_LIST_PTR& funclistPtr)
{
	cout << "Clean up and free the resources\n";
	
    if (dlclose(libHandle)) {
		cout << "Error, dlclose() on softHSM library reference count\n";
	}
    funclistPtr = NULL_PTR;
	
}


/**
 * The function attempts to get the list of all detected slots
 * and display some information about those slots
 * 
 * funclistPtr is a const pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int display_slots_info(const CK_FUNCTION_LIST_PTR funclistPtr)
{
	int retVal = 0;
	CK_ULONG slotsCount;
	CK_SLOT_ID_PTR slotlistPtr = NULL_PTR;
	
	/**
	 * CK_SLOT_INFO provides information about a slot and is defined as follows:
	 * 
	 * 		typedef struct CK_SLOT_INFO {
	 * 				CK_UTF8CHAR slotDescription[64];
	 * 				CK_UTF8CHAR manufacturerID[32];
	 * 				CK_FLAGS flags;
	 * 				CK_VERSION hardwareVersion;
	 * 				CK_VERSION firmwareVersion;
	 * 		} CK_SLOT_INFO;
	*/
	CK_SLOT_INFO slotInfo;

	/**
	 * CK_TOKEN_INFO provides information about a token and is defined as follows:
	 * 
	 * 		typedef struct CK_TOKEN_INFO {
	 * 				CK_UTF8CHAR label[32];
	 * 				CK_UTF8CHAR manufacturerID[32];
	 * 				CK_UTF8CHAR model[16];
	 * 				CK_CHAR serialNumber[16];
	 * 				CK_FLAGS flags;
	 * 				CK_ULONG ulMaxSessionCount;
	 * 				CK_ULONG ulSessionCount;
	 * 				CK_ULONG ulMaxRwSessionCount;
	 * 				CK_ULONG ulRwSessionCount;
	 * 				CK_ULONG ulMaxPinLen;
	 * 				CK_ULONG ulMinPinLen;
	 * 				CK_ULONG ulTotalPublicMemory;
	 * 				CK_ULONG ulFreePublicMemory;
	 * 				CK_ULONG ulTotalPrivateMemory;
	 * 				CK_ULONG ulFreePrivateMemory;
	 * 				CK_VERSION hardwareVersion;
	 * 				CK_VERSION firmwareVersion;
	 * 				CK_CHAR utcTime[16];
	 * 		} CK_TOKEN_INFO;
	*/
	CK_TOKEN_INFO tokenInfo;

	if (check_operation(funclistPtr->C_Initialize(NULL_PTR), "C_Initialize()")) {
		// Operation failed
		return 4;
	}

	/**
	 * CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
	 * 
	 * C_GetSlotList() is used to obtain a list of slots in the system. 
	 * 
	 * tokenPresent indicates whether the list obtained includes only those slots 
	 * with a token present (CK_TRUE), or all slots (CK_FALSE);
	 * pulCount points to the location that receives the number of slots.
	 * There are two ways for an application to call C_GetSlotList:
	 * 			1. If pSlotList is NULL_PTR, then all that C_GetSlotList does is return (in *pulCount)
	 * 				the number of slots, without actually returning a list of slots. The contents of the
	 * 				buffer pointed to by pulCount on entry to C_GetSlotList has no meaning in this case,
	 * 				and the call returns the value CKR_OK.
	 * 			2. If pSlotList is not NULL_PTR, then *pulCount must contain the size (in terms of
	 * 				CK_SLOT_ID elements) of the buffer pointed to by pSlotList. If that buffer is large
	 * 				enough to hold the list of slots, then the list is returned in it, 
	 * 				and CKR_OK is returned. If not, then the call to C_GetSlotList returns the value
	 * 				CKR_BUFFER_TOO_SMALL. In either case, the value *pulCount is set to hold the
	 * 				number of slots.
	 * 
	 * Notes: C_GetSlotList() reads information from the memory when C_initialize() was called.
	 * Therefore, to read updated list of slots, 
	 * C_GetSlotList() should call C_Initialize() and C_Finalize() on very call.
	*/

	retVal = check_operation(funclistPtr->C_GetSlotList(CK_TRUE, NULL_PTR, &slotsCount), "C_GetSlotList()");
	if (retVal == 0) {
		cout << "No. of slots detected: " << slotsCount << endl;
		slotlistPtr = new CK_SLOT_ID[slotsCount];
		
		retVal = check_operation(funclistPtr->C_GetSlotList(CK_TRUE, slotlistPtr, &slotsCount), "C_GetSlotList()");
		if (!retVal) {
			// Operation successful
			for (int i = 0; i < slotsCount; ++i) {
				// Displaying some information about the detected slots
				/**
				 * CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
				 * 
				 * C_GetSlotInfo() obtains information about a particular slot in the system. 
				 * 
				 * slotID is the ID of the slot 
				 * pInfo points to the location that receives the slot information.
				 * */
				retVal = check_operation(C_GetSlotInfo(slotlistPtr[i], &slotInfo), "C_GetSlotInfo()");
				if (!retVal) {
					cout << "For the slot ID: " 	<< slotlistPtr[i] << "we have," << endl
						 << "\tDescription : " 		<< slotInfo.slotDescription << endl
						 << "\tManufacturer ID: " 	<< slotInfo.manufacturerID << endl;
				}
				/**
				 * CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
				 * 
				 * C_GetTokenInfo() obtains information about a particular token in the system. 
				 * 
				 * slotID is the ID of the token’s slot
				 * pInfo points to the location that receives the token information.
				*/
				retVal = check_operation(C_GetTokenInfo(slotlistPtr[i], &tokenInfo), "C_GetTokenInfo()");
				if (!retVal) {
					cout << "For the token, we have" << endl
						 << "\tLabel : " 		<< tokenInfo.label << endl
						 << "\tNo. of sessions: " 	<< tokenInfo.ulSessionCount << endl
						 << "\tMinimum PIN byte-length: "	<< tokenInfo.ulMinPinLen << endl
						 << "\tBit flag value: " << tokenInfo.flags << endl;
				}
				else
					i = slotsCount;
			}
		}
		delete[] slotlistPtr;
	}
	return retVal;
	
}