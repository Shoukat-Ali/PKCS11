#include <iostream>
#ifdef WIND
	#include "..\header\common_basic_operation.hpp"
	#include "..\header\slots_token_list.hpp"
#else
	#include "../header/common_basic_operation.hpp"
	#include "../header/slots_token_list.hpp"
#endif

 

using std::cout; 
using std::cin;
using std::endl;




/**
 * The function displays some of the slot information
 * 
 * funclistPtr is a const pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * slotID is the ID of the slot
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int display_slot_info(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SLOT_ID slotID)
{
	int retVal = 0;
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

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 4;
	}

	/**
	 * CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
	 * 
	 * C_GetSlotInfo() obtains information about a particular slot in the system. 
	 * 
	 * slotID is the ID of the slot 
	 * pInfo points to the location that receives the slot information.
	 * */
	retVal = check_operation(funclistPtr->C_GetSlotInfo(slotID, &slotInfo), "C_GetSlotInfo()");
	if (!retVal) {
		cout << "For the slot ID: " 		<< slotID << endl
				<< "\tDescription : " 		<< slotInfo.slotDescription << endl
				<< "\tManufacturer ID: " 	<< slotInfo.manufacturerID << endl;
	}
	return retVal;
}


/**
 * The function displays some of the token information
 * 
 * funclistPtr is a const pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * slotID is the ID of the slot
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int display_token_info(const CK_FUNCTION_LIST_PTR funclistPtr, const CK_SLOT_ID slotID)
{
	int retVal = 0;
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

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 5;
	}

	/**
	 * CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
	 * 
	 * C_GetTokenInfo() obtains information about a particular token in the system. 
	 * 
	 * slotID is the ID of the token’s slot
	 * pInfo points to the location that receives the token information.
	*/
	retVal = check_operation(funclistPtr->C_GetTokenInfo(slotID, &tokenInfo), "C_GetTokenInfo()");
	if (!retVal) {
		cout << "For the token, we have" 			<< endl
				<< "\tLabel : " 					<< tokenInfo.label << endl
				<< "\tNo. of sessions: " 			<< tokenInfo.ulSessionCount << endl
				<< "\tMinimum PIN byte-length: "	<< tokenInfo.ulMinPinLen << endl
				<< "\tBit flag value: " 			<< tokenInfo.flags << endl;
	}
	return retVal;

}


/**
 * The function attempts to get the list of all detected slots
 * and display some information about those slots
 * 
 * funclistPtr is a const pointer to the list of functions i.e., CK_FUNCTION_LIST_PTR
 * 
 * On success, integer 0 is returned. Otherwise, non-zero integer is returned.
*/
int display_all_slot_token(const CK_FUNCTION_LIST_PTR funclistPtr)
{
	int retVal = 0;
	CK_ULONG slotsCount;
	CK_SLOT_ID_PTR slotlistPtr = NULL_PTR;

	// Checking whether funclistPtr is null or not 
	if (is_nullptr(funclistPtr)) {
		return 6;
	}
	
	if (check_operation(funclistPtr->C_Initialize(NULL_PTR), "C_Initialize()")) {
		// Operation failed
		return 6;
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
			for (unsigned long i = 0; i < slotsCount; ++i) {
				// Displaying some information about the detected slots and tokens
				retVal = display_slot_info(funclistPtr, slotlistPtr[i]);
				retVal = display_token_info(funclistPtr, slotlistPtr[i]);
				if (retVal) {
					// operatioin failed
					i = slotsCount;
				}				
			}
		}
		delete[] slotlistPtr;
	}
	
	retVal = check_operation(funclistPtr->C_Finalize(NULL_PTR), "C_Finalize()");
	return retVal;
	
}