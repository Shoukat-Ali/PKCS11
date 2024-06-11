/**
 * This program is an attempt to show the following operations
 * 
 *      1. Show list of all slots and tokens (initialized or not) using 
 *          i. C_GetSlotList()
 *      2. Display some slot and token information using 
 *          i.  C_GetSlotInfo() 
 *          ii. C_GetTokenInfo()
 * 
*/


#ifndef SLOTS_TOKEN_LIST_HPP
#define SLOTS_TOKEN_LIST_HPP

#include <cryptoki.h>   // exist in include directory in the same program directory with gcc use -I/path/to/include

int display_all_slot_token(const CK_FUNCTION_LIST_PTR funclistPtr);

#endif