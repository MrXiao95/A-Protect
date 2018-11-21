#include "ReLoadSSDTTableHook.h"

extern PSERVICE_DESCRIPTOR_TABLE g_pSafe_ServiceDescriptorTable;
extern PSERVICE_DESCRIPTOR_TABLE g_pOriginalServiceDescriptorTable;

BOOL SystemCallEntryTableHook(char *FunctionName,int *Index,DWORD NewFuctionAddress)
{
	KIRQL oldIrql; 
	BOOL bRetOK = FALSE;
	DWORD FunctionAddress;

	if (!GetFunctionIndexByName(FunctionName,Index))
	{
		return bRetOK;
	}
	__try
	{
		if (MmIsAddressValidEx(g_pSafe_ServiceDescriptorTable) &&
			MmIsAddressValidEx(g_pSafe_ServiceDescriptorTable->ServiceTable))
		{
			if (*Index >= 0 && *Index < (int)g_pSafe_ServiceDescriptorTable->TableSize)
			{
				//因为是自己reload表，所以不需要开启cr0
// 				_asm
// 				{
// 					CLI  ;                 
// 					MOV    EAX, CR0  ;    
// 					AND EAX, NOT 10000H ;
// 					MOV    CR0, EAX;        
// 				}

				InterlockedExchange(&g_pSafe_ServiceDescriptorTable->ServiceTable[*Index],NewFuctionAddress);
				bRetOK = TRUE;

// 				_asm 
// 				{
// 					MOV    EAX, CR0;          
// 					OR    EAX, 10000H;            
// 					MOV    CR0, EAX ;              
// 					STI;                    
// 				}
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	return bRetOK;

}
BOOL SystemCallEntryTableUnHook(int Index)
{
	KIRQL oldIrql; 

	g_pSafe_ServiceDescriptorTable->ServiceTable[Index] = 0;

	return TRUE;
}