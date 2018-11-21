#include "IoTimer.h"

ULONG QueryIopTimerQueueHead()
{
	UNICODE_STRING UnicodeFuncName;
	ULONG ulFunction;
	ULONG ulCodeSize;
	ULONG IopTimerQueueHead = 0;
	PUCHAR i=0;

	RtlInitUnicodeString(&UnicodeFuncName,L"IoInitializeTimer");
	ulFunction = (ULONG)MmGetSystemRoutineAddress(&UnicodeFuncName);
	if (ulFunction)
	{
		//KdPrint(("IoInitializeTimer:%08x\n",ulFunction));
		ulCodeSize = GetFunctionCodeSize((PVOID)ulFunction);
		if (ulCodeSize)
		{
			for (i=(PUCHAR)ulFunction;i<(PUCHAR)(ulFunction+ulCodeSize);i++)
			{
				if (*i == 0xb9)
				{
					IopTimerQueueHead = *(PULONG)(i+1);
					if (MmIsAddressValidEx((PVOID)IopTimerQueueHead))
					{
						break;
					}
				}
			}
		}
	}
	return IopTimerQueueHead;
}
// IoStartTimer
//IoStopTimer
VOID QueryIoTimer(PMyIoTimer IoTimer)
{
	PLIST_ENTRY  pList = NULL;
	PLIST_ENTRY pNextList = NULL;
	PIO_TIMER  pTimer = NULL;
	int i = 0;
	ULONG ulModuleBase;
	ULONG ulModuleSize;

	pList = (PLIST_ENTRY)QueryIopTimerQueueHead();
	if (!pList)
		return;

	//KdPrint(("IopTimerQueueHead -> %08x\n",pList));

	for ( pNextList = pList->Blink; pNextList != pList; pNextList = pNextList->Blink )    //����blink��
	{
		pTimer = CONTAINING_RECORD(pNextList,IO_TIMER,TimerList);            //�õ��ṹ��

		//KdPrint(("DeviceObject:%08x\nTimerRoutine:%08x\r\n\r\n",pTimer->DeviceObject,pTimer->TimerRoutine));

		if (MmIsAddressValidEx(pTimer) &&
			MmIsAddressValidEx(pTimer->DeviceObject) &&
			MmIsAddressValidEx(pTimer->TimerRoutine) &&
			MmIsAddressValidEx(&pTimer->TimerFlag) )                    //����
		{
			IoTimer->MyTimer[i].DeviceObject = (ULONG)pTimer->DeviceObject;
			IoTimer->MyTimer[i].IoTimerRoutineAddress =(ULONG) pTimer->TimerRoutine;
			IoTimer->MyTimer[i].ulStatus = pTimer->TimerFlag;
			if (!IsAddressInSystem(
				IoTimer->MyTimer[i].IoTimerRoutineAddress,
				&ulModuleBase,
				&ulModuleSize,
				IoTimer->MyTimer[i].lpszModule))
			{
				strcat(IoTimer->MyTimer[i].lpszModule,"Unknown");
			}
			i++;
			IoTimer->ulCount = i;
		}
		if (!MmIsAddressValidEx(pNextList->Blink))
		{
			break;                  //����
		}
	}
}
VOID IoTimerControl(PDEVICE_OBJECT DeviceObject,int Type)
{
	ReLoadNtosCALL((PVOID)(&g_fnRIoStartTimer),L"IoStartTimer",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoStopTimer),L"IoStopTimer",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRIoStartTimer &&
		g_fnRIoStopTimer)
	{
		if (MmIsAddressValidEx(DeviceObject))
		{
			switch (Type)
			{
			case 0:
				g_fnRIoStopTimer(DeviceObject);
				break;
			case 1:
				g_fnRIoStartTimer(DeviceObject);
				break;
			}
		}
	}
}