#include "Ntfs.h"

//�������ṹ������ring3
VOID FixNtfs(PNTFSDISPATCHBAKUP NtfsDispatchBakUp,PDRIVER_OBJECT PNtfsDriverObject,int i,ULONG ulReal_Dispatch,WCHAR *lpwzDispatchName,ULONG Dispatch)
{
	ULONG ulCurrentNtfsDispatch;
	ULONG ulHookModuleBase;
	ULONG ulHookModuleSize;
	BOOL bIsHooked = FALSE;
	ULONG ulReloadNtfsDispatch;

	NtfsDispatchBakUp->NtfsDispatch[i].ulNtfsDispatch = ulReal_Dispatch;
	NtfsDispatchBakUp->NtfsDispatch[i].ulNumber = Dispatch;

	memset(NtfsDispatchBakUp->NtfsDispatch[i].lpwzNtfsDispatchName,0,sizeof(NtfsDispatchBakUp->NtfsDispatch[0].lpwzNtfsDispatchName));
	wcsncpy(NtfsDispatchBakUp->NtfsDispatch[i].lpwzNtfsDispatchName,lpwzDispatchName,wcslen(lpwzDispatchName));
	
	ulCurrentNtfsDispatch =(ULONG) PNtfsDriverObject->MajorFunction[Dispatch];

	if (g_bDebugOn)
		KdPrint(("ulCurrentNtfsDispatch:%08x-%08x",ulCurrentNtfsDispatch,PNtfsDriverObject));

	if (ulCurrentNtfsDispatch == ulReal_Dispatch)
	{
		bIsHooked = TRUE;

		ulReloadNtfsDispatch = ulReal_Dispatch - ulNtfsModuleBase + ulReLoadNtfsModuleBase;

		//����Ƿ�inline hook
		if (GetFunctionCodeSize((PVOID)ulReal_Dispatch) == GetFunctionCodeSize((PVOID)ulReloadNtfsDispatch) &&
			memcmp((PVOID)ulReal_Dispatch,(PVOID)ulReloadNtfsDispatch,GetFunctionCodeSize((PVOID)ulReal_Dispatch)) != 0)
		{
			NtfsDispatchBakUp->NtfsDispatch[i].Hooked = 2; //fsd inline hook

			//�򵥵Ĵ���һ��ͷ5�ֽڵ�hook�ļ��
			ulCurrentNtfsDispatch = *(PULONG)(ulReal_Dispatch+1)+(ULONG)(ulReal_Dispatch+5);
			//������ǿ�ͷjmp hook����д��ԭʼ��ַ
			if (!MmIsAddressValidEx((PVOID)ulCurrentNtfsDispatch))
			{
				ulCurrentNtfsDispatch = ulReal_Dispatch;
			}
		}
	}
	if (!bIsHooked)
	{
		NtfsDispatchBakUp->NtfsDispatch[i].Hooked = 1;  //fsd hook
	}
	memset(NtfsDispatchBakUp->NtfsDispatch[i].lpszBaseModule,0,sizeof(NtfsDispatchBakUp->NtfsDispatch[0].lpszBaseModule));

	if (!IsAddressInSystem(
		ulCurrentNtfsDispatch,
		&ulHookModuleBase,
		&ulHookModuleSize,
		NtfsDispatchBakUp->NtfsDispatch[i].lpszBaseModule))
	{
		strcat(NtfsDispatchBakUp->NtfsDispatch[i].lpszBaseModule,"Unknown");
	}
	NtfsDispatchBakUp->NtfsDispatch[i].ulCurrentNtfsDispatch = ulCurrentNtfsDispatch;
	NtfsDispatchBakUp->NtfsDispatch[i].ulModuleSize = ulHookModuleSize;
	NtfsDispatchBakUp->NtfsDispatch[i].ulModuleBase = ulHookModuleBase;

}
VOID SetFsdHook(ULONG ulNumber,ULONG ulRealDispatch)
{
	PDRIVER_OBJECT PNtfsDriverObject = NULL;
	ULONG ulReloadDispatch;

	if (MmIsAddressValidEx(PNtfsDriverObjectBakup))
	{
		PNtfsDriverObject = PNtfsDriverObjectBakup;
		PNtfsDriverObject->MajorFunction[ulNumber] =(PDRIVER_DISPATCH) ulRealDispatch;   //�ָ� fsd hook

		ulReloadDispatch = ulRealDispatch - ulNtfsModuleBase + ulReLoadNtfsModuleBase;

		//�ָ� fsd inline hook
		if (GetFunctionCodeSize((PVOID)ulRealDispatch) != GetFunctionCodeSize((PVOID)ulReloadDispatch))
		{
			return;
		}
		if (memcmp((PVOID)ulRealDispatch,(PVOID)ulReloadDispatch,GetFunctionCodeSize((PVOID)ulRealDispatch)) == 0)
		{
			return;
		}
		__asm
		{
			cli
				push eax
				mov eax,cr0
				and eax,not 0x10000
				mov cr0,eax
				pop eax
		}
		memcpy((PVOID)ulRealDispatch,(PVOID)ulReloadDispatch,GetFunctionCodeSize((PVOID)ulRealDispatch));
		__asm
		{
			push eax
				mov eax,cr0
				or eax,0x10000
				mov cr0,eax
				pop eax
				sti
		}
	}
}
NTSTATUS ReLoadNtfs(PDRIVER_OBJECT DriverObject,PNTFSDISPATCHBAKUP NtfsDispatchBakUp,int IniType)
{
	ULONG ulOldNtfsDispatch;
	ULONG ulNewNtfsDispatch;
	PDRIVER_OBJECT PNtfsDriverObject = NULL;
	int i=0;
	BOOL bIsWinVer = FALSE;
	BOOL bInit = FALSE;
	WIN_VER_DETAIL WinVer;
	BOOL bIsReLoadSuccess = FALSE;
	DWORD NtfsDriverEntry=0;
	ULONG ulAddress;
	ULONG ulDriverEntryToDispatchCodeOffset;
	HANDLE hSection;
	UNICODE_STRING UnicodeModule;
	ULONG ulModuleBase;

	//��ȡdriverobject
	if (GetDriverObject(L"\\FileSystem\\Ntfs",&PNtfsDriverObject) == STATUS_SUCCESS)
	{
		PNtfsDriverObjectBakup = PNtfsDriverObject;

		ulNtfsModuleBase = (ULONG)PNtfsDriverObject->DriverStart;
		ulNtfsModuleSize = PNtfsDriverObject->DriverSize;

		//reload �Ѿ�������2003
		if (PeLoad(
			L"\\SystemRoot\\system32\\drivers\\ntfs.sys",
			(BYTE**)(&ulReLoadNtfsModuleBase),
			DriverObject,
			ulNtfsModuleBase
			))
		{
			bIsReLoadSuccess = TRUE;
		}
		if (!bIsReLoadSuccess)
		{
			return STATUS_UNSUCCESSFUL;
		}
		if (GetDriverEntryPoint((PVOID)ulReLoadNtfsModuleBase,&NtfsDriverEntry))
		{
			//KdPrint(("NtfsDriverEntry:%08x\r\n",NtfsDriverEntry));

			WinVer = GetWindowsVersion();
			switch (WinVer)
			{
			case WINDOWS_VERSION_XP:
				ulDriverEntryToDispatchCodeOffset = 0xFA;   //Ӳ�����ˣ�xp
				break;
			case WINDOWS_VERSION_7_7000:
				ulDriverEntryToDispatchCodeOffset = 0x233;   //Ӳ�����ˣ�win7_7000
				break;
			case WINDOWS_VERSION_7_7600_UP:
				ulDriverEntryToDispatchCodeOffset = 0x205;   //Ӳ�����ˣ�win7_7600_UP
				break;
			case WINDOWS_VERSION_2K3_SP1_SP2:
				ulDriverEntryToDispatchCodeOffset = 0x101;   //Ӳ�����ˣ�2003
				//ulOffset = (ULONG)PNtfsDriverObject->DriverStart - 0x10000;
				break;
			}
			ulAddress = NtfsDriverEntry + ulDriverEntryToDispatchCodeOffset;
			ulReal_IRP_MJ_LOCK_CONTROL = *(PULONG)(ulAddress+3);
			ulReal_IRP_MJ_DIRECTORY_CONTROL = *(PULONG)(ulAddress+0xA);
			ulReal_IRP_MJ_SET_INFORMATION = *(PULONG)(ulAddress+0x11);
			ulReal_IRP_MJ_CREATE = *(PULONG)(ulAddress+0x18);
			ulReal_IRP_MJ_CLOSE = *(PULONG)(ulAddress+0x1F);
			ulReal_IRP_MJ_READ = *(PULONG)(ulAddress+0x26);
			ulReal_IRP_MJ_WRITE = *(PULONG)(ulAddress+0x2D);
			ulReal_IRP_MJ_FLUSH_BUFFERS = *(PULONG)(ulAddress+0x34);
			ulReal_IRP_MJ_FILE_SYSTEM_CONTROL = *(PULONG)(ulAddress+0x3B);

			ulReal_IRP_MJ_CLEANUP  = *(PULONG)(ulAddress+0x45);
			ulReal_IRP_MJ_SHUTDOWN  = *(PULONG)(ulAddress+0x4c);
			ulReal_IRP_MJ_PNP_POWER  = *(PULONG)(ulAddress+0x56);

			if (IniType == 1)
			{
				//���ṹ
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,0,ulReal_IRP_MJ_LOCK_CONTROL,L"IRP_MJ_LOCK_CONTROL",IRP_MJ_LOCK_CONTROL);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,1,ulReal_IRP_MJ_DIRECTORY_CONTROL,L"IRP_MJ_DIRECTORY_CONTROL",IRP_MJ_DIRECTORY_CONTROL);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,2,ulReal_IRP_MJ_SET_INFORMATION,L"IRP_MJ_SET_INFORMATION",IRP_MJ_SET_INFORMATION);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,3,ulReal_IRP_MJ_CREATE,L"IRP_MJ_CREATE",IRP_MJ_CREATE);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,4,ulReal_IRP_MJ_CLOSE,L"IRP_MJ_CLOSE",IRP_MJ_CLOSE);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,5,ulReal_IRP_MJ_READ,L"IRP_MJ_READ",IRP_MJ_READ);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,6,ulReal_IRP_MJ_WRITE,L"IRP_MJ_WRITE",IRP_MJ_WRITE);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,7,ulReal_IRP_MJ_FLUSH_BUFFERS,L"IRP_MJ_FLUSH_BUFFERS",IRP_MJ_FLUSH_BUFFERS);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,8,ulReal_IRP_MJ_FILE_SYSTEM_CONTROL,L"IRP_MJ_FILE_SYSTEM_CONTROL",IRP_MJ_FILE_SYSTEM_CONTROL);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,9,ulReal_IRP_MJ_CLEANUP,L"IRP_MJ_CLEANUP",IRP_MJ_CLEANUP);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,10,ulReal_IRP_MJ_SHUTDOWN,L"IRP_MJ_SHUTDOWN",IRP_MJ_SHUTDOWN);
				FixNtfs(NtfsDispatchBakUp,PNtfsDriverObjectBakup,11,ulReal_IRP_MJ_PNP_POWER,L"IRP_MJ_PNP_POWER",IRP_MJ_PNP_POWER);
				NtfsDispatchBakUp->ulCount = 12;
				goto DebugPrintOn;
			}

			//�����еĵ��ö���reload ntfs
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_LOCK_CONTROL] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_LOCK_CONTROL - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] =(PDRIVER_DISPATCH)( ulReal_IRP_MJ_DIRECTORY_CONTROL - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_SET_INFORMATION] =(PDRIVER_DISPATCH)( ulReal_IRP_MJ_SET_INFORMATION - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_CREATE] =(PDRIVER_DISPATCH)( ulReal_IRP_MJ_CREATE - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_CLOSE - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_READ] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_READ - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_WRITE] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_WRITE - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_FLUSH_BUFFERS - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_FILE_SYSTEM_CONTROL - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_CLEANUP] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_CLEANUP - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_SHUTDOWN] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_SHUTDOWN - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
			PNtfsDriverObjectBakup->MajorFunction[IRP_MJ_PNP_POWER] = (PDRIVER_DISPATCH)(ulReal_IRP_MJ_PNP_POWER - ulNtfsModuleBase + ulReLoadNtfsModuleBase);
DebugPrintOn:
			if (g_bDebugOn)
				KdPrint(("[%08x]ulReal_IRP_MJ_LOCK_CONTROL:%08x\r\n"
				"ulReal_IRP_MJ_DIRECTORY_CONTROL:%08x\r\n"
				"ulReal_IRP_MJ_SET_INFORMATION:%08x\r\n"
				"ulReal_IRP_MJ_CREATE:%08x\r\n"
				"ulReal_IRP_MJ_CLOSE:%08x\r\n"
				"ulReal_IRP_MJ_READ:%08x\r\n"
				"ulReal_IRP_MJ_WRITE:%08x\r\n"
				"ulReal_IRP_MJ_FLUSH_BUFFERS:%08x\r\n"
				"ulReal_IRP_MJ_FILE_SYSTEM_CONTROL:%08x\r\n"
				"ulReal_IRP_MJ_CLEANUP:%08x\r\n"
				"ulReal_IRP_MJ_SHUTDOWN:%08x\r\n"
				"ulReal_IRP_MJ_PNP_POWER:%08x\r\n",
				ulAddress,
				ulReal_IRP_MJ_LOCK_CONTROL,
				ulReal_IRP_MJ_DIRECTORY_CONTROL,
				ulReal_IRP_MJ_SET_INFORMATION,
				ulReal_IRP_MJ_CREATE,
				ulReal_IRP_MJ_CLOSE,
				ulReal_IRP_MJ_READ,
				ulReal_IRP_MJ_WRITE,
				ulReal_IRP_MJ_FLUSH_BUFFERS,
				ulReal_IRP_MJ_FILE_SYSTEM_CONTROL,
				ulReal_IRP_MJ_CLEANUP,
				ulReal_IRP_MJ_SHUTDOWN,
				ulReal_IRP_MJ_PNP_POWER
				));
			if (g_bDebugOn)
				KdPrint(("[%08x]ulReal_IRP_MJ_LOCK_CONTROL:%08x\r\n"
				"ulReal_IRP_MJ_DIRECTORY_CONTROL:%08x\r\n"
				"ulReal_IRP_MJ_SET_INFORMATION:%08x\r\n"
				"ulReal_IRP_MJ_CREATE:%08x\r\n"
				"ulReal_IRP_MJ_CLOSE:%08x\r\n"
				"ulReal_IRP_MJ_READ:%08x\r\n"
				"ulReal_IRP_MJ_WRITE:%08x\r\n"
				"ulReal_IRP_MJ_FLUSH_BUFFERS:%08x\r\n"
				"ulReal_IRP_MJ_FILE_SYSTEM_CONTROL:%08x\r\n"
				"ulReal_IRP_MJ_CLEANUP:%08x\r\n"
				"ulReal_IRP_MJ_SHUTDOWN:%08x\r\n"
				"ulReal_IRP_MJ_PNP_POWER:%08x\r\n",
				ulAddress,
				ulReal_IRP_MJ_LOCK_CONTROL - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_DIRECTORY_CONTROL - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_SET_INFORMATION - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_CREATE - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_CLOSE - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_READ - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_WRITE - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_FLUSH_BUFFERS - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_FILE_SYSTEM_CONTROL - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_CLEANUP - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_SHUTDOWN - ulNtfsModuleBase + ulReLoadNtfsModuleBase,
				ulReal_IRP_MJ_PNP_POWER - ulNtfsModuleBase + ulReLoadNtfsModuleBase
				));
		}
	}
	return STATUS_SUCCESS;
}
NTSTATUS ReLoadNtfsFree()
{
	int i=0;
 	BOOL bIsWinVer = FALSE;
 	WIN_VER_DETAIL WinVer;
	PDRIVER_OBJECT PNtfsDriverObject = NULL;

	if (MmIsAddressValidEx(PNtfsDriverObjectBakup))
	{
		PNtfsDriverObject = PNtfsDriverObjectBakup;

		if (g_bDebugOn)
			KdPrint(("ReLoadNtfsFree success"));

		if (ulReal_IRP_MJ_LOCK_CONTROL)
			PNtfsDriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_LOCK_CONTROL;

		if (ulReal_IRP_MJ_DIRECTORY_CONTROL)
			PNtfsDriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] =(PDRIVER_DISPATCH) ulReal_IRP_MJ_DIRECTORY_CONTROL;

		if (ulReal_IRP_MJ_SET_INFORMATION)
			PNtfsDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_SET_INFORMATION;

		if (ulReal_IRP_MJ_CREATE)
			PNtfsDriverObject->MajorFunction[IRP_MJ_CREATE] =(PDRIVER_DISPATCH) ulReal_IRP_MJ_CREATE;

		if (ulReal_IRP_MJ_CLOSE)
			PNtfsDriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_CLOSE;

		if (ulReal_IRP_MJ_READ)
			PNtfsDriverObject->MajorFunction[IRP_MJ_READ] =(PDRIVER_DISPATCH) ulReal_IRP_MJ_READ;

		if (ulReal_IRP_MJ_WRITE)
			PNtfsDriverObject->MajorFunction[IRP_MJ_WRITE] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_WRITE;

		if (ulReal_IRP_MJ_FLUSH_BUFFERS)
			PNtfsDriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_FLUSH_BUFFERS;

		if (ulReal_IRP_MJ_FILE_SYSTEM_CONTROL)
			PNtfsDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_FILE_SYSTEM_CONTROL;

		if (ulReal_IRP_MJ_CLEANUP)
			PNtfsDriverObject->MajorFunction[IRP_MJ_CLEANUP] =(PDRIVER_DISPATCH) ulReal_IRP_MJ_CLEANUP;

		if (ulReal_IRP_MJ_SHUTDOWN)
			PNtfsDriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_SHUTDOWN;

		if (ulReal_IRP_MJ_PNP_POWER)
			PNtfsDriverObject->MajorFunction[IRP_MJ_PNP_POWER] = (PDRIVER_DISPATCH)ulReal_IRP_MJ_PNP_POWER;

	}
	return STATUS_SUCCESS;
}