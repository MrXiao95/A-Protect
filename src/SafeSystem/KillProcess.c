#include "killprocess.h"

//bIsQueryThread
//false->kill
//true->query
PETHREAD NTAPI GetNextProcessThread(
	IN PEPROCESS Process,
	IN PETHREAD Thread OPTIONAL,
	IN BOOL bIsQueryThread
	)
{
	PETHREAD FoundThread = NULL;
	PLIST_ENTRY ListHead, Entry;

	if (!MmIsAddressValidEx(Process)){
		return NULL;
	}
	if (Thread){
		if (!MmIsAddressValidEx(Thread)){
			return NULL;
		}
	}
	if (Thread)
	{
		//  Entry = Thread->ThreadListEntry.Flink;;//   +0x22c ThreadListEntry  : _LIST_ENTRY
		Entry = (PLIST_ENTRY)((ULONG)(Thread)+ThreadProc);
		Entry=Entry->Flink;
	}
	else
	{
		Entry = (PLIST_ENTRY)((ULONG)(Process)+ThreadListHead);//+0x190 ThreadListHead   : _LIST_ENTRY
		Entry = Entry->Flink; 
	}
	// ListHead = &Process->ThreadListHead;
	ListHead = (PLIST_ENTRY)((ULONG)Process + ThreadListHead);

	while (ListHead != Entry)
	{
		FoundThread = (PETHREAD)((ULONG)Entry - ThreadProc);

		//如果是结束进程的话，就ObReferenceObject掉线程的引数
		if (!bIsQueryThread){
			if (MmIsAddressValidEx(FoundThread)){
				if (ObReferenceObject(FoundThread))
					break;
			}
		}
		if (MmIsAddressValidEx(FoundThread))
			break;

		FoundThread = NULL;
		Entry = Entry->Flink;
	}
	if (!bIsQueryThread){
		if (Thread)
			ObDereferenceObject(Thread);
	}
	return FoundThread;
}
//只要一条线程结束失败，就当做进程结束失败
NTSTATUS TerminateProcess(IN ULONG EProcess,BOOL SysVersionCheck)
{
	NTSTATUS          Status;
	PETHREAD          Thread;
	PEPROCESS         Process;
	ULONG PsLookupProcess;
	UNICODE_STRING PsLookupProcessString;


	Status = STATUS_UNSUCCESSFUL;

	if (g_bDebugOn)
		DbgPrint( "( 0x%x ) ( 0x%x )", UniqueProcessIdOffset,ActiveProcessLinksOffset );

	Process = (PEPROCESS)EProcess;
	if (g_bDebugOn)
		DbgPrint( "TerminateProcess( 0x%08x )", Process );

	__try
	{
		for (Thread = GetNextProcessThread(Process, NULL,FALSE);
			Thread != NULL;
			Thread = GetNextProcessThread(Process, Thread,FALSE))
		{
			//如果线程结束了
			if (PsIsThreadTerminating(Thread)){
				continue;
			}
			if (SysVersionCheck == WINDOWS_VERSION_XP)
			{
				//DbgPrint("WINDOWS_VERSION_XP");

				Status = (*PspTerminateThreadByPointer_XP)( 
					Thread, 
					0
					);  //XP下
				if (!NT_SUCCESS(Status)){
					break;
				}

			}else if (SysVersionCheck == WINDOWS_VERSION_2K3 || SysVersionCheck == WINDOWS_VERSION_2K3_SP1_SP2)
			{
				//DbgPrint("WINDOWS_2003");

				Status = (*PspTerminateThreadByPointer_K)(
					Thread,
					0,
					FALSE
					);  //2003下
				if (!NT_SUCCESS(Status)){
					break;
				}
			}else if (SysVersionCheck == WINDOWS_VERSION_VISTA_2008 ||
				SysVersionCheck == WINDOWS_VERSION_7_7000 || SysVersionCheck == WINDOWS_VERSION_7_7600_UP)
			{
				//DbgPrint("WINDOWS_VERSION_VISTA_2008");

				Status = (*PspTerminateThreadByPointer_K)( 
					Thread,
					0,
					TRUE
					);  //vista下，煮一个参数为　ＴＲＵＥ
				if (!NT_SUCCESS(Status)){
					break;
				}
			}
			//DbgPrint( "PspTerminateThreadByPointer():\t0x%08x", Status );
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
		Status = GetExceptionCode();
	}
	if (g_bDebugOn)
		DbgPrint("TerminateProcess() end:\t0x%08x", Status );

	return Status;
}
PVOID Search_PspTerminateThreadByPointer(BOOL SysVersionCheck)
{
	PUCHAR cPtr;
	BOOL bRetOK = FALSE;
	ULONG addret;
	ULONG ulReloadAddress;

	if (g_bDebugOn)
		DbgPrint( "PsTerminateSystemThread:\t0x%08x", PsTerminateSystemThread);

	_try
	{
		for (cPtr = (PUCHAR)PsTerminateSystemThread;  cPtr < (PUCHAR)PsTerminateSystemThread + PAGE_SIZE; cPtr++)
		{
			//DbgPrint("search....");

			if (SysVersionCheck == WINDOWS_VERSION_XP || 
				SysVersionCheck == WINDOWS_VERSION_VISTA_2008 || 
				SysVersionCheck == WINDOWS_VERSION_2K3_SP1_SP2 ||
				SysVersionCheck == WINDOWS_VERSION_7_7000 ||
				SysVersionCheck == WINDOWS_VERSION_7_7600_UP)
			{
				//DbgPrint("WINDOWS_VERSION_XP || WINDOWS_VERSION_VISTA_2008 ||　WINDOWS_VERSION_2K3_SP1_SP2");

				if (*cPtr == 0xE8 && *(PUSHORT)(cPtr + 5) == 0xC25D) 
				{
					addret = (*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
					if (g_bDebugOn)
						DbgPrint( "PspTerminateThreadByPointer:\t0x%08x", (ULONG)addret);
					ulReloadAddress = addret - g_pOldSystemKernelModuleBase +(ULONG) g_pNewSystemKernelModuleBase;
					bRetOK = TRUE;
					break;
				}

			}else if (SysVersionCheck == WINDOWS_VERSION_2K3)
			{
				//DbgPrint("WINDOWS_VERSION_2K3");

				if (*cPtr == 0xE8 && *(PUSHORT)(cPtr + 5) == 0x04C2)
				{
					addret = (*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
					ulReloadAddress = addret - g_pOldSystemKernelModuleBase +(ULONG)g_pNewSystemKernelModuleBase;
					if (g_bDebugOn)
						DbgPrint( "PspTerminateThreadByPointer:\t0x%08x", (ULONG)addret);
					bRetOK = TRUE;
					break;
				}
			}

		}
	}__except(EXCEPTION_EXECUTE_HANDLER)
	{
		if (g_bDebugOn)
			DbgPrint("Search_PspTerminateThreadByPointer Error \r\n");
	}
	if (bRetOK == TRUE)
	{
		return (PVOID)ulReloadAddress;
	}
	return (PVOID)bRetOK;
}
BOOL IniKillObject()
{
	WIN_VER_DETAIL WinVer;
	BOOL bRetOK = FALSE;

	WinVer=GetWindowsVersion();

	if (WinVer == WINDOWS_VERSION_XP)
	{
		//初始化各个变量
		ThreadProc = 0x22C;
		ThreadListHead = 0x190;

		UniqueProcessIdOffset=0x084;
		ActiveProcessLinksOffset=0x088;

		PspTerminateThreadByPointer_XP = Search_PspTerminateThreadByPointer(WinVer);
		if (PspTerminateThreadByPointer_XP != FALSE)
		{
			bRetOK = TRUE;
		}

	}else if (WinVer == WINDOWS_VERSION_2K3 || 
		WinVer == WINDOWS_VERSION_2K3_SP1_SP2 || 
		WinVer == WINDOWS_VERSION_VISTA_2008 ||
		WinVer == WINDOWS_VERSION_7_7000 ||
		WinVer == WINDOWS_VERSION_7_7600_UP )   //2003以上版本，PspTerminateThreadByPointer都是3个参数
	{
		PspTerminateThreadByPointer_K = Search_PspTerminateThreadByPointer(WinVer);
		if (PspTerminateThreadByPointer_K != FALSE)
		{
			bRetOK = TRUE;

			if (WinVer == WINDOWS_VERSION_2K3)
			{
				if (g_bDebugOn)
					DbgPrint("WINDOWS_VERSION_2K3\r\n");
				ThreadProc = 0x234;
				ThreadListHead = 0x170;

				UniqueProcessIdOffset=0x084;
				ActiveProcessLinksOffset=0x088;

			}
			else if (WinVer == WINDOWS_VERSION_2K3_SP1_SP2)
			{
				if (g_bDebugOn)
					DbgPrint("WINDOWS_VERSION_2K3_SP1_SP2\r\n");
				ThreadProc = 0x224;
				ThreadListHead = 0x180;

				UniqueProcessIdOffset=0x094;
				ActiveProcessLinksOffset=0x098;

			}
			else if (WinVer == WINDOWS_VERSION_VISTA_2008)
			{
				if (g_bDebugOn)
					DbgPrint("WINDOWS_VERSION_VISTA_2008!!\r\n");

				ThreadProc = 0x248;
				ThreadListHead = 0x168;

				UniqueProcessIdOffset=0x09c;
				ActiveProcessLinksOffset=0x0a0;
			}
			else if (WinVer == WINDOWS_VERSION_7_7000 || WinVer == WINDOWS_VERSION_7_7600_UP)
			{
				if (g_bDebugOn)
					DbgPrint("WINDOWS_VERSION_7!!\r\n");

				ThreadProc = 0x268;
				ThreadListHead = 0x188;

				if (WinVer == WINDOWS_VERSION_7_7000){
					ThreadListHead = 0x180;
				}
				UniqueProcessIdOffset=0x0b4;
				ActiveProcessLinksOffset=0x0b8;
			}
		}

	}else
	{
		if (g_bDebugOn)
			DbgPrint("Unkown!!\r\n");
		bRetOK = FALSE;
	}
	return bRetOK;
}
NTSTATUS KillProcess(ULONG ulEprocess)
{
	WIN_VER_DETAIL WinVer;

	if (!ulEprocess ||
		!MmIsAddressValidEx((PVOID)ulEprocess) ||
		!IsExitProcess((PEPROCESS)ulEprocess))
	{
		return STATUS_UNSUCCESSFUL;
	}
	WinVer = GetWindowsVersion();
	if (IniKillObject())
	{
		return TerminateProcess(ulEprocess,WinVer); //结束啊
	}
	return STATUS_UNSUCCESSFUL;
}
//进程虚拟空间填0
BOOL ZeroProcessMemory(ULONG EProcess)
{
	ULONG ulVirtualAddr;
	BOOL bInit = FALSE;
	BOOL bRetOK = FALSE;
	PVOID ZeroMemoryBase = NULL;
	HANDLE ProcessHandle;
	NTSTATUS Status;

	ReLoadNtosCALL((PVOID)(&g_fnRKeAttachProcess),L"KeAttachProcess",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&RKeDetachProcess),L"KeDetachProcess",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExAllocatePool),L"ExAllocatePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRObOpenObjectByPointer),L"ObOpenObjectByPointer",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRKeAttachProcess &&
		RKeDetachProcess &&
		g_fnRExAllocatePool &&
		g_fnRExFreePool &&
		g_fnRObOpenObjectByPointer &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return bRetOK;

	ZeroMemoryBase = g_fnRExAllocatePool(NonPagedPool,0x1024);
	if (!ZeroMemoryBase){
		return bRetOK;
	}
	memset(ZeroMemoryBase,0xcc,0x1024);
	
	g_fnRKeAttachProcess((PEPROCESS)EProcess);  //Attach进程虚拟空间

	for(ulVirtualAddr=0;ulVirtualAddr<=0x7fffffff;ulVirtualAddr+=0x1024)
	{
		//蓝屏原因：用户内存是否可写要进行验证。用ProbeForWrite函数
		if(MmIsAddressValidEx((PVOID)ulVirtualAddr))
		{
			__try
			{
				ProbeForWrite((PVOID)ulVirtualAddr,0x1024,sizeof(ULONG));
				RtlCopyMemory((PVOID)ulVirtualAddr,ZeroMemoryBase,0x1024);
				bRetOK = TRUE;
			}
			__except(EXCEPTION_EXECUTE_HANDLER){ 
				continue;        
			}
		}
		else{
			if(ulVirtualAddr > 0x1000000)  //填这么多足够破坏进程数据了
				break;
		}
	}
	//退出这个进程的空间
	RKeDetachProcess();

	//释放申请的内存
	g_fnRExFreePool(ZeroMemoryBase);

	//验证下是否结束了这个进程
	Status = g_fnRObOpenObjectByPointer(
		(PEPROCESS)EProcess,
		OBJ_KERNEL_HANDLE,
		0, 
		GENERIC_READ, 
		*PsProcessType, 
		KernelMode, 
		&ProcessHandle
		);

	//进程还存在，结束失败
	if (NT_SUCCESS(Status)){
		g_fnRZwClose(ProcessHandle);
		bRetOK = FALSE;
	}
	return bRetOK;
}