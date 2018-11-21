#include "Process.h"

//��ͣ�߳�����
NTSTATUS ResumeProcess(PEPROCESS EProcess)
{
	NTSTATUS status=STATUS_UNSUCCESSFUL;
	NTRESUMEPROCESS ulNtResumeProcess;
	HANDLE hProcess;
	int SSDTIndex;


	if (MmIsAddressValidEx(EProcess) &&
		IsExitProcess(EProcess))
	{
		ReLoadNtosCALL((PVOID)(&g_fnRObOpenObjectByPointer),L"ObOpenObjectByPointer",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		if (!g_fnRObOpenObjectByPointer){
			return status;
		}
		status = g_fnRObOpenObjectByPointer(
			EProcess,          // Object    
			OBJ_KERNEL_HANDLE & 0,  // HandleAttributes    
			NULL,               // PassedAccessState OPTIONAL    
			PROCESS_ALL_ACCESS,       // DesiredAccess    
			*PsProcessType,     // ObjectType    
			KernelMode,         // AccessMode    
			&hProcess);    
		if (NT_SUCCESS(status))
		{
			if (GetFunctionIndexByName("NtResumeProcess",&SSDTIndex))
			{
				if (g_bDebugOn) 
					KdPrint(("SSDTIndex:%d\n",SSDTIndex));

				if (SSDTIndex >= 0 &&
					SSDTIndex <= (int)g_pOriginalServiceDescriptorTable->TableSize)
				{
					ulNtResumeProcess =(NTRESUMEPROCESS) g_pOriginalServiceDescriptorTable->ServiceTable[SSDTIndex];
					if (MmIsAddressValidEx(ulNtResumeProcess))
					{
						ulNtResumeProcess(hProcess);
					}
				}
			}
			ZwClose(hProcess);
		}
	}
	return status;
}
//��ͣ�߳�����
NTSTATUS SuspendProcess(PEPROCESS EProcess)
{
	NTSTATUS status=STATUS_UNSUCCESSFUL;
	NTSUSPENDPROCESS ulNtSuspendProcess;
	HANDLE hProcess;
	int SSDTIndex;


	if (MmIsAddressValidEx(EProcess) &&
		IsExitProcess(EProcess))
	{
		ReLoadNtosCALL((PVOID)(&g_fnRObOpenObjectByPointer),L"ObOpenObjectByPointer",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		if (!g_fnRObOpenObjectByPointer){
			return status;
		}
		status = g_fnRObOpenObjectByPointer(
			EProcess,          // Object    
			OBJ_KERNEL_HANDLE & 0,  // HandleAttributes    
			NULL,               // PassedAccessState OPTIONAL    
			PROCESS_ALL_ACCESS,       // DesiredAccess    
			*PsProcessType,     // ObjectType    
			KernelMode,         // AccessMode    
			&hProcess);    
		if (NT_SUCCESS(status))
		{
			if (GetFunctionIndexByName("NtSuspendProcess",&SSDTIndex))
			{
				if (g_bDebugOn) 
					KdPrint(("SSDTIndex:%d\n",SSDTIndex));

				if (SSDTIndex >= 0 &&
					SSDTIndex <=(int) g_pOriginalServiceDescriptorTable->TableSize)
				{
					ulNtSuspendProcess =(NTSUSPENDPROCESS )g_pOriginalServiceDescriptorTable->ServiceTable[SSDTIndex];
					if (MmIsAddressValidEx(ulNtSuspendProcess))
					{
						ulNtSuspendProcess(hProcess);
					}
				}
			}
			ZwClose(hProcess);
		}
	}
	return status;
}

//����_EPROCESS�ṹ ���û�ҵ���˵�����������
ULONG IsHideProcess(ULONG ulEProcess,PPROCESSINFO Info)
{
	SYSTEM_PROCESSES *pProcess;
	PVOID buf;
	ULONG n = 0;
	NTSTATUS status;
	BOOL bInit = FALSE;
	BOOL bRetOK = FALSE;
	int i=0;
	PEPROCESS EProcess;

	char *lpszProName = NULL;
	BOOL bIsIn = FALSE;
	ULONG ulPid;

	WIN_VER_DETAIL WinVer;
	PEPROCESS pCurrentEprocess;
	PLIST_ENTRY	pListActiveProcess;
	ULONG g_Offset_Eprocess_ProcessId;
	ULONG g_Offset_Eprocess_Flink;
	ULONG		ulCurrentProcessId = 0;
	ULONG		ulStartProcessId = 0; 
	ULONG		uCount = 0;

	//�оٽ��̵�ʱ������ͣ�޸Ľṹ
	if (bPaused)
	{
		return bRetOK;
	}
	//���ring3�˳���
	if (!IsExitProcess(g_protectEProcess))
	{
		return bRetOK;
	}
	if (!g_WinVersion)
		WinVer = GetWindowsVersion();
	else
		WinVer = g_WinVersion;

	switch(WinVer)
	{
	case WINDOWS_VERSION_XP:
		g_Offset_Eprocess_ProcessId = 0x84;
		g_Offset_Eprocess_Flink = 0x88;
		break;
	case WINDOWS_VERSION_7_7000:
	case WINDOWS_VERSION_7_7600_UP:
		g_Offset_Eprocess_ProcessId = 0xb4;
		g_Offset_Eprocess_Flink = 0xb8;
		break;
	case WINDOWS_VERSION_VISTA_2008:
		g_Offset_Eprocess_ProcessId = 0x09c;
		g_Offset_Eprocess_Flink = 0x0a0;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		g_Offset_Eprocess_ProcessId = 0x94;
		g_Offset_Eprocess_Flink = 0x98;
		break;
	case WINDOWS_VERSION_2K3:
		g_Offset_Eprocess_ProcessId = 0x084;
		g_Offset_Eprocess_Flink = 0x088;
		break;
	}
	if (!g_Offset_Eprocess_ProcessId ||
		!g_Offset_Eprocess_Flink)
	{
		return bRetOK;
	}
	bRetOK = 8;  //��ʼ������ʾ��������

	pCurrentEprocess = g_systemEProcess;
	__try
	{
		while(pCurrentEprocess != 0)
		{
			if (ulEProcess == (ULONG)pCurrentEprocess)
			{
				//��������
				bRetOK = 0;
				break;
			}
			pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
			(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink - g_Offset_Eprocess_Flink;
			if (pCurrentEprocess == g_systemEProcess)
			{
				break;
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	
	//�������ؽ��̣�����
	if (bRetOK == 8)
	{
		__try
		{
			ulPid = *(ULONG *)(ulEProcess + g_Offset_Eprocess_ProcessId);

			for (i=0;i<100;i++)
			{
				if (Info->ProcessInfo[i].EProcess ==(PEPROCESS) ulEProcess)
				{
					break;
				}
				if (!IsExitProcess(Info->ProcessInfo[i].EProcess))
				{
					Info->ProcessInfo[i].IntHideType = 1;
					Info->ProcessInfo[i].ulPid = ulPid;
					Info->ProcessInfo[i].EProcess = (PEPROCESS)ulEProcess;
					Info->ulCount++;
					break;
				}
			}
		}__except(EXCEPTION_EXECUTE_HANDLER){

		}
	}
	return bRetOK;
}
PEPROCESS GetIdleProcess()
{
	PEPROCESS IdleProcess;
	WIN_VER_DETAIL WinVer;
	ULONG ulKthread;
	ULONG IdleThreadOffset=0;
	ULONG ApcStateProcessOffset=0;

    WinVer = GetWindowsVersion();
	switch(WinVer)
	{
	case WINDOWS_VERSION_XP:
		IdleThreadOffset = 0x0C;
		ApcStateProcessOffset = 0x44;
		break;
	case WINDOWS_VERSION_7_7000:
	case WINDOWS_VERSION_7_7600_UP:
		IdleThreadOffset = 0x0C;
		ApcStateProcessOffset = 0x50;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		IdleThreadOffset = 0x0C;
		ApcStateProcessOffset = 0x38;
		break;
	}
	if (!IdleThreadOffset ||
		!ApcStateProcessOffset)
	{
		return 0;
	}
	KeSetSystemAffinityThread(1);  //ʹ��ǰ�߳������ڵ�һ����������
	_asm
	{
		mov eax,fs:[0x20] //ȡdt_KPRCB
		mov eax,[eax+0xC] //ȡIdleThread
		mov ulKthread,eax
	}
	KeRevertToUserAffinityThread();//�ָ��߳����еĴ�����

	if (MmIsAddressValidEx((PVOID)ulKthread))
	{
		//ȡApcState->Process
		IdleProcess =(PEPROCESS)( *(ULONG *)(ulKthread+ApcStateProcessOffset));
	}
	return IdleProcess;
}
BOOL GetNormalProcessList(PPROCESSINFO Info,PPROCESSINFO HideInfo)
{
	SYSTEM_PROCESSES *pProcess;
	PVOID buf;
	ULONG n = 0;
	NTSTATUS status;
	PEPROCESS EProcess;
	BOOL bRetOK = FALSE;
	BOOL bInit = FALSE;
	BOOL bNoHided = FALSE;
	int i=0,x=0,y=0;
	WIN_VER_DETAIL WinVer;
	PEPROCESS pCurrentEprocess;
	PLIST_ENTRY	pListActiveProcess;
	ULONG g_Offset_Eprocess_ProcessId;
	ULONG g_Offset_Eprocess_Flink;
	ULONG		ulCurrentProcessId = 0;
	ULONG		ulStartProcessId = 0; 
	ULONG		uCount = 0;
	WCHAR *lpwzNtFullPath = NULL;

	if (!g_WinVersion)
		WinVer = GetWindowsVersion();
	else
		WinVer = g_WinVersion;

	switch(WinVer)
	{
	case WINDOWS_VERSION_XP:
		g_Offset_Eprocess_ProcessId = 0x84;
		g_Offset_Eprocess_Flink = 0x88;
		break;
	case WINDOWS_VERSION_7_7000:
	case WINDOWS_VERSION_7_7600_UP:
		g_Offset_Eprocess_ProcessId = 0xb4;
		g_Offset_Eprocess_Flink = 0xb8;
		break;
	case WINDOWS_VERSION_VISTA_2008:
		g_Offset_Eprocess_ProcessId = 0x09c;
		g_Offset_Eprocess_Flink = 0x0a0;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		g_Offset_Eprocess_ProcessId = 0x94;
		g_Offset_Eprocess_Flink = 0x98;
		break;
	case WINDOWS_VERSION_2K3:
		g_Offset_Eprocess_ProcessId = 0x084;
		g_Offset_Eprocess_Flink = 0x088;
		break;
	}
	if (!g_Offset_Eprocess_ProcessId ||
		!g_Offset_Eprocess_Flink)
	{
		return bRetOK;
	}
	i=0;
	Info->ProcessInfo[i].IntHideType = 0;
	Info->ProcessInfo[i].ulPid = 0;
	Info->ProcessInfo[i].EProcess = GetIdleProcess();
	memset(Info->ProcessInfo[i].lpwzFullProcessPath,0,sizeof(Info->ProcessInfo[i].lpwzFullProcessPath));
	wcsncat(Info->ProcessInfo[i].lpwzFullProcessPath,L"System Idle",wcslen(L"System Idle"));
	Info->ProcessInfo[i].ulKernelOpen = 1;
	Info->ProcessInfo[i].ulInheritedFromProcessId = 0;
	i++;

	__try
	{
		pCurrentEprocess = g_systemEProcess;

		while(pCurrentEprocess != 0)
		{
			if (g_bDebugOn)
				KdPrint(("%08x\r\n",pCurrentEprocess));

			if (IsExitProcess(pCurrentEprocess))
			{
				Info->ProcessInfo[i].IntHideType = 0;
				Info->ProcessInfo[i].ulPid = *((PULONG)((ULONG)pCurrentEprocess + g_Offset_Eprocess_ProcessId));

				Info->ProcessInfo[i].EProcess = pCurrentEprocess;
				memset(Info->ProcessInfo[i].lpwzFullProcessPath,0,sizeof(Info->ProcessInfo[i].lpwzFullProcessPath));

				if (!GetProcessFullImagePath(Info->ProcessInfo[i].EProcess,Info->ProcessInfo[i].lpwzFullProcessPath))
					wcsncat(Info->ProcessInfo[i].lpwzFullProcessPath,L"Unknown",wcslen(L"Unknown"));

				if (g_bDebugOn)
					KdPrint(("[%d:%08x]%ws\r\n",Info->ProcessInfo[i].ulPid,pCurrentEprocess,Info->ProcessInfo[i].lpwzFullProcessPath));

				Info->ProcessInfo[i].ulKernelOpen = KernelStatus((HANDLE)Info->ProcessInfo[i].ulPid);
				Info->ProcessInfo[i].ulInheritedFromProcessId = GetInheritedProcessPid(Info->ProcessInfo[i].EProcess);
				i++;
				Info->ulCount = i;
			}

			pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
			(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink - g_Offset_Eprocess_Flink;
			if (pCurrentEprocess == g_systemEProcess)
			{
				break;
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	//������ؽ���
	for (x=0;x<100;x++)
	{
		//�����Ƿ��˳�
		if (IsExitProcess(HideInfo->ProcessInfo[x].EProcess))
		{
			bNoHided = FALSE;
			//����һ��׼ȷ���жϣ���������������������ʾ�����ؽ���
			pCurrentEprocess = g_systemEProcess;

			while(pCurrentEprocess != 0)
			{
				if (HideInfo->ProcessInfo[x].EProcess == pCurrentEprocess)
				{
					//��������
					bNoHided = TRUE;
					break;
				}
				pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
				(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink - g_Offset_Eprocess_Flink;
				if (pCurrentEprocess == g_systemEProcess)
				{
					bNoHided = TRUE;
					break;
				}
			}
			//���ؽ���
			if (!bNoHided)
			{
				Info->ProcessInfo[i].IntHideType = HideInfo->ProcessInfo[x].IntHideType;
				Info->ProcessInfo[i].ulPid = HideInfo->ProcessInfo[x].ulPid;
				Info->ProcessInfo[i].EProcess = HideInfo->ProcessInfo[x].EProcess;

				memset(Info->ProcessInfo[i].lpwzFullProcessPath,0,sizeof(Info->ProcessInfo[i].lpwzFullProcessPath));

				if (!GetProcessFullImagePath(HideInfo->ProcessInfo[x].EProcess,Info->ProcessInfo[i].lpwzFullProcessPath))
					wcsncat(Info->ProcessInfo[i].lpwzFullProcessPath,L"Unknown",wcslen(L"Unknown"));

				Info->ProcessInfo[i].ulKernelOpen = KernelStatus((HANDLE)HideInfo->ProcessInfo[x].ulPid);
				Info->ProcessInfo[i].ulInheritedFromProcessId = GetInheritedProcessPid(HideInfo->ProcessInfo[x].EProcess);
				i++;
				Info->ulCount = i;
			}
		}
	}
	return bRetOK;
}