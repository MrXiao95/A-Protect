#include "NetworkDefense.h"

//从文件路径获取文件名
BOOL GetFileName(__in WCHAR *FilePath,__in int len,__out WCHAR *FileName)
{
	int i=0;
	WCHAR lpPath[260*2];
	BOOL bRetOK = FALSE;

	//wcslen(L"x:\\")*2
	//效验合法的长度，不然产生溢出漏洞，要蓝屏哦
	if (len < 6 || len > 260)
		return bRetOK;

	memset(lpPath,0,sizeof(lpPath));
	memset(FileName,0,sizeof(FileName));

	memcpy(lpPath,FilePath,len);
	for(i=0;i<len;i++)
	{
		if (wcsstr(lpPath,L"\\") == 0)
		{
			bRetOK = TRUE;

			//FileName的最大长度能容纳lpPath的实际长度，不然蓝屏！
			if (sizeof(FileName) > wcslen(lpPath))
			{
				memcpy(FileName,lpPath,wcslen(lpPath)*2);
			}
			break;
		}
		memset(lpPath,0,sizeof(lpPath));
		memcpy(lpPath,FilePath+i,wcslen(FilePath+i)*2);
	}
	return bRetOK;
}

ULONG CheckExeFileOrDllFileBySectionHandle(HANDLE hSection)
{
	NTSTATUS status;
	PVOID BaseAddress = NULL;
	SIZE_T size=0;
	PIMAGE_NT_HEADERS PImageNtHeaders;

	if (!hSection)
		return 0;

	ReLoadNtosCALL((PVOID)(&g_fnRZwMapViewOfSection),L"ZwMapViewOfSection",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (!g_fnRZwMapViewOfSection)
		return 0;

	status = g_fnRZwMapViewOfSection(
		hSection, 
		NtCurrentProcess(),
		&BaseAddress, 
		0,
		1000, 
		0,
		&size,
		(SECTION_INHERIT)1,
		MEM_TOP_DOWN, 
		PAGE_READWRITE
		); 
	if(NT_SUCCESS(status))
	{
		if (g_bDebugOn)
			KdPrint(("ZwMapViewOfSection success"));

		PImageNtHeaders = RtlImageNtHeader(BaseAddress);
		if (PImageNtHeaders)
		{
			if (g_bDebugOn)
				KdPrint(("Characteristics:%08x\r\n",PImageNtHeaders->FileHeader.Characteristics));

			return PImageNtHeaders->FileHeader.Characteristics;
		}
	}
	return 0;
}
////////////////////////////////////////////////
/*
ZwCreateSection hook, DKOM type.
*/
NTSTATUS _stdcall NewZwCreateSection(
	__out     PHANDLE SectionHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt  PLARGE_INTEGER MaximumSize,
	__in      ULONG SectionPageProtection,
	__in      ULONG AllocationAttributes,
	__in_opt  HANDLE FileHandle)
{
	NTSTATUS status;
	PEPROCESS Eprocess;
	PFILE_OBJECT FileObject;
	PVOID object_temp;
	POBJECT_HEADER ObjectHeader;
	POBJECT_TYPE FileObjectType;
	WIN_VER_DETAIL WinVer;
	BOOL bRetOK = FALSE;
	BOOL bInherited = FALSE;
	int i;
	WCHAR *lpwzExeFile = NULL;
	WCHAR *lpwzExeNtFile = NULL;
	KPROCESSOR_MODE PreviousMode;
	UNICODE_STRING UnicodeDNSAPI_DLL;
	UNICODE_STRING UnicodeExeNtFilePath;
	UNICODE_STRING UnicodeFunction;
	char *lpszProName = NULL;
	BOOL bNetworkDefence = FALSE;
	BOOL bInitAPISuccess = FALSE;
	POBJECT_NAME_INFORMATION DosFullPath=NULL;
	ULONG ulExeFileCharacteristics,ulDllFileCharacteristics;
	ULONG ulIsExeDllModule;
	STRING lpszProString;
	STRING lpszSvchostString;
	STRING lpszWinlogonString;
	STRING lpszServicesString;
	STRING lpszCmdString;
	STRING lpszExplorer;
	WCHAR lpwzDirFile[260];
	WCHAR FileName[260*2];
	WCHAR SystemFile[260];
	BOOL bIsInjectDllInto3600 = FALSE;
	ULONG ulPathSize;
	ZWCREATESECTION OldZwCreateSection;

	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByHandle),L"ObReferenceObjectByHandle",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&RPsGetCurrentProcessId),L"PsGetCurrentProcessId",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRPsGetProcessImageFileName),L"PsGetProcessImageFileName",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExAllocatePool),L"ExAllocatePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoQueryFileDosDeviceName),L"IoQueryFileDosDeviceName",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRRtlCompareString),L"RtlCompareString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitString),L"RtlInitString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRRtlCompareUnicodeString),L"RtlCompareUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRPsGetCurrentProcess &&
		g_fnRObReferenceObjectByHandle &&
		RPsGetCurrentProcessId &&
		g_fnRPsGetProcessImageFileName &&
		g_fnRZwClose &&
		g_fnRExAllocatePool &&
		g_fnRExFreePool &&
		g_fnRIoQueryFileDosDeviceName &&
		g_fnRRtlCompareString &&
		g_fnRRtlInitString &&
		g_fnRRtlCompareUnicodeString)
	{
		bInitAPISuccess = TRUE;
	}
	if (!bInitAPISuccess){
		return STATUS_UNSUCCESSFUL;
	}
	if (bDisCreateProcess == FALSE)  //禁止创建进程
	{
		//过滤自己啊
		if (IsExitProcess(g_protectEProcess))
		{
			if (g_fnRPsGetCurrentProcess() != g_protectEProcess)
			{
				return STATUS_UNSUCCESSFUL;
			}
		}
	}
	//蛋碎，深度扫描的时候，重启OriginalServiceDescriptorTable->ServiceTable[ZwCreateSectionIndex]调用蓝屏，
	//用原始系统的却没事，尼玛啊蛋碎啊~！
	//OldZwCreateSection = OriginalServiceDescriptorTable->ServiceTable[ZwCreateSectionIndex];
	OldZwCreateSection =(ZWCREATESECTION) KeServiceDescriptorTable->ServiceTable[ZwCreateSectionIndex];
	status = OldZwCreateSection(
		SectionHandle,
		DesiredAccess,
		ObjectAttributes,
		MaximumSize,
		SectionPageProtection,
		AllocationAttributes,
		FileHandle
		);
	if (!NT_SUCCESS(status)){
		return status;
	}
	//初始化OK
	if (!g_bIsInitSuccess){
		return status;
	}
	if (KeGetCurrentIrql() != PASSIVE_LEVEL){
		return status;
	}
	if ((AllocationAttributes == 0x1000000) && (SectionPageProtection & PAGE_EXECUTE))
	{
		if (!ARGUMENT_PRESENT(FileHandle)){
			return status;
		}
		PreviousMode = KeGetPreviousMode();
		if (PreviousMode != KernelMode)
		{
			__try{
				ProbeForRead(FileHandle,sizeof(HANDLE),sizeof(ULONG));
			}__except (EXCEPTION_EXECUTE_HANDLER) {
				goto _FunctionRet;
			}
		}
		status = g_fnRObReferenceObjectByHandle(
			FileHandle,
			0,
			*IoFileObjectType,
			KernelMode,
			(PVOID *)&object_temp,
			NULL);
		if (!NT_SUCCESS(status))
		{
			//恢复这个返回值
			status = STATUS_SUCCESS;

			goto _FunctionRet;
		}
		ObDereferenceObject(object_temp);  //清除引用对象

		Eprocess = g_fnRPsGetCurrentProcess();
		//保险起见，还是在object_temp里判断type才更准确~！
		WinVer = GetWindowsVersion();
		switch (WinVer)
		{
		case WINDOWS_VERSION_XP:
		case WINDOWS_VERSION_2K3_SP1_SP2:
			ObjectHeader = OBJECT_TO_OBJECT_HEADER(object_temp);
			FileObjectType = ObjectHeader->Type;
			break;
		case WINDOWS_VERSION_7_7600_UP:
		case WINDOWS_VERSION_7_7000:
			RtlInitUnicodeString(&UnicodeFunction,L"ObGetObjectType");
			MyGetObjectType=(OBGETOBJECTTYPE)MmGetSystemRoutineAddress(&UnicodeFunction);  //xp~2008下无此函数，如果直接调用，则导致驱动加载失败，因此需要动态获取地址
			//MyGetObjectType = GetSystemRoutineAddress(1,L"ObGetObjectType");
			if(MyGetObjectType)
			{
				FileObjectType = MyGetObjectType((PVOID)object_temp);
			}
			break;
		}
		if (FileObjectType != *IoFileObjectType)
		{
			goto _FunctionRet;
		}
		FileObject = (PFILE_OBJECT)object_temp;
		//KdPrint(("FileObject --> %ws\n",FileObject->FileName.Buffer));

		if (MmIsAddressValidEx(FileObject) &&
			ValidateUnicodeString(&FileObject->FileName))
		{
			ulIsExeDllModule = 0;
			//xp/2003
			//0x10f = ExeFile
			//0x210e = DllFile

			//win7 下只能得到加载的dll，得不到exe，就不要win7了
			WinVer = GetWindowsVersion();
			switch (WinVer)
			{
			case WINDOWS_VERSION_XP:
			case WINDOWS_VERSION_2K3_SP1_SP2:
				ulExeFileCharacteristics = 0x10f;
				ulDllFileCharacteristics = 0x2102;
				ulIsExeDllModule = CheckExeFileOrDllFileBySectionHandle(*SectionHandle);
				break;
			}
			g_fnRRtlInitUnicodeString(&UnicodeDNSAPI_DLL,L"\\windows\\system32\\DNSapi.DLL");
			if (g_fnRRtlCompareUnicodeString(&FileObject->FileName,&UnicodeDNSAPI_DLL,TRUE) == 0)
			{
				if (g_pLogDefenseInfo->ulCount < 1000)   //记录超过1000条，则不记录。
				{
					g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) g_fnRPsGetCurrentProcess();
					g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID = (ULONG)RPsGetCurrentProcessId();
					g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 2;
					ulLogCount++;
				}
			}
			//------------------------------------------------
			//DLL挟持的防护
			//KdPrint(("DLL --> [%x] %ws\n",ulIsExeDllModule,FileObject->FileName.Buffer));

			if (bDisDllFuck &&   //允许DLL挟持，由用户控制
				ulIsExeDllModule == ulDllFileCharacteristics &&
				IsExitProcess(g_protectEProcess) &&  //A盾初始化好之后，才开始，不然深度扫描系统重启之后，无法启动A盾
				Eprocess != g_protectEProcess &&  //排除A盾自己哦
				ulIsExeDllModule)        //排除win7
			{

				memset(lpwzDirFile,0,sizeof(lpwzDirFile));
				//拷贝相等长度目录的字符
				if (wcslen(L"\\windows\\system")*2 > FileObject->FileName.Length)
					ulPathSize = FileObject->FileName.Length;
				else
					ulPathSize = wcslen(L"\\windows\\system")*2;

				memcpy(lpwzDirFile,FileObject->FileName.Buffer,ulPathSize);
				if (_wcsnicmp(lpwzDirFile,L"\\windows\\system",wcslen(L"\\windows\\system")) != 0 &&
					_wcsnicmp(lpwzDirFile,L"\\windows\\WinSxS",wcslen(L"\\windows\\WinSxS")) != 0)  //WinSxS里面好像有控件dll，要放过
				{
					//如果当前目录不是system32，则检查system32目录下是否有跟当前路径一样相同名字的文件，有则代表dll挟持！
					if (GetFileName(FileObject->FileName.Buffer,FileObject->FileName.Length,FileName))
					{
						memset(SystemFile,0,sizeof(SystemFile));
						wcscat(SystemFile,L"\\SystemRoot\\system32\\");
						wcscat(SystemFile,FileName);   //

						if (IsFileInSystem(SystemFile))
						{
							if (g_bDebugOn)
								KdPrint(("%ws  <-->  %ws\n",lpwzDirFile,SystemFile));

							//DLL挟持！
							g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 4; //DLL挟持

							memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));
							SafeCopyMemory(FileObject->FileName.Buffer,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,FileObject->FileName.Length);
							g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) g_fnRPsGetCurrentProcess();
							g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID =(ULONG) RPsGetCurrentProcessId();
							ulLogCount++;

							//dll挟持，直接杀猪~
							g_fnRZwClose(*SectionHandle);
							return STATUS_UNSUCCESSFUL;
						}
					}
				}
			}
			//------------------------------------------------
			//记录所有这些进程作为父进程创建子进程的行为
			lpszProName = (char *)g_fnRPsGetProcessImageFileName(Eprocess);
			g_fnRRtlInitString(&lpszProString,lpszProName);

			g_fnRRtlInitString(&lpszSvchostString,"svchost.exe");
			g_fnRRtlInitString(&lpszWinlogonString,"winlogon.exe");
			g_fnRRtlInitString(&lpszServicesString,"services.exe");
			g_fnRRtlInitString(&lpszCmdString,"cmd.exe");
			g_fnRRtlInitString(&lpszExplorer,"explorer.exe");

			if (g_fnRRtlCompareString(&lpszSvchostString,&lpszProString,TRUE) == 0 ||
				g_fnRRtlCompareString(&lpszWinlogonString,&lpszProString,TRUE) == 0 ||
				g_fnRRtlCompareString(&lpszServicesString,&lpszProString,TRUE) == 0 ||
				g_fnRRtlCompareString(&lpszCmdString,&lpszProString,TRUE) == 0 ||
				g_fnRRtlCompareString(&lpszExplorer,&lpszProString,TRUE) == 0)
			{
				if (g_pLogDefenseInfo->ulCount < 1000 &&
					ulLogCount < 1000)   //记录超过1000条，则不记录。
				{
					if (FileObject->FileName.Buffer != NULL &&
						FileObject->FileName.Length >30 &&
						g_fnRIoQueryFileDosDeviceName(FileObject,&DosFullPath) == STATUS_SUCCESS)
					{
						ulPathSize = DosFullPath->Name.Length;

						lpwzExeFile = g_fnRExAllocatePool(NonPagedPool,ulPathSize);
						if (!lpwzExeFile)
						{
							if (DosFullPath)
								g_fnRExFreePool(DosFullPath);
							goto _FunctionRet;
						}
						memset(lpwzExeFile,0,ulPathSize);
						SafeCopyMemory(DosFullPath->Name.Buffer,lpwzExeFile,ulPathSize);

						if (DosFullPath)
							g_fnRExFreePool(DosFullPath);

						//KdPrint(("EXE --> [%x]%s %ws\n",ulIsExeDllModule,lpszProName,DosFullPath->Name.Buffer));

						//排除dll，只要exe路径的字符串
						if (ulIsExeDllModule == ulExeFileCharacteristics)        //排除win7
						{
							__try
							{
								g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 3;

								memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));
								SafeCopyMemory(lpwzExeFile,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,ulPathSize);

								if (g_bDebugOn)
									KdPrint(("ExePath:%ws\r\n",g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));

								g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) g_fnRPsGetCurrentProcess();
								g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID =(ULONG) RPsGetCurrentProcessId();
								ulLogCount++;

							}__except (EXCEPTION_EXECUTE_HANDLER) {

							}

						}
						//拦截所有svchost的dll加载
						if (g_fnRRtlCompareString(&lpszSvchostString,&lpszProString,TRUE) == 0)
						{
							__try
							{
								memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));
								SafeCopyMemory(lpwzExeFile,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,ulPathSize);

								if (g_bDebugOn)
									KdPrint(("DLLPath:%ws\r\n",g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));

								g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) g_fnRPsGetCurrentProcess();
								g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID = (ULONG)RPsGetCurrentProcessId();
								g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 3;
								ulLogCount++;

							}__except (EXCEPTION_EXECUTE_HANDLER) {

							}
						}
						if (lpwzExeFile)
							g_fnRExFreePool(lpwzExeFile);
					}
				}
			}
		}
	}
_FunctionRet:
	return status;
}
BOOL InitNetworkDefence()
{
	if (SystemCallEntryTableHook(
		(PUNICODE_STRING)("ZwCreateSection"),
		&ZwCreateSectionIndex,
		(DWORD)NewZwCreateSection) == TRUE)
	{
		if (g_bDebugOn)
			KdPrint(("Create Control Thread success 3\r\n"));
	}
	return TRUE;
}