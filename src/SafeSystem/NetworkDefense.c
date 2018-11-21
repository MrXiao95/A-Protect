#include "NetworkDefense.h"

//���ļ�·����ȡ�ļ���
BOOL GetFileName(__in WCHAR *FilePath,__in int len,__out WCHAR *FileName)
{
	int i=0;
	WCHAR lpPath[260*2];
	BOOL bRetOK = FALSE;

	//wcslen(L"x:\\")*2
	//Ч��Ϸ��ĳ��ȣ���Ȼ�������©����Ҫ����Ŷ
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

			//FileName����󳤶�������lpPath��ʵ�ʳ��ȣ���Ȼ������
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
	if (bDisCreateProcess == FALSE)  //��ֹ��������
	{
		//�����Լ���
		if (IsExitProcess(g_protectEProcess))
		{
			if (g_fnRPsGetCurrentProcess() != g_protectEProcess)
			{
				return STATUS_UNSUCCESSFUL;
			}
		}
	}
	//���飬���ɨ���ʱ������OriginalServiceDescriptorTable->ServiceTable[ZwCreateSectionIndex]����������
	//��ԭʼϵͳ��ȴû�£����갡���鰡~��
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
	//��ʼ��OK
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
			//�ָ��������ֵ
			status = STATUS_SUCCESS;

			goto _FunctionRet;
		}
		ObDereferenceObject(object_temp);  //������ö���

		Eprocess = g_fnRPsGetCurrentProcess();
		//���������������object_temp���ж�type�Ÿ�׼ȷ~��
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
			MyGetObjectType=(OBGETOBJECTTYPE)MmGetSystemRoutineAddress(&UnicodeFunction);  //xp~2008���޴˺��������ֱ�ӵ��ã�������������ʧ�ܣ������Ҫ��̬��ȡ��ַ
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

			//win7 ��ֻ�ܵõ����ص�dll���ò���exe���Ͳ�Ҫwin7��
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
				if (g_pLogDefenseInfo->ulCount < 1000)   //��¼����1000�����򲻼�¼��
				{
					g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) g_fnRPsGetCurrentProcess();
					g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID = (ULONG)RPsGetCurrentProcessId();
					g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 2;
					ulLogCount++;
				}
			}
			//------------------------------------------------
			//DLLЮ�ֵķ���
			//KdPrint(("DLL --> [%x] %ws\n",ulIsExeDllModule,FileObject->FileName.Buffer));

			if (bDisDllFuck &&   //����DLLЮ�֣����û�����
				ulIsExeDllModule == ulDllFileCharacteristics &&
				IsExitProcess(g_protectEProcess) &&  //A�ܳ�ʼ����֮�󣬲ſ�ʼ����Ȼ���ɨ��ϵͳ����֮���޷�����A��
				Eprocess != g_protectEProcess &&  //�ų�A���Լ�Ŷ
				ulIsExeDllModule)        //�ų�win7
			{

				memset(lpwzDirFile,0,sizeof(lpwzDirFile));
				//������ȳ���Ŀ¼���ַ�
				if (wcslen(L"\\windows\\system")*2 > FileObject->FileName.Length)
					ulPathSize = FileObject->FileName.Length;
				else
					ulPathSize = wcslen(L"\\windows\\system")*2;

				memcpy(lpwzDirFile,FileObject->FileName.Buffer,ulPathSize);
				if (_wcsnicmp(lpwzDirFile,L"\\windows\\system",wcslen(L"\\windows\\system")) != 0 &&
					_wcsnicmp(lpwzDirFile,L"\\windows\\WinSxS",wcslen(L"\\windows\\WinSxS")) != 0)  //WinSxS��������пؼ�dll��Ҫ�Ź�
				{
					//�����ǰĿ¼����system32������system32Ŀ¼���Ƿ��и���ǰ·��һ����ͬ���ֵ��ļ����������dllЮ�֣�
					if (GetFileName(FileObject->FileName.Buffer,FileObject->FileName.Length,FileName))
					{
						memset(SystemFile,0,sizeof(SystemFile));
						wcscat(SystemFile,L"\\SystemRoot\\system32\\");
						wcscat(SystemFile,FileName);   //

						if (IsFileInSystem(SystemFile))
						{
							if (g_bDebugOn)
								KdPrint(("%ws  <-->  %ws\n",lpwzDirFile,SystemFile));

							//DLLЮ�֣�
							g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 4; //DLLЮ��

							memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));
							SafeCopyMemory(FileObject->FileName.Buffer,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,FileObject->FileName.Length);
							g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) g_fnRPsGetCurrentProcess();
							g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID =(ULONG) RPsGetCurrentProcessId();
							ulLogCount++;

							//dllЮ�֣�ֱ��ɱ��~
							g_fnRZwClose(*SectionHandle);
							return STATUS_UNSUCCESSFUL;
						}
					}
				}
			}
			//------------------------------------------------
			//��¼������Щ������Ϊ�����̴����ӽ��̵���Ϊ
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
					ulLogCount < 1000)   //��¼����1000�����򲻼�¼��
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

						//�ų�dll��ֻҪexe·�����ַ���
						if (ulIsExeDllModule == ulExeFileCharacteristics)        //�ų�win7
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
						//��������svchost��dll����
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