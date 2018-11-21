#include "Function.h"

VOID WcharToChar(__in WCHAR *wzFuncName,__out CHAR *FuncName)
{
	UNICODE_STRING UnicodeFuncName;
	ANSI_STRING AnsiFuncName;

	RtlInitUnicodeString(&UnicodeFuncName,wzFuncName);
	if (RtlUnicodeStringToAnsiString(&AnsiFuncName,&UnicodeFuncName,TRUE) == STATUS_SUCCESS){
		memcpy(FuncName,AnsiFuncName.Buffer,AnsiFuncName.Length);
		RtlFreeAnsiString(&AnsiFuncName);
	}
}
ULONG PsGetProcessCount()
{ 
	NTSTATUS	 status;
	ULONG		 uCount = 0;
	PLIST_ENTRY	 pListActiveProcess;
	PEPROCESS	 pCurrentEprocess = NULL;
	ULONG        ulNextProcess = 0;
	ULONG        g_Offset_Eprocess_Flink;
	WIN_VER_DETAIL WinVer;

	WinVer = GetWindowsVersion();
	switch(WinVer)
	{
	case WINDOWS_VERSION_XP:
		g_Offset_Eprocess_Flink = 0x88;
		break;
	case WINDOWS_VERSION_7_7600_UP:
	case WINDOWS_VERSION_7_7000:
		g_Offset_Eprocess_Flink = 0xb8;
		break;
	case WINDOWS_VERSION_VISTA_2008:
		g_Offset_Eprocess_Flink = 0x0a0;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		g_Offset_Eprocess_Flink = 0x98;
		break;
	case WINDOWS_VERSION_2K3:
		g_Offset_Eprocess_Flink = 0x088;
		break;
	}
	if (!g_Offset_Eprocess_Flink){
		return 0;
	}
	pCurrentEprocess = PsGetCurrentProcess();
	ulNextProcess = (ULONG)pCurrentEprocess;
	__try
	{
		while(1)
		{
			pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
			(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink;
			(ULONG)pCurrentEprocess = (ULONG)pCurrentEprocess - g_Offset_Eprocess_Flink;
			uCount++;

			if (ulNextProcess ==(ULONG) pCurrentEprocess){
				__leave;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
		return uCount;
	}
	return uCount;
}
//�������ִ����reload֮ǰ�����Ҫʹ��ԭʼ����
BOOL KeBugCheckCreateValueKey(PWCHAR SafeKey)
{
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING RegUnicodeString,Unicode_ValueName;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	ULONG ulValue_DWORD;
	ULONG ulResult=0;
	BOOL bRetOK = FALSE;

	RtlInitUnicodeString(&RegUnicodeString,SafeKey);
	//��ʼ��objectAttributes
	InitializeObjectAttributes(
		&objectAttributes,
		&RegUnicodeString,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,//�Դ�Сд���� 
		NULL, 
		NULL 
		);
	//���������ע�����Ŀ
	ntStatus = ZwCreateKey(
		&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		&ulResult
		);
	if (NT_SUCCESS(ntStatus))
	{
		bRetOK = TRUE;
		ZwFlushKey(hRegister);
		ZwClose(hRegister);
	}
	return bRetOK;
}
//�������ִ����reload֮ǰ�����Ҫʹ��ԭʼ����
BOOL IsRegKeyInSystem(PWCHAR ServicesKey)
{
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING RegUnicodeString;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	BOOL bRetOK = FALSE;

	RtlInitUnicodeString(&RegUnicodeString,ServicesKey);
	InitializeObjectAttributes(
		&objectAttributes,
		&RegUnicodeString,
		OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,//�Դ�Сд���� 
		NULL, 
		NULL 
		);
	ntStatus = ZwOpenKey(&hRegister,
		KEY_QUERY_VALUE,
		&objectAttributes
		);
	if (NT_SUCCESS(ntStatus))
	{
		bRetOK = TRUE;
		ZwClose(hRegister);
	}
	return bRetOK;
}
BOOL IsFileInSystem(WCHAR *lpwzFile)
{
	HANDLE hFile = NULL;
	NTSTATUS status;
	IO_STATUS_BLOCK Io_Status_Block;
	OBJECT_ATTRIBUTES obj_attrib;
	UNICODE_STRING UnicodeFileName;
	BOOL bIsFile = FALSE;

	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoCreateFile),L"IoCreateFile",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRRtlInitUnicodeString &&
		g_fnRIoCreateFile &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return bIsFile;

	g_fnRRtlInitUnicodeString(&UnicodeFileName,lpwzFile);
	InitializeObjectAttributes(
		&obj_attrib,
		&UnicodeFileName,
		OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
		NULL, 
		NULL
		);
	status = g_fnRIoCreateFile(
		&hFile,
		GENERIC_READ,  //��ֻ���ķ�ʽ�򿪣���Ȼ����ʾ����32
		&obj_attrib,
		&Io_Status_Block,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,
		NULL,
		0,
		0,
		NULL,
		IO_NO_PARAMETER_CHECKING);
	if (NT_SUCCESS(status))
	{
		//�ļ���ɾ����
		//KdPrint(("file been deleted"));

		g_fnRZwClose(hFile);
		bIsFile = TRUE;
	}
	return bIsFile;
}
NTSTATUS SafeQueryFileDosDeviceName(__in WCHAR *wzNtImageName,__out WCHAR *wzDosFullPath)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES	ObjectAttributes; 
	struct _IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle=NULL;
	PFILE_OBJECT FileObject;
	POBJECT_NAME_INFORMATION DosFullPath=NULL;
	UNICODE_STRING NtImageName;

	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwOpenFile),L"ZwOpenFile",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByHandle),L"ObReferenceObjectByHandle",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoQueryFileDosDeviceName),L"IoQueryFileDosDeviceName",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRZwOpenFile &&
		g_fnRObReferenceObjectByHandle &&
		g_fnRIoQueryFileDosDeviceName &&
		g_fnRZwClose &&
		g_fnRExFreePool &&
		g_fnRRtlInitUnicodeString)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return STATUS_UNSUCCESSFUL;

	g_fnRRtlInitUnicodeString(&NtImageName,wzNtImageName);
	InitializeObjectAttributes( 
		&ObjectAttributes,
		&NtImageName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);
	Status = g_fnRZwOpenFile(
		&FileHandle,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_READ,
		FILE_SYNCHRONOUS_IO_NONALERT
		);
	if (!NT_SUCCESS(Status))
	{
		//DbgPrint("ZwOpenFile[%ws] failed:%d\r\n",NtImageName.Buffer,RtlNtStatusToDosError(Status));
		return Status;
	}
	Status = g_fnRObReferenceObjectByHandle(
		FileHandle,
		PROCESS_ALL_ACCESS,
		*IoFileObjectType,
		KernelMode,
		(PVOID *)&FileObject,
		NULL);
	if (NT_SUCCESS(Status))
	{
		if (g_fnRIoQueryFileDosDeviceName(FileObject,&DosFullPath) == STATUS_SUCCESS)
		{
			Status = STATUS_UNSUCCESSFUL;
			Status = SafeCopyMemory(DosFullPath->Name.Buffer,wzDosFullPath,DosFullPath->Name.Length);
			g_fnRExFreePool(DosFullPath);
		}
		ObDereferenceObject(FileObject);
	}
	g_fnRZwClose(FileHandle);
	return Status;
}
NTSTATUS SafeQueryNameString(
	IN PVOID FileObject,
	OUT POBJECT_NAME_INFORMATION *FileNameInfo
	)
{
	ULONG NumberOfBytes;
	ULONG AdditionalLengthNeeded;
	NTSTATUS Status;
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRExAllocatePoolWithTag),L"ExAllocatePoolWithTag",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRObQueryNameString),L"ObQueryNameString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRExAllocatePoolWithTag &&
		g_fnRExFreePool &&
		g_fnRObQueryNameString)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return STATUS_UNSUCCESSFUL;

	NumberOfBytes = 1024;

	*FileNameInfo = NULL;

	*FileNameInfo = g_fnRExAllocatePoolWithTag (NonPagedPool, NumberOfBytes, ' mM');

	if (*FileNameInfo == NULL) {
		return STATUS_NO_MEMORY;
	}

	Status = g_fnRObQueryNameString (FileObject,
		*FileNameInfo,
		NumberOfBytes,
		&AdditionalLengthNeeded);

	if (!NT_SUCCESS (Status)) {

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			//
			// Our buffer was not large enough, retry just once with a larger
			// one (as specified by ObQuery). Don't try more than once to
			// prevent broken parse procedures which give back wrong
			// AdditionalLengthNeeded values from causing problems.
			//

			g_fnRExFreePool (*FileNameInfo);

			NumberOfBytes += AdditionalLengthNeeded;

			*FileNameInfo = g_fnRExAllocatePoolWithTag (NonPagedPool,
				NumberOfBytes,
				' mM');

			if (*FileNameInfo == NULL) {
				return STATUS_NO_MEMORY;
			}

			Status = g_fnRObQueryNameString (FileObject,
				*FileNameInfo,
				NumberOfBytes,
				&AdditionalLengthNeeded);

			if (NT_SUCCESS (Status)) {
				return STATUS_SUCCESS;
			}
		}

		g_fnRExFreePool (*FileNameInfo);
		*FileNameInfo = NULL;
		return Status;
	}

	return STATUS_SUCCESS;
}
BOOL GetDriverEntryPoint(PVOID ImageBase,DWORD *pOutDriverEntry)
{
	BOOL bRet=FALSE;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG_PTR EntryPoint;

	NtHeaders = RtlImageNtHeader(ImageBase);
	if (NtHeaders)
	{
		DWORD dwEntryPoint;
		DWORD dwCurAddress;
		DWORD Length=0;
		PUCHAR pOpcode;
		EntryPoint = NtHeaders->OptionalHeader.AddressOfEntryPoint;
		EntryPoint += (ULONG_PTR)ImageBase;
		dwEntryPoint=(DWORD)EntryPoint;
		for(dwCurAddress = dwEntryPoint; dwCurAddress < dwEntryPoint + 0x1000; dwCurAddress+=Length)
		{
			Length = SizeOfCode((PUCHAR)dwCurAddress, &pOpcode);
			if(Length==2&&*(WORD *)dwCurAddress==0xFF8B)
			{  
				//KdPrint(("find:%08x",dwCurAddress));
				*pOutDriverEntry = dwCurAddress;
				bRet = TRUE;
				break;
			}
			//mouclass.sys ��ͷ������
			/*
			INIT:00017811 DriverEntry     proc near
			INIT:00017811                 mov     eax, dword_14028
			INIT:00017816                 test    eax, eax
			INIT:00017818                 mov     ecx, 0BB40E64Eh
			INIT:0001781D                 jz      short loc_17823
			INIT:0001781F                 cmp     eax, ecx
			INIT:00017821                 jnz     short loc_1783C
			INIT:00017823
			INIT:00017823 loc_17823:                              ; CODE XREF: DriverEntry+Cj
			INIT:00017823                 mov     eax, ds:KeTickCount
			INIT:00017828                 mov     eax, [eax]            <------������ 0x008B
			INIT:0001782A                 xor     eax, offset dword_14028
			INIT:0001782F                 mov     dword_14028, eax
			INIT:00017834                 jnz     short loc_1783C
			INIT:00017836                 mov     dword_14028, ecx
			INIT:0001783C
			INIT:0001783C loc_1783C:                              ; CODE XREF: DriverEntry+10j
			INIT:0001783C                                         ; DriverEntry+23j
			INIT:0001783C                 jmp     sub_172CE
			INIT:0001783C DriverEntry     endp
			*/
			else if (Length==2&&*(WORD *)dwCurAddress==0x008B)
			{
				*pOutDriverEntry = dwCurAddress;
				bRet = TRUE;
				break;
			}
		}
	}
	return bRet;
}
NTSTATUS GetDriverObject(WCHAR *lpwzDevice,PDRIVER_OBJECT *PDriverObject)
{
	PDRIVER_OBJECT DriverObject;
	UNICODE_STRING ObjectName;
	NTSTATUS Status;
	BOOL bInit = FALSE;


	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByName),L"ObReferenceObjectByName",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRRtlInitUnicodeString &&
		g_fnRObReferenceObjectByName)
	{
		bInit = TRUE;
	}
	if (!bInit)
	{
		//KdPrint(("ReLoadNtosCALL failed:%x %x",RRtlInitUnicodeString,RObReferenceObjectByName));
		return STATUS_UNSUCCESSFUL;
	}

	g_fnRRtlInitUnicodeString(&ObjectName,lpwzDevice);
	Status = g_fnRObReferenceObjectByName(&ObjectName, 
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&DriverObject);
	if (NT_SUCCESS(Status))
	{
		*PDriverObject = DriverObject;
	}else
		KdPrint(("ObReferenceObjectByName failed:%d",RtlNtStatusToDosError(Status)));

	return Status;
}
PVOID LookupKernelModuleByName(PDRIVER_OBJECT DriverObject,char *KernelModuleName,DWORD *ulWin32kSize)
{
	PLDR_DATA_TABLE_ENTRY DriverSection,LdrEntry;
	ANSI_STRING AnsiKernelModuleName;
	UNICODE_STRING UniKernelModuleName;
	UNICODE_STRING ModuleName;
	WCHAR *Buffer;
	int Lentgh,Index;

	__try
	{
		RtlInitAnsiString(&AnsiKernelModuleName,KernelModuleName);
		RtlAnsiStringToUnicodeString(&UniKernelModuleName,&AnsiKernelModuleName,TRUE);
		Buffer=ExAllocatePool(NonPagedPool,260*2);
		if (Buffer==NULL)
		{
			RtlFreeUnicodeString(&UniKernelModuleName);
			return NULL;
		}
		RtlZeroMemory(Buffer,206*2);
		DriverSection=DriverObject->DriverSection;
		LdrEntry=(PLDR_DATA_TABLE_ENTRY)DriverSection->InLoadOrderLinks.Flink;
		while (LdrEntry&&DriverSection!=LdrEntry)
		{

			if ((DWORD)LdrEntry->DllBase>=*(DWORD*)MmSystemRangeStart&&
				LdrEntry->FullDllName.Length>0&&
				LdrEntry->FullDllName.Buffer!=NULL)
			{

				if (MmIsAddressValidEx(&LdrEntry->FullDllName.Buffer[LdrEntry->FullDllName.Length/2-1]))
				{
					Lentgh=LdrEntry->FullDllName.Length/2;
					for (Index=Lentgh-1;Index>0;Index--)
					{
						if (LdrEntry->FullDllName.Buffer[Index]==0x005C)
						{
							break;
						}
					}
					if (LdrEntry->FullDllName.Buffer[Index]==0x005C)
					{
						RtlCopyMemory(Buffer,&(LdrEntry->FullDllName.Buffer[Index+1]),(Lentgh-Index-1)*2);
						ModuleName.Buffer=Buffer;
						ModuleName.Length=(Lentgh-Index-1)*2;
						ModuleName.MaximumLength=260*2;
					}
					else
					{
						RtlCopyMemory(Buffer,LdrEntry->FullDllName.Buffer,Lentgh*2);
						ModuleName.Buffer=Buffer;
						ModuleName.Length=Lentgh*2;
						ModuleName.MaximumLength=260*2;

					}
					//KdPrint(("L:%wZ--%wZ\n",&ModuleName,&UniKernelModuleName));

					if (RtlEqualUnicodeString(&ModuleName,&UniKernelModuleName,TRUE))
					{
						ExFreePool(Buffer);
						RtlFreeUnicodeString(&UniKernelModuleName);

						//KdPrint(("find:%wZ--%X\n",&LdrEntry->FullDllName,LdrEntry->DllBase));
						*ulWin32kSize = LdrEntry->SizeOfImage;
						return LdrEntry->DllBase;
					}

				}

			}	
			LdrEntry=(PLDR_DATA_TABLE_ENTRY)LdrEntry->InLoadOrderLinks.Flink;
		}
		RtlFreeUnicodeString(&UniKernelModuleName);
		ExFreePool(Buffer);

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	return NULL;
}
DWORD CsGetFileSize(HANDLE FileHandle,PDWORD HightLength)
{
	FILE_STANDARD_INFORMATION FileStandardInfo;
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatus;
	Status=ZwQueryInformationFile(FileHandle,
		&IoStatus,
		&FileStandardInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation
		);
	if (!NT_SUCCESS(Status))
	{
		return -1;
	}
	if (HightLength)
	{
		__try
		{
			*HightLength=FileStandardInfo.EndOfFile.HighPart;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint(("CsGetFileSize:%08x\r\n",GetExceptionCode()));
			return -1;
		}
	}
	return FileStandardInfo.EndOfFile.LowPart;
}
BOOL CsSetFilePointer(HANDLE FileHandle,
	PLARGE_INTEGER ByteOffset)
{
	FILE_STANDARD_INFORMATION FileStandardInfo;
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatus;
	FILE_POSITION_INFORMATION FilePositionInfo;
	BOOL bRetOK = FALSE;

	FilePositionInfo.CurrentByteOffset.QuadPart=ByteOffset->QuadPart;
	Status=ZwSetInformationFile(
		FileHandle,
		&IoStatus,
		&FilePositionInfo,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation
		);
	if (NT_SUCCESS(Status))
	{
		bRetOK = TRUE;
	}
	return bRetOK;
}
ULONG  DebugWriteToFile(WCHAR *FileName,PVOID buffer,ULONG ulSize)
{
	HANDLE hFile = NULL;
	NTSTATUS status;
	IO_STATUS_BLOCK Io_Status_Block;
	UNICODE_STRING lpwFileName;
	ULONG ulHighPart;
	ULONG ulLowPart;

	LARGE_INTEGER ByteOffset;

	// ��ʼ���ļ�·��
	OBJECT_ATTRIBUTES obj_attrib;

	RtlInitUnicodeString(&lpwFileName,FileName);
	InitializeObjectAttributes(
		&obj_attrib,
		&lpwFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL, 
		NULL
		);
	status = IoCreateFile(
		&hFile,
		GENERIC_WRITE,
		&obj_attrib,
		&Io_Status_Block,
		0,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN_IF,
		0,
		NULL,
		0,
		0,
		NULL,
		IO_NO_PARAMETER_CHECKING
		);
	if (NT_SUCCESS(status))
	{
		ulLowPart = CsGetFileSize(hFile,&ulHighPart);
		if (ulLowPart != -1)
		{
			//KdPrint(("FileSize:%d\r\nWriteBuffer:%d",ulLowPart,ulSize));

			ByteOffset.QuadPart = ulLowPart;

			if (CsSetFilePointer(hFile,&ByteOffset) == TRUE)
			{
				status = ZwWriteFile(
					hFile,
					NULL,
					NULL,
					NULL,
					&Io_Status_Block,
					buffer,
					ulSize,
					&ByteOffset,
					NULL
					);
			}
		}
		// �رվ��
		if (hFile)
		{
			ZwClose(hFile);
		}
	}else
		KdPrint(("NtCreateFile failed:%d\r\n",RtlNtStatusToDosError(status)));

	return RtlNtStatusToDosError(status);
}
/*
BOOL GetProcessImagePath(    
	IN  ULONG   ulPid,    
	OUT WCHAR *FullProcessImagePath    
	)    
{    
	NTSTATUS Status;    
	HANDLE hProcess;    
	PEPROCESS EProcess;    
	ULONG returnedLength;    
	ULONG bufferLength;    
	PVOID buffer;    
	PUNICODE_STRING ImageName;
	BOOL bInit = FALSE;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID ClientId={0};

	//ReLoadNtosCALL(&RObOpenObjectByPointer,L"ObOpenObjectByPointer",SystemKernelModuleBase,ImageModuleBase);
	ReLoadNtosCALL(&RZwOpenProcess,L"ZwOpenProcess",SystemKernelModuleBase,ImageModuleBase);
	RZwQueryInformationProcess = ReLoadNtosCALL(L"ZwQueryInformationProcess",SystemKernelModuleBase,ImageModuleBase);
	ReLoadNtosCALL(&RExAllocatePool,L"ExAllocatePool",SystemKernelModuleBase,ImageModuleBase);
	ReLoadNtosCALL(&RExFreePool,L"ExFreePool",SystemKernelModuleBase,ImageModuleBase);
	ReLoadNtosCALL(&RZwClose,L"ZwClose",SystemKernelModuleBase,ImageModuleBase);
	if (RZwOpenProcess &&
		RZwQueryInformationProcess &&
		RExAllocatePool &&
		RExFreePool &&
		RZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return NULL;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process     

	ClientId.UniqueProcess = ulPid;
	InitializeObjectAttributes(
		&ObjectAttributes, 
		NULL,
		0, 
		NULL,
		NULL 
		);
	Status=RZwOpenProcess(
		&hProcess,
		PROCESS_ALL_ACCESS,
		&ObjectAttributes,
		&ClientId
		);
	if (!NT_SUCCESS(Status))
	{
		return NULL;
	}
// 	Status = RObOpenObjectByPointer(
// 		EProcess,          // Object    
// 		OBJ_KERNEL_HANDLE,  // HandleAttributes    
// 		NULL,               // PassedAccessState OPTIONAL    
// 		GENERIC_READ,       // DesiredAccess    
// 		*PsProcessType,     // ObjectType    
// 		KernelMode,         // AccessMode    
// 		&hProcess
// 		);    
// 	if (!NT_SUCCESS(Status))
// 	{
// 		if (DebugOn)
// 			KdPrint(("ObOpenObjectByPointer Error\r\n"));
// 		return FALSE;  
// 	}
	Status = RZwQueryInformationProcess(
		hProcess,    
		ProcessImageFileName,    
		NULL, // buffer    
		0, // buffer size    
		&returnedLength);
	if (STATUS_INFO_LENGTH_MISMATCH != Status)
	{    
		RZwClose(hProcess);

		if (DebugOn)
			KdPrint(("ZwQueryInformationProcess Error\r\n"));
		return FALSE;    
	}

	buffer = RExAllocatePool(PagedPool, returnedLength);    
	if (buffer)
	{
		memset(buffer,0,returnedLength);
		Status = RZwQueryInformationProcess( 
			hProcess,    
			ProcessImageFileName,    
			buffer,    
			returnedLength,    
			&returnedLength
			);    
		if (NT_SUCCESS(Status))
		{        
			ImageName = (PUNICODE_STRING)buffer;
			if (ValidateUnicodeString(ImageName))
			{
				SafeCopyMemory(
					ImageName->Buffer,
					FullProcessImagePath,
					ImageName->Length
					);
			}   
		}    
		if (buffer)
			RExFreePool(buffer); 
	}
	RZwClose(hProcess);
	return TRUE;    
}*/

PVOID GetZwQueryVirtualMemoryAddress()
{
	PVOID FunctionAddress=0;
	ULONG ulSearchStart;
	int Index;
	PUCHAR i=0;
	
/*
lkd> u ZwQueryVirtualMemory
nt!ZwQueryVirtualMemory:
804ffb90 b8b2000000      mov     eax,0B2h
804ffb95 8d542404        lea     edx,[esp+4]
804ffb99 9c              pushfd
804ffb9a 6a08            push    8
804ffb9c e8f0e80300      call    nt!KiSystemService (8053e491)
804ffba1 c21800          ret     18h
nt!ZwQueryVolumeInformationFile:                 <------------------������һֱ���ϼ�����Indexһ����ʱ�򣬾��ǵ�ַ�ˡ�
804ffba4 b8b3000000      mov     eax,0B3h
804ffba9 8d542404        lea     edx,[esp+4]
*/
	GetFunctionIndexByName("ZwQueryVirtualMemory",&Index);
	if (Index){
		ulSearchStart = (ULONG)ZwQueryVolumeInformationFile;
		for (i=(PUCHAR)ulSearchStart;i > (PUCHAR)ulSearchStart - 0x50;i--)
		{
			if (MmIsAddressValidEx(i))
			{
				if (*i == Index){
					FunctionAddress = i - 1;

					if (g_bDebugOn)
						KdPrint(("FunctionAddress:%08x\n",FunctionAddress));
					break;
				}
			}
		}
	}
	return FunctionAddress;
}
BOOL GetProcessFullImagePath(    
	IN  PEPROCESS Eprocess, 
	OUT WCHAR *FullProcessImagePath
	)    
{
	ULONG dwStartAddr = 0x00000000;
	HANDLE hProcess;
	MEMORY_BASIC_INFORMATION mbi;
	PUNICODE_STRING SectionName = NULL;
	NTSTATUS status;
	int count = 0;
	ULONG SectionBaseAddressOffset = 0;
	ULONG SectionBaseAddress = 0;

	ULONG ulPid = 0;
	BOOL bInit = FALSE;

	if (!ARGUMENT_PRESENT(Eprocess) ||
		!Eprocess){
			return FALSE;
	}
	if (Eprocess == g_systemEProcess)
	{
		memcpy(FullProcessImagePath,L"System",wcslen(L"System")*2);
		return TRUE;
	}
	WinVer = GetWindowsVersion();
	switch(WinVer)
	{
	case WINDOWS_VERSION_XP:
		SectionBaseAddressOffset = 0x13c;
		if (!MmIsAddressValidEx(g_fnRZwQueryVirtualMemory)){
			g_fnRZwQueryVirtualMemory = GetZwQueryVirtualMemoryAddress();
		}
		break;
	case WINDOWS_VERSION_7_7600_UP:
	case WINDOWS_VERSION_7_7000:
		SectionBaseAddressOffset = 0x12c;
		ReLoadNtosCALL((PVOID)(&g_fnRZwQueryVirtualMemory),L"ZwQueryVirtualMemory",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase); //win7�����ˣ�����ֱ����
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		SectionBaseAddressOffset = 0x128;
		if (!MmIsAddressValidEx(g_fnRZwQueryVirtualMemory)){
			g_fnRZwQueryVirtualMemory = GetZwQueryVirtualMemoryAddress();
		}
		break;
	}
	if (!SectionBaseAddressOffset){
		return bInit;
	}
	ReLoadNtosCALL((PVOID)(&g_fnRObOpenObjectByPointer),L"ObOpenObjectByPointer",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExAllocatePool),L"ExAllocatePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRObOpenObjectByPointer &&
		g_fnRZwQueryVirtualMemory &&
		g_fnRExAllocatePool &&
		g_fnRExFreePool &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit){
		//KdPrint(("function failed %08x %08x %08x %08x %08x\n",RObOpenObjectByPointer,RZwQueryVirtualMemory,RExAllocatePool,RExFreePool,RZwClose));
		return FALSE;
	}
	bInit = FALSE;

	SectionBaseAddress = *((PULONG)((ULONG)Eprocess + SectionBaseAddressOffset));

// 	ClientId.UniqueProcess = ulPid;
// 	InitializeObjectAttributes(
// 		&ObjectAttributes,
// 		NULL,
// 		0,
// 		NULL, 
// 		NULL 
// 		);
// 	status=RZwOpenProcess(
// 		&hProcess,
// 		PROCESS_ALL_ACCESS,
// 		&ObjectAttributes,
// 		&ClientId
// 		);

	status = g_fnRObOpenObjectByPointer(
		Eprocess,          // Object    
		OBJ_KERNEL_HANDLE,  // HandleAttributes    
		NULL,               // PassedAccessState OPTIONAL    
		GENERIC_READ,       // DesiredAccess    
		*PsProcessType,     // ObjectType    
		KernelMode,         // AccessMode    
		&hProcess
		);    
	if (!NT_SUCCESS(status))
	{
		//KdPrint(("ObOpenObjectByPointer failed:%d",RtlNtStatusToDosError(status)));
		return FALSE;
	}
	SectionName = (PUNICODE_STRING)g_fnRExAllocatePool(NonPagedPool,260*sizeof(WCHAR));
	if (!SectionName)
	{
		g_fnRZwClose(hProcess);
		//KdPrint(("RExAllocatePool failed\n"));
		return FALSE;
	}
	memset(SectionName,0,260*sizeof(WCHAR));

	__try
	{
		for (dwStartAddr=0; dwStartAddr<0x80000000; dwStartAddr=dwStartAddr+0x10000)
		{
			status = g_fnRZwQueryVirtualMemory(
				hProcess,
				(PVOID)dwStartAddr,
				MemoryBasicInformation,
				&mbi,
				sizeof(MEMORY_BASIC_INFORMATION),
				0
				);
			if (NT_SUCCESS(status))
			{
				if(mbi.Type == MEM_IMAGE &&
				   mbi.BaseAddress ==(PVOID) SectionBaseAddress) //���˵����ʱ��VirtualMemory��exe���ռ䣬����dll
				{
					status = g_fnRZwQueryVirtualMemory(
						hProcess,
						(PVOID)dwStartAddr,
						MemorySectionName,
						SectionName,
						260*sizeof(WCHAR),
						0
						);
					if (NT_SUCCESS(status))
					{
						if (g_bDebugOn)
							KdPrint(("SectionName:%08x %ws \n",mbi.BaseAddress,SectionName->Buffer));

						if (ValidateUnicodeString(SectionName))
						{
							SafeCopyMemory(
								SectionName->Buffer,
								FullProcessImagePath,
								SectionName->Length
								);
							bInit = TRUE;
							break;
						}
					}
				}
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){
		//KdPrint(("EXCEPTION_EXECUTE_HANDLER failed\n"));
		goto _FunctionRet;
	}
_FunctionRet:
	{
		g_fnRExFreePool(SectionName);
		g_fnRZwClose(hProcess);
		return bInit;
	}
	return bInit;
}
NTSTATUS LookupProcessByPid(
	IN HANDLE hProcessPid,
	OUT PEPROCESS *pEprocess
	)
{ 
	NTSTATUS	status;
	ULONG		uCurrentProcessId = 0;
	ULONG		uStartProcessId = 0; 
	ULONG		uCount = 0;
	ULONG		uLength = 0;
	PLIST_ENTRY	pListActiveProcess;
	PEPROCESS	pCurrentEprocess = NULL;
	ULONG g_Offset_Eprocess_ProcessId;
	ULONG g_Offset_Eprocess_Flink;
	WIN_VER_DETAIL WinVer;

	if (!ARGUMENT_PRESENT(hProcessPid))
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	WinVer = GetWindowsVersion();
	switch(WinVer)
	{
	case WINDOWS_VERSION_XP:
		g_Offset_Eprocess_ProcessId = 0x84;
		g_Offset_Eprocess_Flink = 0x88;
		break;
	case WINDOWS_VERSION_7_7600_UP:
	case WINDOWS_VERSION_7_7000:
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
		!g_Offset_Eprocess_Flink){
			return STATUS_UNSUCCESSFUL;
	}
	pCurrentEprocess = PsGetCurrentProcess();
	uStartProcessId = *((PULONG)((ULONG)pCurrentEprocess + g_Offset_Eprocess_ProcessId));
	uCurrentProcessId = uStartProcessId;

	__try
	{
		while(1)
		{
			if (hProcessPid == (HANDLE)(*((PULONG)((ULONG)pCurrentEprocess + g_Offset_Eprocess_ProcessId))))
			{
				*pEprocess = pCurrentEprocess;
				status = STATUS_SUCCESS;
				break;
			}
			if ((uCount >= 1) && (uStartProcessId == uCurrentProcessId))
			{
				*pEprocess = 0x00000000;
				status = STATUS_NOT_FOUND;
				break;
			}
			pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
			(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink;
			(ULONG)pCurrentEprocess = (ULONG)pCurrentEprocess - g_Offset_Eprocess_Flink;
			uCurrentProcessId = *(PULONG)((ULONG)pCurrentEprocess + g_Offset_Eprocess_ProcessId);
			uCount++;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("LookupProcessByPid:%08x\r\n",GetExceptionCode()));
		status = STATUS_NOT_FOUND;
	}
	return status;
}
///////////////////////////////////////////////////////////////////////////////////
//
//  ����ʵ�֣������豸����ȡ�ļ�������ļ�����ָ��
//  ���������FileHandle��Ҫ������ļ����ָ��;
//        FileObject��Ҫ������ļ�����ָ��
//        DeviceName��Ҫ��ȡ�豸���豸��
//  �������������NTSTATUS���͵�ֵ
//
///////////////////////////////////////////////////////////////////////////////////

NTSTATUS GetObjectByName(
	OUT PHANDLE FileHandle,
	OUT PFILE_OBJECT  *FileObject,
	IN WCHAR  *DeviceName
	)
{
	UNICODE_STRING    deviceTCPUnicodeString;
	OBJECT_ATTRIBUTES  TCP_object_attr;
	NTSTATUS      status;
	IO_STATUS_BLOCK    IoStatus;
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwCreateFile),L"ZwCreateFile",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByHandle),L"ObReferenceObjectByHandle",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRRtlInitUnicodeString &&
		g_fnRZwCreateFile &&
		g_fnRObReferenceObjectByHandle
		)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return STATUS_UNSUCCESSFUL;

	g_fnRRtlInitUnicodeString(&deviceTCPUnicodeString,DeviceName);
	InitializeObjectAttributes(&TCP_object_attr,
		&deviceTCPUnicodeString,
		OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
		0,
		0
		);
	status=g_fnRZwCreateFile(
		FileHandle,
		GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
		&TCP_object_attr,
		&IoStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,
		0,
		0
		);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("Failed to open"));
		return STATUS_UNSUCCESSFUL;
	}
	status=g_fnRObReferenceObjectByHandle(
		*FileHandle,
		FILE_ANY_ACCESS,
		*IoFileObjectType,
		KernelMode,
		(PVOID*)FileObject,
		NULL
		);
	return status;
}
HANDLE MapFileAsSection(PUNICODE_STRING FileName,PVOID *ModuleBase)
{
	NTSTATUS status;
	HANDLE  hSection, hFile;
	DWORD dwKSDT;
	PVOID BaseAddress = NULL;
	SIZE_T size=0;
	IO_STATUS_BLOCK iosb;
	OBJECT_ATTRIBUTES oa = {sizeof oa, 0, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE};
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRZwOpenFile),L"ZwOpenFile",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwCreateSection),L"ZwCreateSection",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwMapViewOfSection),L"ZwMapViewOfSection",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRZwOpenFile &&
		g_fnRZwCreateSection &&
		g_fnRZwMapViewOfSection &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return NULL;

	*ModuleBase=NULL;

	status=g_fnRZwOpenFile(
		&hFile, 
		FILE_EXECUTE | SYNCHRONIZE, 
		&oa, 
		&iosb, 
		FILE_SHARE_READ, 
		FILE_SYNCHRONOUS_IO_NONALERT);

	if(!NT_SUCCESS(status))
	{
		if (g_bDebugOn)
			KdPrint(("ZwOpenFile failed\n"));
		return NULL;
	}
	oa.ObjectName = 0;

	status=g_fnRZwCreateSection(
		&hSection, 
		SECTION_ALL_ACCESS, 
		&oa, 
		0,
		PAGE_EXECUTE, 
		SEC_IMAGE, 
		hFile);
	if(!NT_SUCCESS(status))
	{
		g_fnRZwClose(hFile);
		KdPrint(("ZwCreateSection failed:%d\n",RtlNtStatusToDosError(status)));
		return NULL;
	}

	status=g_fnRZwMapViewOfSection(
		hSection, 
		NtCurrentProcess(),
		&BaseAddress, 
		0,
		1000, 
		0,
		&size,
		(SECTION_INHERIT)1,
		MEM_TOP_DOWN, 
		PAGE_READWRITE); 
	if(!NT_SUCCESS(status))
	{
		g_fnRZwClose(hFile);
		g_fnRZwClose(hSection);

		if (g_bDebugOn)
			KdPrint(("ZwMapViewOfSection failed %d\n",RtlNtStatusToDosError(status)));
		return NULL;
	}
	g_fnRZwClose(hFile);
	__try
	{
		*ModuleBase=BaseAddress;
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
		return NULL;
	}
	return hSection;
}
BOOL GetFunctionNameByIndex(ULONG ulModuleBase,int *Index,CHAR *lpszFunctionName)
{
	UNICODE_STRING wsNtDllString;

	HANDLE hNtSection;
	ULONG ulNtDllModuleBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS NtDllHeader;

	IMAGE_OPTIONAL_HEADER opthdr;
	DWORD* arrayOfFunctionAddresses;
	DWORD* arrayOfFunctionNames;
	WORD* arrayOfFunctionOrdinals;
	DWORD functionOrdinal;
	DWORD Base, x, functionAddress,position;
	char* functionName;
	IMAGE_EXPORT_DIRECTORY *pExportTable;
	BOOL bRetOK = FALSE;
	BOOL bInit = FALSE;

	__try
	{
		//NtDllHeader=(PIMAGE_NT_HEADERS)GetPeHead((ULONG)ulNtDllModuleBase);
		ulNtDllModuleBase = (ULONG)ulModuleBase;
		pDosHeader=(PIMAGE_DOS_HEADER)ulNtDllModuleBase;
		if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
		{
			if (g_bDebugOn)
				KdPrint(("failed to find NtHeader\r\n"));
			return bRetOK;
		}
		NtDllHeader=(PIMAGE_NT_HEADERS)(ULONG)((ULONG)pDosHeader+pDosHeader->e_lfanew);
		if (NtDllHeader->Signature!=IMAGE_NT_SIGNATURE)
		{
			if (g_bDebugOn)
				KdPrint(("failed to find NtHeader\r\n"));
			return bRetOK;
		}
		opthdr = NtDllHeader->OptionalHeader;
		pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*)ulNtDllModuleBase + opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress); //�õ�������
		arrayOfFunctionAddresses = (DWORD*)( (BYTE*)ulNtDllModuleBase + pExportTable->AddressOfFunctions);  //��ַ��
		arrayOfFunctionNames = (DWORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNames);         //��������
		arrayOfFunctionOrdinals = (WORD*)( (BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNameOrdinals);

		Base = pExportTable->Base;

		for(x = 0; x < pExportTable->NumberOfFunctions; x++) //��������������ɨ��
		{
			functionName = (char*)( (BYTE*)ulNtDllModuleBase + arrayOfFunctionNames[x]);
			functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; 
			functionAddress = (DWORD)((BYTE*)ulNtDllModuleBase + arrayOfFunctionAddresses[functionOrdinal]);
			position  = *((WORD*)(functionAddress + 1));  //�õ������

			if (*Index == position)
			{
				if (g_bDebugOn)
					KdPrint(("search success[%s]",functionName));

				strcat(lpszFunctionName,functionName);
				bRetOK = TRUE;
				break;
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){
		KdPrint(("EXCEPTION_EXECUTE_HANDLER[%08x]",GetExceptionCode()));
	}
	return bRetOK;
}
BOOL GetFunctionIndexByName(CHAR *lpszFunctionName,int *Index)
{
	UNICODE_STRING wsNtDllString;

	HANDLE hNtSection;
	ULONG ulNtDllModuleBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS NtDllHeader;

	IMAGE_OPTIONAL_HEADER opthdr;
	DWORD* arrayOfFunctionAddresses;
	DWORD* arrayOfFunctionNames;
	WORD* arrayOfFunctionOrdinals;
	DWORD functionOrdinal;
	DWORD Base, x, functionAddress,position;
	char* functionName;
	IMAGE_EXPORT_DIRECTORY *pExportTable;
	BOOL bRetOK = FALSE;
	BOOL bInit = FALSE;

	STRING lpszSearchFunction;
	STRING lpszFunction;

	__try
	{
		ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		if (g_fnRRtlInitUnicodeString &&
			g_fnRZwClose)
		{
			bInit = TRUE;
		}
		if (!bInit)
			return FALSE;

		g_fnRRtlInitUnicodeString(&wsNtDllString,L"\\SystemRoot\\System32\\ntdll.dll");
		hNtSection = MapFileAsSection(&wsNtDllString,(PVOID)(&ulNtDllModuleBase));  //���뵽�ڴ�
		if (!hNtSection)
		{
			return bRetOK;
		}
		g_fnRZwClose(hNtSection);

		//NtDllHeader=(PIMAGE_NT_HEADERS)GetPeHead((ULONG)ulNtDllModuleBase);
		pDosHeader=(PIMAGE_DOS_HEADER)ulNtDllModuleBase;
		if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
		{
			if (g_bDebugOn)
				KdPrint(("failed to find NtHeader\r\n"));
			return bRetOK;
		}
		NtDllHeader=(PIMAGE_NT_HEADERS)(ULONG)((ULONG)pDosHeader+pDosHeader->e_lfanew);
		if (NtDllHeader->Signature!=IMAGE_NT_SIGNATURE)
		{
			if (g_bDebugOn)
				KdPrint(("failed to find NtHeader\r\n"));
			return bRetOK;
		}
		opthdr = NtDllHeader->OptionalHeader;
		pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*)ulNtDllModuleBase + opthdr.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress); //�õ�������
		arrayOfFunctionAddresses = (DWORD*)( (BYTE*)ulNtDllModuleBase + pExportTable->AddressOfFunctions);  //��ַ��
		arrayOfFunctionNames = (DWORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNames);         //��������
		arrayOfFunctionOrdinals = (WORD*)( (BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNameOrdinals);

		Base = pExportTable->Base;

		for(x = 0; x < pExportTable->NumberOfFunctions; x++) //��������������ɨ��
		{
			functionName = (char*)( (BYTE*)ulNtDllModuleBase + arrayOfFunctionNames[x]);
			functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; 
			functionAddress = (DWORD)((BYTE*)ulNtDllModuleBase + arrayOfFunctionAddresses[functionOrdinal]);
			position  = *((WORD*)(functionAddress + 1));  //�õ������

			RtlInitString(&lpszSearchFunction,functionName);
			RtlInitString(&lpszFunction,lpszFunctionName);
			if (RtlCompareString(&lpszSearchFunction,&lpszFunction,TRUE) == 0)
			{
				if (g_bDebugOn)
					KdPrint(("Find FunctionName:%s\r\nposition:%d\r\n",functionName,position));
				*Index = position;
				bRetOK = TRUE;
				break;
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	return bRetOK;
}
BOOL IsAddressInSystem(ULONG ulDriverBase,ULONG *ulSysModuleBase,ULONG *ulSize,char *lpszSysModuleImage)
{
	NTSTATUS status;
	ULONG NeededSize,i;
	PMODULES pModuleList;
	BOOL bRet = FALSE;
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRZwQuerySystemInformation),L"ZwQuerySystemInformation",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExAllocatePool),L"ExAllocatePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRZwQuerySystemInformation &&
		g_fnRExAllocatePool &&
		g_fnRExFreePool)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return FALSE;

	__try
	{
		status=g_fnRZwQuerySystemInformation(
			SystemModuleInformation,
			NULL,
			0,
			&NeededSize);
		if (status!=STATUS_INFO_LENGTH_MISMATCH)
		{
			//KdPrint(("ZwQuerySystemInformation failed:%d",RtlNtStatusToDosError(status)));
			return bRet;
		}
		pModuleList=(PMODULES)g_fnRExAllocatePool(NonPagedPool,NeededSize);
		if (pModuleList)
		{
			status=g_fnRZwQuerySystemInformation(
				SystemModuleInformation,
				pModuleList,
				NeededSize,
				&NeededSize);

			if (NT_SUCCESS(status))
			{
				for (i=0;i<pModuleList->ulCount;i++)
				{
					if (ulDriverBase > pModuleList->smi[i].Base && ulDriverBase < pModuleList->smi[i].Base + pModuleList->smi[i].Size)
					{
						bRet = TRUE;
						__try
						{
							*ulSysModuleBase = pModuleList->smi[i].Base;
							*ulSize = pModuleList->smi[i].Size;

							//memset(lpszSysModuleImage,0,sizeof(lpszSysModuleImage));
							memcpy(lpszSysModuleImage,pModuleList->smi[i].ImageName,strlen(pModuleList->smi[i].ImageName));

						}__except(EXCEPTION_EXECUTE_HANDLER){

						}
						break;
					}
				}
			}
			//else
			//	KdPrint(("@@ZwQuerySystemInformation failed:%d",RtlNtStatusToDosError(status)));

			g_fnRExFreePool(pModuleList);
			pModuleList = NULL;
		}
		//else
		//	KdPrint(("ExAllocatePool failed"));
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		if (g_bDebugOn)
			KdPrint(("IsAddressInSystem:%08x\r\n",GetExceptionCode()));
	}
	if (pModuleList)
		g_fnRExFreePool(pModuleList);

	return bRet;
}
//0��char *
//1��wchar*
ULONG GetSystemRoutineAddress(int IntType,PVOID lpwzFunction)
{
	ULONG ulFunction;
	UNICODE_STRING UnicodeFunctionString;
	ANSI_STRING AnsiFunctionString;
	int index;

	__try
	{
		ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		ReLoadNtosCALL((PVOID)(&g_fnRMmGetSystemRoutineAddress),L"MmGetSystemRoutineAddress",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		if (g_fnRRtlInitUnicodeString &&
			g_fnRMmGetSystemRoutineAddress)
		{
			if (IntType == 1)
			{
				g_fnRRtlInitUnicodeString(&UnicodeFunctionString,lpwzFunction);

			}else if (IntType == 0)
			{
				RtlInitAnsiString(&AnsiFunctionString,lpwzFunction);
				RtlAnsiStringToUnicodeString(&UnicodeFunctionString,&AnsiFunctionString,TRUE);
			}else
			{
				return FALSE;
			}
			ulFunction = (ULONG)g_fnRMmGetSystemRoutineAddress(&UnicodeFunctionString);
			if (IntType == 0)
			{
				RtlFreeUnicodeString(&UnicodeFunctionString);
			}
			if (MmIsAddressValidEx((PVOID)ulFunction))
			{
				if (IntType == 0)
				{
					if (*((char *)lpwzFunction) == 'Z' &&
						*((char *)lpwzFunction+1) == 'w')
					{
						index=*(DWORD*)(ulFunction+1);
						//��ssdt����ŵķ�Χ�ŷ���ssdt������ĵ�ַ
						if (index <=(int) g_pOriginalServiceDescriptorTable->TableSize)
						{
							ulFunction = g_pOriginalServiceDescriptorTable->ServiceTable[index] - (ULONG)g_pNewSystemKernelModuleBase + g_pOldSystemKernelModuleBase;
						}
					}
				}
				if (IntType == 1)
				{
					if (*((WCHAR *)lpwzFunction) == 'Z' &&
						*((WCHAR *)lpwzFunction+1) == 'w')
					{
						index=*(DWORD*)(ulFunction+1);
						if (index <=(int) g_pOriginalServiceDescriptorTable->TableSize)
						{
							ulFunction = g_pOriginalServiceDescriptorTable->ServiceTable[index] - (ULONG)g_pNewSystemKernelModuleBase + g_pOldSystemKernelModuleBase;
						}
					}
				}
				//return ulFunction;
				if (MmIsAddressValidEx((PVOID)ulFunction))
				{
					return ulFunction;
				}
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	return ulFunction;
}
NTSTATUS LookupProcessByName(
	IN PCHAR pcProcessName,
	OUT PEPROCESS *pEprocess
	)
{ 
	NTSTATUS	status;
	ULONG		uCount = 0;
	ULONG		uLength = 0;
	PLIST_ENTRY	pListActiveProcess;
	PEPROCESS	pCurrentEprocess = NULL;
	ULONG ulNextProcess = 0;
	ULONG g_Offset_Eprocess_Flink;
	WIN_VER_DETAIL WinVer;
	char lpszProName[100];
	char *lpszAttackProName = NULL;


	if (!ARGUMENT_PRESENT(pcProcessName) || !ARGUMENT_PRESENT(pEprocess))
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	uLength = strlen(pcProcessName);

	WinVer = GetWindowsVersion();
	switch(WinVer)
	{
	case WINDOWS_VERSION_XP:
		g_Offset_Eprocess_Flink = 0x88;
		break;
	case WINDOWS_VERSION_7_7600_UP:
	case WINDOWS_VERSION_7_7000:
		g_Offset_Eprocess_Flink = 0xb8;
		break;
	case WINDOWS_VERSION_VISTA_2008:
		g_Offset_Eprocess_Flink = 0x0a0;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		g_Offset_Eprocess_Flink = 0x98;
		break;
	case WINDOWS_VERSION_2K3:
		g_Offset_Eprocess_Flink = 0x088;
		break;
	}
	if (!g_Offset_Eprocess_Flink){
		return STATUS_UNSUCCESSFUL;
	}

	pCurrentEprocess = PsGetCurrentProcess();
	ulNextProcess =(ULONG) pCurrentEprocess;


	__try
	{
		memset(lpszProName,0,sizeof(lpszProName));
		if (uLength > 15)
		{
			strncat(lpszProName,pcProcessName,15);
		}
		while(1)
		{
			lpszAttackProName = NULL;
			lpszAttackProName = (char *)PsGetProcessImageFileName(pCurrentEprocess);

			if (uLength > 15)
			{
				if (lpszAttackProName &&
					strlen(lpszAttackProName) == uLength)
				{
					if(_strnicmp(lpszProName,lpszAttackProName, uLength) == 0)
					{
						*pEprocess = pCurrentEprocess;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
			else
			{
				if (lpszAttackProName &&
					strlen(lpszAttackProName) == uLength)
				{
					if(_strnicmp(pcProcessName,lpszAttackProName, uLength) == 0)
					{
						*pEprocess = pCurrentEprocess;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
			if ((uCount >= 1) && (ulNextProcess ==(ULONG) pCurrentEprocess))
			{
				*pEprocess = 0x00000000;
				status = STATUS_NOT_FOUND;
				break;
			}
			pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
			(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink;
			(ULONG)pCurrentEprocess = (ULONG)pCurrentEprocess - g_Offset_Eprocess_Flink;
			uCount++;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("LookupProcessByName:%08x\r\n",GetExceptionCode()));
		status = STATUS_NOT_FOUND;
	}
	return status;
}

BOOLEAN ValidateUnicodeString(PUNICODE_STRING usStr)
{
	ULONG i;

	__try
	{
		if (!MmIsAddressValidEx(usStr))
		{
			return FALSE;
		}
		if (usStr->Buffer == NULL || usStr->Length == 0)
		{
			return FALSE;
		}
		for (i = 0; i < usStr->Length; i++)
		{
			if (!MmIsAddressValidEx((PUCHAR)usStr->Buffer + i))
			{
				return FALSE;
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	return TRUE;
}
NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size)
{
	PMDL  pSrcMdl, pDstMdl;
	PUCHAR pSrcAddress, pDstAddress;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	ULONG r;
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRIoAllocateMdl),L"IoAllocateMdl",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&RMmBuildMdlForNonPagedPool),L"MmBuildMdlForNonPagedPool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRMmProbeAndLockPages),L"MmProbeAndLockPages",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRMmUnlockPages),L"MmUnlockPages",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoFreeMdl),L"IoFreeMdl",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRIoAllocateMdl &&
		RMmBuildMdlForNonPagedPool &&
		g_fnRMmProbeAndLockPages &&
		g_fnRMmUnlockPages &&
		g_fnRIoFreeMdl)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return STATUS_UNSUCCESSFUL;

	pSrcMdl = g_fnRIoAllocateMdl(SrcAddr, Size, FALSE, FALSE, NULL);
	if (MmIsAddressValidEx(pSrcMdl))
	{
		RMmBuildMdlForNonPagedPool(pSrcMdl);
		pSrcAddress = MmGetSystemAddressForMdlSafe(pSrcMdl, NormalPagePriority);
		if (MmIsAddressValidEx(pSrcAddress))
		{
			pDstMdl = g_fnRIoAllocateMdl(DstAddr, Size, FALSE, FALSE, NULL);
			if (MmIsAddressValidEx(pDstMdl))
			{
				__try
				{
					g_fnRMmProbeAndLockPages(pDstMdl, KernelMode, IoWriteAccess);
					pDstAddress = MmGetSystemAddressForMdlSafe(pDstMdl, NormalPagePriority);
					if (MmIsAddressValidEx(pDstAddress))
					{
						RtlZeroMemory(pDstAddress,Size);
						RtlCopyMemory(pDstAddress, pSrcAddress, Size);
						st = STATUS_SUCCESS;
					}
					g_fnRMmUnlockPages(pDstMdl);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{                 
					if (pDstMdl)
						g_fnRMmUnlockPages(pDstMdl);

					if (pDstMdl)
						g_fnRIoFreeMdl(pDstMdl);

					if (pSrcMdl)
						g_fnRIoFreeMdl(pSrcMdl);

					return GetExceptionCode();
				}
				g_fnRIoFreeMdl(pDstMdl);
			}
		}            
		g_fnRIoFreeMdl(pSrcMdl);
	}
	return st;
}
PEPROCESS GetEprocessFromPid(HANDLE Pid)
{
	HANDLE hProcess;
	NTSTATUS status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PEPROCESS Process=NULL;
	CLIENT_ID ClientId={0};

	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRZwOpenProcess),L"ZwOpenProcess",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByHandle),L"ObReferenceObjectByHandle",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRZwOpenProcess &&
		g_fnRObReferenceObjectByHandle &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return NULL;

	ClientId.UniqueProcess = Pid;
	InitializeObjectAttributes(
		&ObjectAttributes,
		NULL,
		0,
		NULL, 
		NULL
		);
	status=g_fnRZwOpenProcess(
		&hProcess,
		PROCESS_ALL_ACCESS,
		&ObjectAttributes,
		&ClientId
		);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	status = g_fnRObReferenceObjectByHandle(
		hProcess,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		(PVOID *)&Process,
		NULL);
	if (!NT_SUCCESS(status))
	{
		g_fnRZwClose(hProcess);
		return NULL;
	}
	ObDereferenceObject(Process);
	g_fnRZwClose(hProcess);
	return Process;
}
ULONG GetInheritedProcessPid(PEPROCESS Eprocess)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	HANDLE hProcess;
	ULONG pid=0;
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRObOpenObjectByPointer),L"ObOpenObjectByPointer",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwQueryInformationProcess),L"ZwQueryInformationProcess",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRObOpenObjectByPointer &&
		g_fnRZwQueryInformationProcess &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
	{
		if (g_bDebugOn)
			KdPrint(("bInit failed:%x %x %x",g_fnRObOpenObjectByPointer,g_fnRZwQueryInformationProcess,g_fnRZwClose));

		return 0;
	}
	//��Ч�Ľ��̶��󣬻����Ѿ��˳��Ľ��̣���ֱ�ӷ���
	if (!MmIsAddressValidEx(Eprocess) ||
		!IsExitProcess(Eprocess)){
		return 0;
	}
	status = g_fnRObOpenObjectByPointer(
		Eprocess,          // Object    
		OBJ_KERNEL_HANDLE,  // HandleAttributes    
		NULL,               // PassedAccessState OPTIONAL    
		PROCESS_ALL_ACCESS,       // DesiredAccess    
		*PsProcessType,     // ObjectType    
		KernelMode,         // AccessMode    
		&hProcess);
	if (!NT_SUCCESS(status))
	{
		if (g_bDebugOn)
			KdPrint(("ObOpenObjectByPointer failed:%d",RtlNtStatusToDosError(status)));
		return 0;
	}
	status = g_fnRZwQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		(PVOID)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL );
	if (!NT_SUCCESS(status))
	{
		g_fnRZwClose(hProcess);

		if (g_bDebugOn)
			KdPrint(("ZwQueryInformationProcess failed:%d",RtlNtStatusToDosError(status)));
		return 0;
	}
	if (g_bDebugOn)
		KdPrint(("InheritedFromUniqueProcessId:%d",pbi.InheritedFromUniqueProcessId));

	pid = pbi.InheritedFromUniqueProcessId;
	g_fnRZwClose(hProcess);
	return pid;
}
BOOL KernelStatus(HANDLE hPid)
{
	HANDLE hProcess;
	NTSTATUS status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID ClientId={0};
	BOOL bRetOK = FALSE;

	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRZwOpenProcess),L"ZwOpenProcess",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRZwOpenProcess &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return FALSE;

	ClientId.UniqueProcess = hPid;
	InitializeObjectAttributes(
		&ObjectAttributes,
		NULL,
		0,
		NULL, 
		NULL 
		);
	status=g_fnRZwOpenProcess(
		&hProcess,
		PROCESS_ALL_ACCESS,
		&ObjectAttributes,
		&ClientId
		);
	if (NT_SUCCESS(status))
	{
		bRetOK = TRUE;
		g_fnRZwClose(hProcess);
	}
	return bRetOK;
}
BOOL IsExitProcess(PEPROCESS Eprocess)
{
	WIN_VER_DETAIL WinVer;
	ULONG SectionObjectOffset = 0;
	ULONG SectionObject;
	ULONG SegmentOffset = 0;
	ULONG Segment;
	BOOL bRetOK = FALSE;

	if (!ARGUMENT_PRESENT(Eprocess) ||
		!Eprocess)
	{
		return bRetOK;
	}
	//�ų�system����
	if (Eprocess == g_systemEProcess)
	{
		return TRUE;
	}
	__try
	{
                
		if (!g_WinVersion)
		WinVer = GetWindowsVersion();
	        else
		WinVer = g_WinVersion;

		switch (WinVer)
		{
		case WINDOWS_VERSION_XP:
			SectionObjectOffset = 0x138;
			SegmentOffset=0x14;
			break;
		case WINDOWS_VERSION_2K3_SP1_SP2:
			SectionObjectOffset = 0x124;
			SegmentOffset=0x14;
			break;
		case WINDOWS_VERSION_7_7600_UP:
			SectionObjectOffset = 0x128;
			SegmentOffset=0x14;
			break;
		case WINDOWS_VERSION_7_7000:
			SectionObjectOffset = 0x128;
			SegmentOffset=0x14;
			break;
		}
		if (SegmentOffset &&
			SectionObjectOffset)
		{
			if (MmIsAddressValidEx((PVOID)((ULONG)Eprocess + SectionObjectOffset)) ){
				SectionObject = *(PULONG)((ULONG)Eprocess + SectionObjectOffset);

				if (MmIsAddressValidEx((PVOID)((ULONG)SectionObject + SegmentOffset))){
					Segment = *(PULONG)((ULONG)SectionObject + SegmentOffset);

					if (MmIsAddressValidEx((PVOID)Segment)){
						bRetOK = TRUE;  //��������Ч��
						__leave;
					}
				}
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
		KdPrint(("%08x\r\n",GetExceptionCode()));
	}
	return bRetOK;
}
BOOL DeleteRegKey(WCHAR *ServicesKey)
{
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING RegUnicodeString;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	BOOL bRetOK = FALSE;

	RtlInitUnicodeString(&RegUnicodeString,ServicesKey);
	InitializeObjectAttributes(
		&objectAttributes,
		&RegUnicodeString,
		OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,//�Դ�Сд���� 
		NULL, 
		NULL 
		);
	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes
		);
	if (NT_SUCCESS(ntStatus))
	{
		KdPrint(("ZwOpenKey\n"));

		//������ǰ��ֵ��û���Ӽ�����ɾ��
		ntStatus = ZwDeleteKey(hRegister);
		if (ntStatus == STATUS_SUCCESS)
		{
			KdPrint(("ZwDeleteKey:%ws\n",ServicesKey));
			bRetOK = TRUE;
		}
		else
			KdPrint(("ZwDeleteKey failed:%d\n",RtlNtStatusToDosError(ntStatus)));

		ZwClose(hRegister);
	}
	return bRetOK;
}
BOOL Safe_CreateValueKey(PWCHAR SafeKey,ULONG Reg_Type,PWCHAR ValueName,PWCHAR Value)
{
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING RegUnicodeString,Unicode_ValueName;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	ULONG ulValue_DWORD;
	ULONG ulResult=0;
	BOOL bRetOK = FALSE;

	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwCreateKey),L"ZwCreateKey",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwSetValueKey),L"ZwSetValueKey",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&RZwFlushKey),L"ZwFlushKey",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRRtlInitUnicodeString &&
		g_fnRZwCreateKey &&
		g_fnRZwSetValueKey &&
		RZwFlushKey &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return FALSE;

	g_fnRRtlInitUnicodeString(&Unicode_ValueName,ValueName);
	g_fnRRtlInitUnicodeString(&RegUnicodeString,SafeKey);
	//��ʼ��objectAttributes
	InitializeObjectAttributes(
		&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,//�Դ�Сд���� 
		NULL, 
		NULL 
		);
	//���������ע�����Ŀ
	ntStatus = g_fnRZwCreateKey(
		&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		&ulResult
		);
	if (NT_SUCCESS(ntStatus))
	{
		bRetOK = TRUE;

		switch (Reg_Type)
		{
		case REG_SZ:
			g_fnRZwSetValueKey(
				hRegister,
				&Unicode_ValueName,
				0,
				Reg_Type,
				Value,
				wcslen(Value)*2
				);
			break;
		case REG_EXPAND_SZ:
			g_fnRZwSetValueKey(
				hRegister,
				&Unicode_ValueName,
				0,
				Reg_Type,
				Value,
				wcslen(Value)*2
				);
			break;
		case REG_DWORD:
			ulValue_DWORD = sizeof(REG_DWORD);
			g_fnRZwSetValueKey(
				hRegister,
				&Unicode_ValueName,
				0,
				Reg_Type,
				&Value,
				sizeof(ulValue_DWORD)
				);
			break;
		}
		RZwFlushKey(hRegister);
		g_fnRZwClose(hRegister);
	}
	return bRetOK;
}
VOID KillPro(ULONG ulPidOrEprocess)
{
	PEPROCESS EProcess;
	BOOL bInit = FALSE;

	//�Լ������Լ����ͷ���
	if (ulPidOrEprocess == (ULONG)g_protectEProcess)
	{
		return;
	}
	//�������MmUserProbeAddress��˵���������PEPROCESS
	if (ulPidOrEprocess >(ULONG) MmUserProbeAddress)
	{
		if (g_bDebugOn)
			KdPrint(("kill by object:%08X",ulPidOrEprocess));

		if (!IsExitProcess((PEPROCESS)ulPidOrEprocess)){
			return;
		}
		EProcess = (PEPROCESS)ulPidOrEprocess;

		if (!ZeroProcessMemory((ULONG)EProcess)){
			//�ڴ�����ʧ�ܣ���ɱ�̣߳�˫�ر�֤~
			if (IsExitProcess(EProcess)){
				if (KillProcess((ULONG)EProcess) != STATUS_SUCCESS){
					if (g_bDebugOn)
						KdPrint(("failed\r\n"));
				}
			}
		}

	}else
	{
		if (g_bDebugOn)
			KdPrint(("kill by pid:%d",ulPidOrEprocess));

		if (LookupProcessByPid((HANDLE)ulPidOrEprocess,&EProcess) == STATUS_SUCCESS)
		{
			if (!ZeroProcessMemory((ULONG)EProcess)){
				//�ڴ�����ʧ�ܣ���ɱ�̣߳�˫�ر�֤~
				if (IsExitProcess(EProcess)){
					if (KillProcess((ULONG)EProcess) != STATUS_SUCCESS){
						if (g_bDebugOn)
							KdPrint(("failed\r\n"));
					}
				}
			}
		}
	}
}