#include "ntos.h"

BOOL GetOriginalKiServiceTable(BYTE *NewImageBase,DWORD ExistImageBase,DWORD *NewKiServiceTable)
{
	PIMAGE_DOS_HEADER ImageDosHeader;
	PIMAGE_NT_HEADERS ImageNtHeaders;
	DWORD KeServiceDescriptorTableRva;
	PIMAGE_BASE_RELOCATION ImageBaseReloc=NULL;
	DWORD RelocSize;
	int ItemCount,Index;
	int Type;
	PDWORD RelocAddress;
	DWORD RvaData;
	DWORD count=0;
	WORD *TypeOffset;


	ImageDosHeader=(PIMAGE_DOS_HEADER)NewImageBase;
	if (ImageDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}
	ImageNtHeaders=(PIMAGE_NT_HEADERS)(NewImageBase+ImageDosHeader->e_lfanew);
	if (ImageNtHeaders->Signature!=IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	KeServiceDescriptorTableRva=(DWORD)MiFindExportedRoutine(NewImageBase,TRUE,"KeServiceDescriptorTable",0);
	if (KeServiceDescriptorTableRva==0)
	{
		return FALSE;
	}

	KeServiceDescriptorTableRva=KeServiceDescriptorTableRva-(DWORD)NewImageBase;
	if (g_bDebugOn)
		KdPrint(("KeServiceDescriptorTable:%X\n",KeServiceDescriptorTableRva));
	ImageBaseReloc=RtlImageDirectoryEntryToData(NewImageBase,TRUE,IMAGE_DIRECTORY_ENTRY_BASERELOC,&RelocSize);
	if (ImageBaseReloc==NULL)
	{
		return FALSE;
	}
	if (g_bDebugOn)
		KdPrint(("get x IMAGE_DIRECTORY_ENTRY_BASERELOC ok\n"));
	while (ImageBaseReloc->SizeOfBlock)
	{  
		count++;
		ItemCount=(ImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
		TypeOffset=(WORD*)((DWORD)ImageBaseReloc+sizeof(IMAGE_BASE_RELOCATION));
		for (Index=0;Index<ItemCount;Index++)
		{
			Type=TypeOffset[Index]>>12;
			if (Type==3)
			{
				RelocAddress=(PDWORD)((DWORD)(TypeOffset[Index]&0x0fff)+ImageBaseReloc->VirtualAddress+(DWORD)NewImageBase);
				RvaData=*RelocAddress-ExistImageBase;

				if (RvaData==KeServiceDescriptorTableRva)
				{
					if(*(USHORT*)((DWORD)RelocAddress-2)==0x05c7)
					{

						*NewKiServiceTable=*(DWORD*)((DWORD)RelocAddress+4)-ExistImageBase+(DWORD)NewImageBase;
						if (g_bDebugOn)
							KdPrint(("Find OriginalImage ssdt :%X\n",*NewKiServiceTable));
						return TRUE;
					}
				}

			}

		}
		ImageBaseReloc=(PIMAGE_BASE_RELOCATION)((DWORD)ImageBaseReloc+ImageBaseReloc->SizeOfBlock);
	}
	if (g_bDebugOn)
		KdPrint(("count:%d\n",count));

	return FALSE;
}
VOID FixOriginalKiServiceTable(PDWORD OriginalKiServiceTable,DWORD ModuleBase,DWORD ExistImageBase)
{
	DWORD FuctionCount;
	DWORD Index;
	FuctionCount=KeServiceDescriptorTable->TableSize;
	if (g_bDebugOn)
		KdPrint(("ssdt funcion count:%X---KiServiceTable:%X\n",FuctionCount,KeServiceDescriptorTable->ServiceTable));	
	for (Index=0;Index<FuctionCount;Index++)
	{
		OriginalKiServiceTable[Index]=OriginalKiServiceTable[Index]-ExistImageBase+ModuleBase;
	}
}

BOOL InitSafeOperationModule(PDRIVER_OBJECT pDriverObject,WCHAR *SystemModulePath,ULONG KernelModuleBase)
{
	UNICODE_STRING FileName;
	HANDLE hSection;
	PDWORD FixdOriginalKiServiceTable;
	PDWORD CsRootkitOriginalKiServiceTable;
	int i=0;

	if (g_bDebugOn)
		KdPrint(("Safe->Get System Kernel Module Info %ws:%08x\r\n",SystemModulePath,KernelModuleBase));

	if (g_bDebugOn)
		KdPrint(("Safe->DriverObject:%08x\r\n",pDriverObject));

	//�Լ�peload һ��ntos*�������ͽ���˸�������ȫ����ĳ�ͻ��~
	if (!PeLoad(SystemModulePath,&g_pNewSystemKernelModuleBase,pDriverObject,KernelModuleBase))
	{
		if (g_bDebugOn)
			KdPrint(("Safe->PeLoad failed\n"));
		return FALSE;
	}

	if (g_bDebugOn)
		KdPrint(("Safe->ModuleBase:%08x\r\n",g_pNewSystemKernelModuleBase));

	g_dwOriginalKiServiceTable =(DWORD) ExAllocatePool(NonPagedPool,KeServiceDescriptorTable->TableSize*sizeof(DWORD));
	if (!g_dwOriginalKiServiceTable)
	{
		if (g_bDebugOn)
			KdPrint(("OriginalKiServiceTable Failed\n"));
		return FALSE;
	}
	if(!GetOriginalKiServiceTable(g_pNewSystemKernelModuleBase,KernelModuleBase,&g_dwOriginalKiServiceTable))
	{
		if (g_bDebugOn)
			KdPrint(("Safe->Get Original KiServiceTable Failed\n"));

		ExFreePool((PVOID)g_dwOriginalKiServiceTable);

		return FALSE;
	}
	if (g_bDebugOn)
		KdPrint(("Safe->OriginalKiServiceTable %X\n",g_dwOriginalKiServiceTable));

	//���ÿһ��ssdt��Ӧ������ַ~����ĵ�ַ��reload��
    FixOriginalKiServiceTable((PDWORD)g_dwOriginalKiServiceTable,(DWORD)g_pNewSystemKernelModuleBase,KernelModuleBase);

	g_pOriginalServiceDescriptorTable=ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	if (g_pOriginalServiceDescriptorTable == NULL)
	{
		ExFreePool((PVOID)g_dwOriginalKiServiceTable);
		return FALSE;
	}
	RtlZeroMemory(g_pOriginalServiceDescriptorTable,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	//����һ���ɾ���ԭʼ��ÿ����������Ӧ��SSDT�����ĵ�ַ������Ч��~
	g_pOriginalServiceDescriptorTable->ServiceTable = (PDWORD)g_dwOriginalKiServiceTable;
	g_pOriginalServiceDescriptorTable->CounterTable = KeServiceDescriptorTable->CounterTable;
	g_pOriginalServiceDescriptorTable->TableSize    = KeServiceDescriptorTable->TableSize;
	g_pOriginalServiceDescriptorTable->ArgumentTable = KeServiceDescriptorTable->ArgumentTable;

	CsRootkitOriginalKiServiceTable = ExAllocatePool(NonPagedPool,KeServiceDescriptorTable->TableSize*sizeof(DWORD));
	if (CsRootkitOriginalKiServiceTable==NULL)
	{
		ExFreePool(g_pOriginalServiceDescriptorTable);
		ExFreePool((PVOID)g_dwOriginalKiServiceTable);
		return FALSE;

	}
	RtlZeroMemory(CsRootkitOriginalKiServiceTable,KeServiceDescriptorTable->TableSize*sizeof(DWORD));

	g_pSafe_ServiceDescriptorTable = ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	if (g_pSafe_ServiceDescriptorTable == NULL)
	{
		ExFreePool(g_pOriginalServiceDescriptorTable);
		ExFreePool(CsRootkitOriginalKiServiceTable);
		ExFreePool((PVOID)g_dwOriginalKiServiceTable);
		return FALSE;
	}
	//����һ���ɾ���ԭʼ��ÿ����������Ӧ��SSDT�����ĵ�ַ����ԭʼ����
	RtlZeroMemory(g_pSafe_ServiceDescriptorTable,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	
	//���ԭʼ������ַ
// 	for (i=0;i<KeServiceDescriptorTable->TableSize;i++)
// 	{
// 		CsRootkitOriginalKiServiceTable[i] = OriginalServiceDescriptorTable->ServiceTable[i];
// 	}
	g_pSafe_ServiceDescriptorTable->ServiceTable = (PDWORD)CsRootkitOriginalKiServiceTable;
	g_pSafe_ServiceDescriptorTable->CounterTable = KeServiceDescriptorTable->CounterTable;
	g_pSafe_ServiceDescriptorTable->TableSize = KeServiceDescriptorTable->TableSize;
	g_pSafe_ServiceDescriptorTable->ArgumentTable = KeServiceDescriptorTable->ArgumentTable;

	//�ͷžͻ�bsod
	//ExFreePool(OriginalKiServiceTable);
	return TRUE;
}
///////////////////////////////////////////////////
__declspec(naked) VOID KiFastCallEntryHookZone()
{
	_asm
	{
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		jmp [KiFastCallEntryRet];

	}
}
///////////////////////////////////////////////////
__declspec(naked) VOID KiFastCallEntryTempHookZone()
{
	_asm
	{
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		_emit 0x90;
		jmp [KiFastCallEntryTempRet];

	}
}

PSERVICE_DESCRIPTOR_TABLE __stdcall FakeServiceDescriptorTable(PSERVICE_DESCRIPTOR_TABLE ServiceDescriptorTable,DWORD Index)
{
	ULONG ulEProcess;
	ULONG ulRetOK;
	int i=0;

	if (!g_fnRMmIsAddressValid ||
		!g_fnRPsGetCurrentProcess)
	{
		goto _FunRet;
	}
	//---------------------------------------------------
	//sreach hide process demo
	//---------------------------------------------------
	if (g_bIsInitSuccess)
	{
		ulEProcess = 0;
		ulEProcess = (ULONG)g_fnRPsGetCurrentProcess();
		if (g_fnRMmIsAddressValid((PVOID)ulEProcess))
		{
			ulRetOK = IsHideProcess(ulEProcess,g_pHideProcessInfo);
			if (ulRetOK == 8)
			{
				//�������ؽ��̣�����
			}
		}
	}
	//--------------------------------------------------------
	//SSDT
	//-------------------------------------------------------
	if (ServiceDescriptorTable->ServiceTable == KeServiceDescriptorTable->ServiceTable)
	{
		if (g_pSafe_ServiceDescriptorTable->TableSize > Index &&
			g_pSafe_ServiceDescriptorTable->TableSize == ServiceDescriptorTable->TableSize)
		{
			if ((ULONG)g_pSafe_ServiceDescriptorTable->ServiceTable[Index] >= g_ulMyDriverBase &&
				(ULONG)g_pSafe_ServiceDescriptorTable->ServiceTable[Index] <= g_ulMyDriverBase + g_ulMyDriverSize)
			{
				//��ǰ����ŵĺ�����hook�������й��˺����ı�~
				return g_pSafe_ServiceDescriptorTable;
			}
		}
		//����ú���û�б�hook���ͷ��ظɾ��ı�����ĵ�ַ����Ч����û�б��������hook����Ŷ���������������hook�Ͳ�������~����Ϊ��������������Խ���xuetr
		//����Ҳ���Է���ServiceDescriptorTable���������������hook�ʹ�����
		//�������ַ���ֵ�����վ���������� -_-!!
		//�������ں˰�ȫģʽ������һ������һ��ԭʼ�ɾ���SSDT��~~�����κ�hook��

		//��A�����е�ʱ�򣬲ſ����ں˰�ȫģʽ
		if (g_bIsInitSuccess &&
			g_bKernelSafeModule &&
			g_pOriginalServiceDescriptorTable->TableSize == ServiceDescriptorTable->TableSize)
		{
			return g_pOriginalServiceDescriptorTable;
		}

	}
	if (bInitWin32K &&
		g_fnRMmIsAddressValid((PVOID)g_ShadowTable))
	{
		if (ServiceDescriptorTable->ServiceTable == (PDWORD)g_ShadowTable)    //ShadowSSDT
		{
			//KdPrint(("ShadowSSDT:%08x",ServiceDescriptorTable->ServiceTable[Index]));
			if (g_Safe_ServiceDescriptorShadowSSDTTable->TableSize > Index &&
				g_Safe_ServiceDescriptorShadowSSDTTable->TableSize == ServiceDescriptorTable->TableSize)
			{
				if (g_Safe_ServiceDescriptorShadowSSDTTable->ServiceTable[Index] >= g_ulMyDriverBase &&
					g_Safe_ServiceDescriptorShadowSSDTTable->ServiceTable[Index] <= g_ulMyDriverBase + g_ulMyDriverSize)
				{
					//��ǰ����ŵĺ�����hook�������й��˺����ı�~
					return g_Safe_ServiceDescriptorShadowSSDTTable;
				}
			}
			if (g_bIsInitSuccess &&
				g_bKernelSafeModule &&
				g_OriginalShadowServiceDescriptorTable->TableSize == ServiceDescriptorTable->TableSize)
			{
				return g_OriginalShadowServiceDescriptorTable;
			}
		}
	}

_FunRet:
	//����ssdt������ԭʼ~
	return ServiceDescriptorTable;
}
__declspec(naked) VOID KiFastCallEntryHookProc()
{
	_asm
	{
		push eax;
		push ecx;
		push edx;

		push eax;
		push edi;
		call FakeServiceDescriptorTable;
		mov edi,eax;

		pop edx;
		pop ecx;
		pop eax;
		jmp [KiFastCallEntryHookZone];
	}
}
/*
    win xp:
	8053e632 8bf2            mov     esi,edx
	8053e634 8b5f0c          mov     ebx,dword ptr [edi+0Ch]
	8053e637 33c9            xor     ecx,ecx
	8053e639 8a0c18          mov     cl,byte ptr [eax+ebx]
	8053e63c 8b3f            mov     edi,dword ptr [edi]
	8053e63e 8b1c87          mov     ebx,dword ptr [edi+eax*4]

	CodeInfo->LineCount=2;
	CodeInfo->CodeLine[0].CodeLength=2;
	CodeInfo->CodeLine[0].Code[0]=0x33;
	CodeInfo->CodeLine[0].Code[1]=0xC9;

	CodeInfo->CodeLine[1].CodeLength=3;
	CodeInfo->CodeLine[1].Code[0]=0x8A;
	CodeInfo->CodeLine[1].Code[1]=0x0C;
	CodeInfo->CodeLine[1].Code[2]=0x18;


	win 7:
	83c593ce 64ff05b0060000  inc     dword ptr fs:[6B0h]
	83c593d5 8bf2            mov     esi,edx
	83c593d7 33c9            xor     ecx,ecx
	83c593d9 8b570c          mov     edx,dword ptr [edi+0Ch]
	83c593dc 8b3f            mov     edi,dword ptr [edi]
	83c593de 8a0c10          mov     cl,byte ptr [eax+edx]
	83c593e1 8b1487          mov     edx,dword ptr [edi+eax*4]
	83c593e4 2be1            sub     esp,ecx
	83c593e6 c1e902          shr     ecx,2

	CodeInfo->LineCount=2;
	CodeInfo->CodeLine[0].CodeLength=2;
	CodeInfo->CodeLine[0].Code[0]=0x33;
	CodeInfo->CodeLine[0].Code[1]=0xC9;

	CodeInfo->CodeLine[1].CodeLength=3;
	CodeInfo->CodeLine[1].Code[0]=0x8B;
	CodeInfo->CodeLine[1].Code[1]=0x57;
	CodeInfo->CodeLine[1].Code[2]=0x0C;
*/

BOOL HookKiFastCallEntry()
{
	DWORD fnKiFastCallEntry;
	DWORD dwReloadKiFastCallEntry;
	int nCodeInfoLength;
	PCODE_INFO pCodeInfo;
	int nPatchCodeLength;
	WIN_VER_DETAIL winVer;
	BOOL bRetOK = FALSE;

	_asm
	{
		pushad;
		mov ecx, 0x176;
		rdmsr;
		mov fnKiFastCallEntry, eax;
		popad;
	}
	if (g_bDebugOn)
		KdPrint(("Safe->KiFastCallEntry:0x%08X\n",fnKiFastCallEntry));

	nCodeInfoLength = sizeof(CODE_INFO)+sizeof(CODE_LINE);
	pCodeInfo = ExAllocatePool(NonPagedPool,nCodeInfoLength);
	if (pCodeInfo == NULL)
	{
		return bRetOK;
	}
	RtlZeroMemory(pCodeInfo,nCodeInfoLength);

	winVer = GetWindowsVersion();
	switch(winVer)
	{
	case WINDOWS_VERSION_XP:
	case WINDOWS_VERSION_2K3_SP1_SP2:
		pCodeInfo->LineCount=1;
		pCodeInfo->CodeLine[0].CodeLength=2;
		pCodeInfo->CodeLine[0].Code[0]=0x33;
		pCodeInfo->CodeLine[0].Code[1]=0xC9;

		pCodeInfo->CodeLine[1].CodeLength=3;
		pCodeInfo->CodeLine[1].Code[0]=0x8A;
		pCodeInfo->CodeLine[1].Code[1]=0x0C;
		pCodeInfo->CodeLine[1].Code[2]=0x18;
		break;
	case WINDOWS_VERSION_7_7000:
	case WINDOWS_VERSION_7_7600_UP:
		pCodeInfo->LineCount=1;
		pCodeInfo->CodeLine[0].CodeLength=2;
		pCodeInfo->CodeLine[0].Code[0]=0x33;
		pCodeInfo->CodeLine[0].Code[1]=0xC9;

		pCodeInfo->CodeLine[1].CodeLength=3;
		pCodeInfo->CodeLine[1].Code[0]=0x8B;
		pCodeInfo->CodeLine[1].Code[1]=0x57;
		pCodeInfo->CodeLine[1].Code[2]=0x0C;
		break;
	}
	//��hook KiFastCallEntryͷ������ת�� dwReloadKiFastCallEntry
	dwReloadKiFastCallEntry = fnKiFastCallEntry - g_pOldSystemKernelModuleBase +(ULONG) g_pNewSystemKernelModuleBase;
	if (!MmIsAddressValidEx((PVOID)dwReloadKiFastCallEntry))
	{
		ExFreePool(pCodeInfo);
		return FALSE;
	}
	bRetOK = HookFunctionByHeaderAddress(
		dwReloadKiFastCallEntry,
		fnKiFastCallEntry,
		KiFastCallEntryTempHookZone,
		&KiFastCallEntryTempPatchCodeLength,
		&KiFastCallEntryTempRet
		);
	if (bRetOK)
	{
		bRetOK = FALSE;

		//��hook dwReloadKiFastCallEntry����ñ�hook����

		if(HookFunctionMiddle((BYTE*)dwReloadKiFastCallEntry,4096,(DWORD)KiFastCallEntryHookProc,pCodeInfo,KiFastCallEntryHookZone,&nPatchCodeLength,&KiFastCallEntryRet))
		{
			memcpy(ByteKiFastCallEntryBak,(PVOID)fnKiFastCallEntry,5);  //������ת��ַ
			memcpy(ByteReloadKiFastCallEntryBak,(PVOID)dwReloadKiFastCallEntry,5);  //������ת��ַ
			bRetOK = TRUE;
		}
	}
/*
	if(HookFunctionMiddle((BYTE*)KiFastCallEntry,4096,(DWORD)KiFastCallEntryHookProc,CodeInfo,KiFastCallEntryHookZone,&PatchCodeLength,&KiFastCallEntryRet))
	{
		//����hook�ĵ�ַ
		//ulKiFastCallEntryHookCheck = (ULONG)KiFastCallEntryRet-PatchCodeLength;
		//memcpy(ByteHookCheck,(PVOID)ulKiFastCallEntryHookCheck,5);  //������ת��ַ

		//KdPrint(("hook ok��%08x\n",ulKiFastCallEntryHookCheck));
		bRetOK = TRUE;
	}
*/
	ExFreePool(pCodeInfo);
	return bRetOK;
}

PVOID ReLoadNtosCALL(PVOID *pFuncSyntax,WCHAR *lpwzFuncTion,ULONG ulOldNtosBase,ULONG ulReloadNtosBase)
{
	int i=0;
	ULONG ulRet = FALSE;

	if (g_fnRMmIsAddressValid)
	{
		if (g_fnRMmIsAddressValid(*pFuncSyntax))
		{
			return *pFuncSyntax;
		}
	}
	else
	{
		if (MmIsAddressValid(*pFuncSyntax))
		{
			return *pFuncSyntax;
		}
	}
	__try
	{
		for (i=0;i<(int)g_pNtosFuncAddressInfo->ulCount;i++)
		{
			if (_wcsnicmp(g_pNtosFuncAddressInfo->ntosFuncInfo[i].FuncName,lpwzFuncTion,wcslen(lpwzFuncTion)) == 0)
			{
				*pFuncSyntax = (PVOID)g_pNtosFuncAddressInfo->ntosFuncInfo[i].ulReloadAddress;

				if (g_bDebugOn)
					KdPrint(("[%ws]%08x -- %08x\n",lpwzFuncTion,*pFuncSyntax,g_pNtosFuncAddressInfo->ntosFuncInfo[i].ulReloadAddress));

				ulRet = TRUE;
				break;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return (PVOID)ulRet;
}

//�ӵ���������ȥ���к������浽�ṹ��
ULONG GetKernelFunction(PNTOSFUNCINFO pNtosFunc)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;

	IMAGE_OPTIONAL_HEADER opthdr;
	DWORD* arrayOfFunctionAddresses;
	DWORD* arrayOfFunctionNames;
	WORD* arrayOfFunctionOrdinals;
	DWORD functionOrdinal;
	DWORD Base, x, functionAddress,position;
	char* functionName;
	IMAGE_EXPORT_DIRECTORY *pExportTable;
	ULONG ulNtDllModuleBase;

	UNICODE_STRING UnicodeFunction;
	UNICODE_STRING UnicodeExportTableFunction;
	ANSI_STRING ExportTableFunction;


	memcpy(pNtosFunc->szModulePath,g_szSystemKernelFilePath,wcslen(g_szSystemKernelFilePath)*2);

	__try
	{
		//�ӵ��������ȡ
		ulNtDllModuleBase = (ULONG)g_pNewSystemKernelModuleBase;
		pDosHeader = (PIMAGE_DOS_HEADER)g_pNewSystemKernelModuleBase;
		if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
		{
			KdPrint(("failed to find NtHeader\r\n"));
			return 0;
		}
		pNtHeader=(PIMAGE_NT_HEADERS)(ULONG)((ULONG)pDosHeader+pDosHeader->e_lfanew);
		if (pNtHeader->Signature!=IMAGE_NT_SIGNATURE)
		{
			KdPrint(("failed to find NtHeader\r\n"));
			return 0;
		}
		opthdr = pNtHeader->OptionalHeader;
		pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*)ulNtDllModuleBase + opthdr.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress); //�õ�������
		arrayOfFunctionAddresses = (DWORD*)( (BYTE*)ulNtDllModuleBase + pExportTable->AddressOfFunctions);  //��ַ��
		arrayOfFunctionNames = (DWORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNames);         //��������
		arrayOfFunctionOrdinals = (WORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNameOrdinals);

		Base = pExportTable->Base;

		for(x = 0; x < pExportTable->NumberOfFunctions; x++) //��������������ɨ��
		{
			functionName = (char*)( (BYTE*)ulNtDllModuleBase + arrayOfFunctionNames[x]);
			functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; 
			functionAddress = (DWORD)((BYTE*)ulNtDllModuleBase + arrayOfFunctionAddresses[functionOrdinal]);

			if (strlen(functionName) < 2)
			{
				continue;
			}
			RtlInitAnsiString(&ExportTableFunction,functionName);
			RtlAnsiStringToUnicodeString(&UnicodeExportTableFunction,&ExportTableFunction,TRUE);

			pNtosFunc->ulCount = x;
			memcpy(pNtosFunc->ntosFuncInfo[x].FuncName,UnicodeExportTableFunction.Buffer,UnicodeExportTableFunction.Length);
			pNtosFunc->ntosFuncInfo[x].ulAddress = functionAddress - (ULONG)g_pNewSystemKernelModuleBase + g_pOldSystemKernelModuleBase;
			pNtosFunc->ntosFuncInfo[x].ulReloadAddress = functionAddress;
			pNtosFunc->ntosFuncInfo[x].NumberOfFunctions = x;

			RtlFreeUnicodeString(&UnicodeExportTableFunction);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return x;
}

NTSTATUS ReLoadNtos(PDRIVER_OBJECT   DriverObject,DWORD RetAddress)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ulKeAddSystemServiceTable;
	int p;
	HANDLE ThreadHandle;
	PVOID ThreadObject;

	if (g_bDebugOn)
		KdPrint(("ret address:%X\n",RetAddress));

	//Ϊ��¼���ؽ��̽�����
	g_pHideProcessInfo = (PPROCESSINFO)ExAllocatePool(NonPagedPool,(sizeof(PROCESSINFO)+sizeof(SAFESYSTEM_PROCESS_INFORMATION))*120);
	if (!g_pHideProcessInfo)
	{
		KdPrint(("Init ProcessInfo failed"));
		return status;
	}
	memset(g_pHideProcessInfo,0,(sizeof(PROCESSINFO)+sizeof(SAFESYSTEM_PROCESS_INFORMATION))*120);

	//��ȡ�ں�·�����ں˻�ַ
	if (!GetSystemKernelModuleInfo(
		&g_szSystemKernelFilePath,
		&g_pOldSystemKernelModuleBase,
		&g_nSystemKernelModuleSize
		))
	{
		KdPrint(("Get System Kernel Module failed"));
		ExFreePool(g_pHideProcessInfo);
		return status;
	}
	if (g_bDebugOn)
		KdPrint(("%S,%X\n",g_szSystemKernelFilePath,g_pOldSystemKernelModuleBase));

	//Ϊ��¼��־����һ����
	g_pLogDefenseInfo = (PLOGDEFENSE)ExAllocatePool(NonPagedPool,sizeof(LOGDEFENSE)*1024);
	if (!g_pLogDefenseInfo)
	{
		KdPrint(("Init Log Defense Info failed\n"));
		ExFreePool(g_pHideProcessInfo);
		return status;
	}
	memset(g_pLogDefenseInfo,0,sizeof(LOGDEFENSE)*1024);

	if (InitSafeOperationModule(
		DriverObject,
		g_szSystemKernelFilePath,
		g_pOldSystemKernelModuleBase
		))
	{
		KdPrint(("Init Ntos Module Success\r\n"));

		//����һ���ڴ������溯����һЩ��Ϣ
		g_pNtosFuncAddressInfo = (PNTOSFUNCINFO)ExAllocatePool(NonPagedPool,(g_nSystemKernelModuleSize+1024));
		if (!g_pNtosFuncAddressInfo)
		{
			KdPrint(("Init Kernel Function Pool failed\n"));
			ExFreePool(g_pHideProcessInfo);
			ExFreePool(g_pLogDefenseInfo);
			return status;
		}
		memset(g_pNtosFuncAddressInfo,0,(g_nSystemKernelModuleSize+1024));
		if (!GetKernelFunction(g_pNtosFuncAddressInfo))
		{
			KdPrint(("Init Kernel Function Info failed\n"));
			ExFreePool(g_pHideProcessInfo);
			ExFreePool(g_pLogDefenseInfo);
			ExFreePool(g_pNtosFuncAddressInfo);
			return status;
		}
		if (g_bDebugOn)
		{
			for (p=0;p<(int)g_pNtosFuncAddressInfo->ulCount;p++)
			{
				KdPrint(("add:%08x\r\nreload:%80x\r\n%ws\r\n\r\n",
					g_pNtosFuncAddressInfo->ntosFuncInfo[p].ulAddress,
					g_pNtosFuncAddressInfo->ntosFuncInfo[p].ulReloadAddress,
					g_pNtosFuncAddressInfo->ntosFuncInfo[p].FuncName));
			}
		}

		//��ʼ����������api
		ReLoadNtosCALL((PVOID)(&g_fnRPsGetCurrentProcess),L"PsGetCurrentProcess",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		ReLoadNtosCALL((PVOID)(&g_fnRMmIsAddressValid),L"MmIsAddressValid",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
		if (!g_fnRMmIsAddressValid ||
			!g_fnRPsGetCurrentProcess)
		{
			KdPrint(("Init NtosCALL failed\n"));
			ExFreePool(g_pHideProcessInfo);
			ExFreePool(g_pLogDefenseInfo);
			ExFreePool(g_pNtosFuncAddressInfo);
			return status;
		}
		KdPrint(("Init Kernel Function Info Success\n"));
		
		if (HookKiFastCallEntry())
		{
			//ͨ�ſ���
			InitControl();
			status = STATUS_SUCCESS;

			KdPrint(("Init A-Protect Kernel Module Success\r\n"));
		}
		else
			KdPrint(("Init A-Protect Kernel Module Failed"));
	}
	return status;
}

