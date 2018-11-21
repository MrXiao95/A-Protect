#include "Protect.h"


///////////////////////////////////////////////////////////////////////////
//����KiInsertQueueApc�ĵ�ַ��Ӳ���ı��밡~
///////////////////////////////////////////////////////////////////////////
ULONG QueryKiInsertQueueApcAddress()
{
	UNICODE_STRING UnicodeFunctionName;
	ULONG ulKeInsertQueueApc=0;

	ULONG ulKiInsertQueueApc=0;
	WIN_VER_DETAIL WinVer;
	BOOL bIsOK = FALSE;
	PUCHAR i;
	int count=0;
	ULONG ulCodeSize;

	RtlInitUnicodeString(&UnicodeFunctionName,L"KeInsertQueueApc");
	ulKeInsertQueueApc =(ULONG) MmGetSystemRoutineAddress(&UnicodeFunctionName);
	if (ulKeInsertQueueApc)
	{
		ulCodeSize = SizeOfProc((PVOID)ulKeInsertQueueApc);
		if (g_bDebugOn)
			DbgPrint("ulKeInsertQueueApc success:%08x %x\r\n",ulKeInsertQueueApc,ulCodeSize);

		for (i=(PUCHAR)ulKeInsertQueueApc;i < i+ulCodeSize;i++)
		{
			WinVer=GetWindowsVersion();
			switch (WinVer)
			{
			case WINDOWS_VERSION_7_7000:
			case WINDOWS_VERSION_7_7600_UP:
				if (*i == 0xe8)
				{
					count++;
					if (count == 2)  //�ڶ���call��e8��������
					{
						ulKiInsertQueueApc = *(PULONG)(i+1)+(ULONG)(i+5);
						if (MmIsAddressValidEx((PVOID)ulKiInsertQueueApc))
						{
							if (g_bDebugOn)
								DbgPrint("ulKiInsertQueueApc:%08x\r\n",ulKiInsertQueueApc);
							bIsOK = TRUE;
						}
					}
				}
				break;
			case WINDOWS_VERSION_XP:
			case WINDOWS_VERSION_2K3_SP1_SP2:
				if (*i == 0x89 &&
					*(i+2) == 0x28 &&
					*(i+3) == 0xe8)
				{
					i = i+3;

					ulKiInsertQueueApc = *(PULONG)(i+1)+(ULONG)(i+5);
					if (MmIsAddressValidEx((PVOID)ulKiInsertQueueApc))
					{
						if (g_bDebugOn)
							DbgPrint("ulKiInsertQueueApc:%08x\r\n",ulKiInsertQueueApc);
						bIsOK = TRUE;
					}
				}
				break;
			}
			if (bIsOK)
				break;
		}
	}else
		DbgPrint("ulKeInsertQueueApc:%08x\r\n",ulKeInsertQueueApc);

	return ulKiInsertQueueApc;
}
__declspec(naked) VOID KiInsertQueueApcHookZone(,...)
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
		jmp [KiInsertQueueApcRet];
	}
}
__declspec(naked) VOID KeInsertQueueApcHookZone(,...)
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
		jmp [KeInsertQueueApcRet];
	}
}
//IRQL�ȼ�̫�ߣ����Գ�ʼ��ƫ�Ƶ�������ڹ��˺�������ȥ����~��
//for xp/2003
VOID FASTCALL NewKiInsertQueueApc(
	IN PKAPC Apc,
	IN KPRIORITY Increment
	)
{
	KIINSERTQUEUEAPC OldKiInsertQueueApc;

	ULONG ulThread;
	ULONG ulKapcState;
	ULONG ulProcess;
	ULONG ulSystemArgument1;
	ULONG ulCallerEprocess;

	//���б����ջ
	_asm
	{
		pushfd
		pushad
	}
	OldKiInsertQueueApc = (KIINSERTQUEUEAPC)KiInsertQueueApcHookZone;

	//����˳���
	if (!g_bIsInitSuccess)
		goto _FuncTionRet;

	//Ĭ�ϲ�����
	if (!bProtectProcess)
		goto _FuncTionRet;

	if (MmIsAddressValidEx((PVOID)((ULONG)Apc + ulThreadOffset)))
	{
		ulThread = *(ULONG *)((ULONG)Apc + ulThreadOffset);
		if (MmIsAddressValidEx((PVOID)ulThread))
		{
			//���ﲻ����IoThreadToProcess����ȡeprocess
			//��ΪKiInsertQueueApc��IRQL̫�ߣ���IoThreadToProcess������
			if (MmIsAddressValidEx((PVOID)((ULONG)ulThread + ulApcStateOffset)))
			{
				ulKapcState = *(ULONG *)((ULONG)ulThread + ulApcStateOffset);
				if (MmIsAddressValidEx((PVOID)((ULONG)ulKapcState + ulProcessOffset)))
				{
					ulProcess = *(ULONG *)((ULONG)ulKapcState + ulProcessOffset);
					if (MmIsAddressValidEx((PVOID)ulProcess))
					{
						ulSystemArgument1 = *(ULONG *)((ULONG)Apc + ulSystemArgument1Offset);

						if (ulProcess == (ULONG)g_protectEProcess &&
							Increment == 0x2 &&
							(ULONG)Apc == ulSystemArgument1)
						{
							ulCallerEprocess = (ULONG)g_fnRPsGetCurrentProcess();

							//KdPrint(("APC:%08x-%08x",(ULONG)Apc,ulSystemArgument1));
							//KdPrint(("[%d]Caller:%08x-%08x",Increment,ulCallerEprocess,ProtectEProcess));

							//����csrss.exe
							if (ulCallerEprocess ==(ULONG) AttachGuiEProcess)
								goto _FuncTionRet;

							if (g_pLogDefenseInfo->ulCount < 1000)   //��¼����1000�����򲻼�¼��
							{
								g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) g_fnRPsGetCurrentProcess();
								g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID =(ULONG) RPsGetCurrentProcessId();
								g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 1;
								ulLogCount++;
							}

							//���лָ���ջ
							_asm
							{
								popad
								popfd
							}
							return;
						}
					}
				}
			}
		}
	}
_FuncTionRet:
	//���лָ���ջ
	_asm
	{
		popad
		popfd
	}
	OldKiInsertQueueApc(
		Apc,
		Increment
		);
}
BOOLEAN __stdcall NewKeInsertQueueApc(
	__inout PRKAPC Apc,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2,
	__in KPRIORITY Increment
	)
{
	KEINSERTQUEUEAPC OldKeInsertQueueApc;

	ULONG ulThread;
	ULONG ulKapcState;
	ULONG ulProcess;
	ULONG ulCallerEprocess;

	if (!g_bIsInitSuccess)
		goto _FuncTionRet;

	//Ĭ�ϲ�����
	if (!bProtectProcess)
		goto _FuncTionRet;

	if (MmIsAddressValidEx((PVOID)((ULONG)Apc + ulThreadOffset)))
	{
		ulThread = *(ULONG *)((ULONG)Apc + ulThreadOffset);
		if (MmIsAddressValidEx((PVOID)ulThread))
		{
			if (MmIsAddressValidEx((PVOID)((ULONG)ulThread + ulApcStateOffset)))
			{
				ulKapcState = *(ULONG *)((ULONG)ulThread + ulApcStateOffset);

				if (MmIsAddressValidEx((PVOID)((ULONG)ulKapcState + ulProcessOffset)))
				{
					ulProcess = *(ULONG *)((ULONG)ulKapcState + ulProcessOffset);
					if (MmIsAddressValidEx((PVOID)ulProcess))
					{
						if (ulProcess ==(ULONG) g_protectEProcess &&
							Increment == 2 &&
							(ULONG)Apc == (ULONG)SystemArgument1)
						{
							ulCallerEprocess =(ULONG) g_fnRPsGetCurrentProcess();

							//KdPrint(("APC:%08x %x %x\n",(ULONG)Apc,SystemArgument1,SystemArgument2));
							//KdPrint(("[%d]Caller:%08x-%08x\n",Increment,ulCallerEprocess,ProtectEProcess));

							//����csrss.exe
							if (ulCallerEprocess == (ULONG)AttachGuiEProcess)
								goto _FuncTionRet;

							if (g_pLogDefenseInfo->ulCount < 1000)   //��¼����1000�����򲻼�¼��
							{
								g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess = (ULONG)g_fnRPsGetCurrentProcess();
								g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID =(ULONG) RPsGetCurrentProcessId();
								g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 1;
								ulLogCount++;
							}
							return FALSE;
						}
					}
				}
			}
		}
	}
_FuncTionRet:

	OldKeInsertQueueApc = (KEINSERTQUEUEAPC)KeInsertQueueApcHookZone;
	return OldKeInsertQueueApc(
		Apc,
		SystemArgument1,
		SystemArgument2,
		Increment
		);
}
BOOL ProtectCode()
{
	BOOL bRetOK = FALSE;
	PUCHAR ulKiInsertQueueApc;
	PUCHAR ulKeInsertQueueApc;
	ULONG ulReloadKiInsertQueueApc;
	ULONG ulReloadKeInsertQueueApc;
	
	KiInsertQueueApcHooked = FALSE;
	KeInsertQueueApcHooked = FALSE;

	//RPsGetCurrentProcess = ReLoadNtosCALL(L"PsGetCurrentProcess",SystemKernelModuleBase,ImageModuleBase);
	ReLoadNtosCALL((PVOID)(&RPsGetCurrentProcessId),L"PsGetCurrentProcessId",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	//��ʼ��ƫ��
	WinVer = GetWindowsVersion();
	switch (WinVer)
	{
	case WINDOWS_VERSION_2K3_SP1_SP2:
		ulThreadOffset = 0x008;
		ulApcStateOffset = 0x028;
		ulProcessOffset = 0x10;
		ulSystemArgument1Offset = 0x24;
		break;
	case WINDOWS_VERSION_XP:
		ulThreadOffset = 0x008;
		ulApcStateOffset = 0x034;
		ulProcessOffset = 0x10;
		ulSystemArgument1Offset = 0x24;
		break;
	case WINDOWS_VERSION_7_7600_UP:
	case WINDOWS_VERSION_7_7000:
		ulThreadOffset = 0x008;
		ulApcStateOffset = 0x040;
		ulProcessOffset = 0x10;
		ulSystemArgument1Offset = 0x24;
		break;
	}
	if (WinVer == WINDOWS_VERSION_2K3_SP1_SP2 ||
		WinVer == WINDOWS_VERSION_XP)
	{
		//�õ�reload�ĵ�ַ
		ulKiInsertQueueApc =(PUCHAR) QueryKiInsertQueueApcAddress();
		if (ulKiInsertQueueApc &&
			g_fnRPsGetCurrentProcess &&
			RPsGetCurrentProcessId)
		{
			ulReloadKiInsertQueueApc = (ULONG)(ulKiInsertQueueApc - g_pOldSystemKernelModuleBase + (ULONG)g_pNewSystemKernelModuleBase);
			if (MmIsAddressValidEx((PVOID)ulReloadKiInsertQueueApc))
			{
				//�ţ��Ѿ���hook����
				if (*ulKiInsertQueueApc == 0xE9)
				{
					//��ȡ��hook����ת��ַ
					ulKiInsertQueueApc =(PUCHAR) (*(PULONG)((ULONG)ulKiInsertQueueApc+1)+(ULONG)((ULONG)ulKiInsertQueueApc+5));
				}
				//hook KiInsertQueueApc�������е��ö���reload��KiInsertQueueApc
				bRetOK = HookFunctionByHeaderAddress(
					ulReloadKiInsertQueueApc,
					(DWORD)ulKiInsertQueueApc,
					KiInsertQueueApcHookZone,
					&KiInsertQueueApcPatchCodeLen,
					&KiInsertQueueApcRet
					);
				if (bRetOK)
				{
					//hook ulReloadKiInsertQueueApc�������е��ö���NewKiInsertQueueApc
					bRetOK = HookFunctionByHeaderAddress(
						(DWORD)NewKiInsertQueueApc,
						ulReloadKiInsertQueueApc,
						KiInsertQueueApcHookZone,
						&KiInsertQueueApcPatchCodeLen,
						&KiInsertQueueApcRet
						);
					if (bRetOK)
					{
						KiInsertQueueApcHooked = TRUE;
						return KiInsertQueueApcHooked;
					}
				}
			}
		}

	}else if (WinVer == WINDOWS_VERSION_7_7000 || WinVer == WINDOWS_VERSION_7_7600_UP)
	{
		//hook KeInsertQueueApc
		ulKeInsertQueueApc = (PUCHAR)GetSystemRoutineAddress(0,"KeInsertQueueApc");
		if (ulKeInsertQueueApc &&
			g_fnRPsGetCurrentProcess)
		{
			ulReloadKeInsertQueueApc = (ULONG)((ULONG)ulKeInsertQueueApc - g_pOldSystemKernelModuleBase + (ULONG)g_pNewSystemKernelModuleBase);
			if (MmIsAddressValidEx((PVOID)ulReloadKeInsertQueueApc))
			{
				//�ţ��Ѿ���hook����
				if (*ulKeInsertQueueApc == 0xE9)
				{
					//��ȡ��hook����ת��ַ
					ulKeInsertQueueApc = (PUCHAR)(*(PULONG)((ULONG)ulKeInsertQueueApc+1)+(ULONG)((ULONG)ulKeInsertQueueApc+5));
				}
				bRetOK = HookFunctionByHeaderAddress(
					ulReloadKeInsertQueueApc,
					(DWORD)ulKeInsertQueueApc,
					KeInsertQueueApcHookZone,
					&KeInsertQueueApcPatchCodeLen,
					&KeInsertQueueApcRet
					);
				if (bRetOK)
				{
					bRetOK = HookFunctionByHeaderAddress(
						(DWORD)NewKeInsertQueueApc,
						ulReloadKeInsertQueueApc,
						KeInsertQueueApcHookZone,
						&KeInsertQueueApcPatchCodeLen,
						&KeInsertQueueApcRet
						);
					if (bRetOK)
					{
						KeInsertQueueApcHooked = TRUE;
						return KeInsertQueueApcHooked;
					}
				}
			}
		}
	}
	return FALSE;
}
/*
PSYSTEM_HANDLE_INFORMATION_EX GetInfoTable(OUT PULONG nSize)
{
	PVOID Buffer;
	NTSTATUS status;
	Buffer =ExAllocatePool(PagedPool,0x1000);
	status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, 0x1000, nSize);
	ExFreePool(Buffer);
	if(status == STATUS_INFO_LENGTH_MISMATCH)
	{
		Buffer = ExAllocatePool(NonPagedPool, *nSize);
		status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, *nSize, NULL);
		if(NT_SUCCESS(status))
		{
			return (PSYSTEM_HANDLE_INFORMATION_EX)Buffer;
		}
	}
	return (PSYSTEM_HANDLE_INFORMATION_EX)0;
}
HANDLE GetCsrPid(VOID)
{
	HANDLE Process,hObject;
	HANDLE CsrId = (HANDLE)0;
	OBJECT_ATTRIBUTES obj;
	CLIENT_ID cid;
	UCHAR Buff[0x100];
	POBJECT_NAME_INFORMATION ObjName = (PVOID)&Buff;
	PSYSTEM_HANDLE_INFORMATION_EX Handles;
	ULONG i;
	ULONG nSize;

	Handles = GetInfoTable(&nSize);
	if(!Handles)
	{
		return CsrId;
	}
	for(i = 0; i < Handles->NumberOfHandles; i++)
	{

		if(Handles->Information[i].ObjectTypeNumber == 21)
		{
			InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			cid.UniqueProcess = (HANDLE)Handles->Information[i].ProcessID;
			cid.UniqueThread  = 0;
			if(NT_SUCCESS(NtOpenProcess(&Process, PROCESS_DUP_HANDLE, &obj, &cid)))
			{
				if(NT_SUCCESS(ZwDuplicateObject(Process, (HANDLE)Handles->Information[i].Handle, NtCurrentProcess(), &hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
				{
					if(NT_SUCCESS(ZwQueryObject(hObject, ObjectNameInformation, ObjName, 0x100, NULL)))
					{
						//!!!!!
						//win7��û��"\\Windows\\ApiPort"
						if(ObjName->Name.Buffer && !wcsncmp(L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20))
						{
							CsrId = (HANDLE)Handles->Information[i].ProcessID;
							if (DebugOn)
								KdPrint(("Csrss.exe PID = %d", CsrId));
						}
					}
					ZwClose(hObject);
				}
				ZwClose(Process);
			}
		}
	}
	ExFreePool(Handles);
	return CsrId;
}
*/