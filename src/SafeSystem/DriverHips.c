#include "DriverHips.h"

__declspec(naked) BOOLEAN SeSinglePrivilegeCheckHookZone(,...)
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
		jmp [SeSinglePrivilegeCheckRet];
	}
}
//Ȩ�޼���ʱ�򷵻�ʧ�����ﵽ��ֹ��������
BOOLEAN __stdcall NewSeSinglePrivilegeCheck(
	__in  LUID PrivilegeValue,
	__in  KPROCESSOR_MODE PreviousMode
	)
{
	ULONG ulPage;

	if (!g_bIsInitSuccess)
		goto _FunctionRet;

	//ȡ���ص�ַ
	_asm
	{
		mov eax,dword ptr[ebp+4]
		mov ulPage,eax
	}
	if (g_fnRPsGetCurrentProcess() == g_protectEProcess)
	{
		goto _FunctionRet;
	}
	//�����ں˰�ȫģʽ�����жϵ���Reload��ĵ�ַ
	if (g_bKernelSafeModule){
		if (ulPage >= ulReloadNtLoadDriverBase && ulPage <= ulReloadNtLoadDriverBase+ulNtLoadDriverSize)
			return FALSE;

		if (ulPage >= ulReloadZwSetSystemInformationBase && ulPage <= ulReloadZwSetSystemInformationBase+ulZwSetSystemInformationSize)
			return FALSE;
	}else{

		//û�п����ں˰�ȫģʽ�����жϵ���ԭʼ��ַ
		if (ulPage >= ulNtLoadDriverBase && ulPage <= ulNtLoadDriverBase+ulNtLoadDriverSize)
			return FALSE;

		if (ulPage >= ulZwSetSystemInformationBase && ulPage <= ulZwSetSystemInformationBase+ulZwSetSystemInformationSize)
			return FALSE;
	}

_FunctionRet:
	OldSeSinglePrivilegeCheck = (SeSinglePrivilegeCheck_1)SeSinglePrivilegeCheckHookZone;
	return OldSeSinglePrivilegeCheck(
		PrivilegeValue,
		PreviousMode
		);
}

//��ֹ��������
NTSTATUS DisableDriverLoading()
{
	int bRet;

	ulZwSetSystemInformationBase = GetSystemRoutineAddress(1,L"ZwSetSystemInformation");
	ulNtLoadDriverBase = GetSystemRoutineAddress(1,L"ZwLoadDriver");
	if (ulNtLoadDriverBase &&
		ulZwSetSystemInformationBase)
	{
		ulNtLoadDriverSize = SizeOfProc((PVOID)ulNtLoadDriverBase);
		ulZwSetSystemInformationSize = SizeOfProc((PVOID)ulZwSetSystemInformationBase);
	}

	ulSeSinglePrivilegeCheck = GetSystemRoutineAddress(1,L"SeSinglePrivilegeCheck");
	if (!ulSeSinglePrivilegeCheck ||
		!ulNtLoadDriverBase ||
		!ulZwSetSystemInformationBase)
	{
		return STATUS_UNSUCCESSFUL;
	}
	//����������ں˰�ȫģʽ����Ҫ����reload��ĵ�ַ����Ȼ�жϲ���
	ulReloadNtLoadDriverBase = (ULONG)(ulNtLoadDriverBase - g_pOldSystemKernelModuleBase+(ULONG)g_pNewSystemKernelModuleBase);
	ulReloadZwSetSystemInformationBase = (ULONG)(ulZwSetSystemInformationBase - g_pOldSystemKernelModuleBase+(ULONG)g_pNewSystemKernelModuleBase);

	ulReloadSeSinglePrivilegeCheck = (ULONG)(ulSeSinglePrivilegeCheck - g_pOldSystemKernelModuleBase+(ULONG)g_pNewSystemKernelModuleBase);

	//hook reload SeSinglePrivilegeCheck

	bRet = HookFunctionByHeaderAddress(ulReloadSeSinglePrivilegeCheck,ulSeSinglePrivilegeCheck,SeSinglePrivilegeCheckHookZone,&SeSinglePrivilegeCheckPatchCodeLen,&SeSinglePrivilegeCheckRet);
	if(bRet)
	{
		bRet = FALSE;
		bRet = HookFunctionByHeaderAddress(
			(DWORD)NewSeSinglePrivilegeCheck,
			ulReloadSeSinglePrivilegeCheck,
			SeSinglePrivilegeCheckHookZone,
			&SeSinglePrivilegeCheckPatchCodeLen,
			&SeSinglePrivilegeCheckRet
			);
		if (bRet)
		{
			SeSinglePrivilegeCheckHooked = TRUE;
			//DbgPrint("hook SeSinglePrivilegeCheck success\n");
		}
	}
	return STATUS_SUCCESS;
}
//������������
NTSTATUS EnableDriverLoading()
{
	if (SeSinglePrivilegeCheckHooked == TRUE)
	{
		SeSinglePrivilegeCheckHooked = FALSE;
		UnHookFunctionByHeaderAddress((DWORD)ulReloadSeSinglePrivilegeCheck,SeSinglePrivilegeCheckHookZone,SeSinglePrivilegeCheckPatchCodeLen);
		UnHookFunctionByHeaderAddress((DWORD)ulSeSinglePrivilegeCheck,SeSinglePrivilegeCheckHookZone,SeSinglePrivilegeCheckPatchCodeLen);
	}
	return STATUS_SUCCESS;
}
//***************************************
//����һ��ImageNotify������ص�����
//***************************************
VOID ImageNotify(
	PUNICODE_STRING  FullImageName,
	HANDLE  ProcessId,
	PIMAGE_INFO  ImageInfo
	)
{
	//�ų�������ģ��ļ���
	if (ProcessId != (HANDLE)0 || PsGetCurrentProcessId() != (HANDLE)4)
	{
		return;
	}
	//����Ƿ��Ǽ�������
	if (ImageInfo->ImageBase < (PVOID)MmUserProbeAddress)
	{
		return;
	}
	//���UNICODE_STRING�Ƿ���Է���
	if (!ValidateUnicodeString(FullImageName))
	{
		return;
	}
	//KdPrint(("%d:%08x --> %ws\r\n",PsGetCurrentProcessId(),ImageInfo->ImageBase,FullImageName->Buffer));

	if (g_pLogDefenseInfo->ulCount < 1000 &&
		ulLogCount < 1000)   //��¼����1000�����򲻼�¼��
	{
		g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID = ImageInfo->ImageSize;
		g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 6;  //��������
		g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) ImageInfo->ImageBase;  //������ַ

		memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));
		memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents));

		SafeCopyMemory(FullImageName->Buffer,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,FullImageName->Length);
		ulLogCount++;
	}
	return;
}