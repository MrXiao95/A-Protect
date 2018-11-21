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
//权限检查的时候返回失败来达到禁止加载驱动
BOOLEAN __stdcall NewSeSinglePrivilegeCheck(
	__in  LUID PrivilegeValue,
	__in  KPROCESSOR_MODE PreviousMode
	)
{
	ULONG ulPage;

	if (!g_bIsInitSuccess)
		goto _FunctionRet;

	//取返回地址
	_asm
	{
		mov eax,dword ptr[ebp+4]
		mov ulPage,eax
	}
	if (g_fnRPsGetCurrentProcess() == g_protectEProcess)
	{
		goto _FunctionRet;
	}
	//开启内核安全模式，则判断的是Reload后的地址
	if (g_bKernelSafeModule){
		if (ulPage >= ulReloadNtLoadDriverBase && ulPage <= ulReloadNtLoadDriverBase+ulNtLoadDriverSize)
			return FALSE;

		if (ulPage >= ulReloadZwSetSystemInformationBase && ulPage <= ulReloadZwSetSystemInformationBase+ulZwSetSystemInformationSize)
			return FALSE;
	}else{

		//没有开启内核安全模式，则判断的是原始地址
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

//禁止驱动加载
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
	//如果开启了内核安全模式，则要计算reload后的地址，不然判断不对
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
//允许驱动加载
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
//创建一个ImageNotify保存加载的驱动
//***************************************
VOID ImageNotify(
	PUNICODE_STRING  FullImageName,
	HANDLE  ProcessId,
	PIMAGE_INFO  ImageInfo
	)
{
	//排除非驱动模块的加载
	if (ProcessId != (HANDLE)0 || PsGetCurrentProcessId() != (HANDLE)4)
	{
		return;
	}
	//检查是否是加载驱动
	if (ImageInfo->ImageBase < (PVOID)MmUserProbeAddress)
	{
		return;
	}
	//检查UNICODE_STRING是否可以访问
	if (!ValidateUnicodeString(FullImageName))
	{
		return;
	}
	//KdPrint(("%d:%08x --> %ws\r\n",PsGetCurrentProcessId(),ImageInfo->ImageBase,FullImageName->Buffer));

	if (g_pLogDefenseInfo->ulCount < 1000 &&
		ulLogCount < 1000)   //记录超过1000条，则不记录。
	{
		g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID = ImageInfo->ImageSize;
		g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 6;  //驱动加载
		g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess =(ULONG) ImageInfo->ImageBase;  //驱动基址

		memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));
		memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents));

		SafeCopyMemory(FullImageName->Buffer,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,FullImageName->Length);
		ulLogCount++;
	}
	return;
}