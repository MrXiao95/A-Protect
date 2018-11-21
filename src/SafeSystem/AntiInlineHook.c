#include "AntiInlineHook.h"

/*
__declspec(naked) VOID __stdcall NewHookFunctionProcess()
{
	_asm
	{
		jmp [ulReloadAddress];   //直接跳到我reload的函数地址去~~日死他
	}
}
*/
//在这里是摆设而已！
__declspec(naked) VOID HookFunctionProcessHookZone(,...)
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
		jmp [JmpFunctionAddress];
	}
}
/*

通过Hook跳转到reload函数来对抗inline hook

*/
VOID AntiInlineHook(ULONG ulRealBase,ULONG ulModuleBase,ULONG ulReloadModuleBase)
{
	ULONG ulTemp = 0;
	PUCHAR p;
	BOOL bIsHooked = FALSE;
	INSTRUCTION	Inst;
	INSTRUCTION	Instb;
	BOOL bInit = FALSE;
	ULONG ulHookFunctionAddress;
	ULONG JmpReloadFunctionAddress;
	int i=0;
	BOOL bIsCallHook = FALSE;
	__try
	{
		
// 		JmpFunctionAddress = GetSystemRoutineAddress(1,FunctionName);  //得到函数地址
// 
// 		if (DebugOn)
// 			KdPrint(("Get System Routine Address:%ws:%08x\r\n",FunctionName,JmpFunctionAddress));

		JmpFunctionAddress = ulRealBase;
		JmpReloadFunctionAddress = JmpFunctionAddress - ulModuleBase + ulReloadModuleBase;

		if (MmIsAddressValidEx((PVOID)JmpFunctionAddress) &&
			MmIsAddressValidEx((PVOID)JmpReloadFunctionAddress))
		{
			if (GetFunctionCodeSize((PVOID)JmpFunctionAddress) == GetFunctionCodeSize((PVOID)JmpReloadFunctionAddress) &&
				memcmp((PVOID)JmpFunctionAddress,(PVOID)JmpReloadFunctionAddress,GetFunctionCodeSize((PVOID)JmpFunctionAddress)) != 0)
			{
				//KdPrint(("---->%s:%08x",functionName,ulOldAddress));
				//开始扫描hook
				for (p=(PUCHAR)JmpFunctionAddress ;p< (PUCHAR)JmpFunctionAddress+GetFunctionCodeSize((PVOID)JmpFunctionAddress); p++)
				{
					//是否结束？
					if (*p == 0xcc ||
						*p == 0xc2)
					{
						break;
					}
					ulTemp = 0;
					get_instruction(&Inst,p,MODE_32);
					switch (Inst.type)
					{
					case INSTRUCTION_TYPE_JMP:
						if(Inst.opcode==0xFF&&Inst.modrm==0x25)
						{
							//DIRECT_JMP
							ulTemp = Inst.op1.displacement;
						}
						else if (Inst.opcode==0xEB)
						{
							ulTemp = (ULONG)(p+Inst.op1.immediate);
						}
						else if(Inst.opcode==0xE9)
						{
							//RELATIVE_JMP;
							ulTemp = (ULONG)(p+Inst.op1.immediate);
						}
						break;
					case INSTRUCTION_TYPE_CALL:
						if(Inst.opcode==0xFF&&Inst.modrm==0x15)
						{
							//DIRECT_CALL
							ulTemp = Inst.op1.displacement;
						}
						else if (Inst.opcode==0x9A)
						{
							ulTemp = (ULONG)(p+Inst.op1.immediate);
						}
						else if(Inst.opcode==0xE8)
						{
							//RELATIVE_CALL;
							ulTemp = (ULONG)(p+Inst.op1.immediate);
						}
						bIsCallHook = TRUE;
						break;
					case INSTRUCTION_TYPE_PUSH:
						if(!MmIsAddressValidEx((PVOID)(p)))
						{
							break;
						}
						get_instruction(&Instb,(BYTE*)(p),MODE_32);
						if(Instb.type == INSTRUCTION_TYPE_RET)
						{
							//StartAddress+len-inst.length-instb.length;
							ulTemp = Instb.op1.displacement;
						}
						break;
					}
					if (ulTemp &&
						MmIsAddressValidEx((PVOID)ulTemp))
					{
						if (ulTemp > g_pOldSystemKernelModuleBase &&
							ulTemp < g_pOldSystemKernelModuleBase+g_nSystemKernelModuleSize)   //太近的跳也不是
						{
							continue;
						}
						//ulTemp也不能小于 SystemKernelModuleBase
						if (ulTemp < g_pOldSystemKernelModuleBase)
						{
							continue;
						}
						if (*(ULONG *)ulTemp == 0x00000000 ||
							*(ULONG *)ulTemp == 0x00000005)
						{
							continue;
						}
						if (ulTemp > g_ulMyDriverBase &&
							ulTemp < g_ulMyDriverBase + g_ulMyDriverSize)
						{
							if (g_bDebugOn)
								KdPrint(("my hook, denied access！"));
							return;
						}
						if (ulTemp > (ULONG)g_pNewSystemKernelModuleBase &&
							ulTemp < (ULONG)g_pNewSystemKernelModuleBase + g_nSystemKernelModuleSize)
						{
							if (g_bDebugOn)
								KdPrint(("new kernel hook, denied access！"));
							return;
						}
						//如果是call hook，就Hook当前地址的头部吧~~！！！
						if (bIsCallHook)
						{
							if (g_bDebugOn)
								KdPrint(("the hook is a call hook!\n"));

							HookFunctionByHeaderAddress(
								(DWORD)JmpReloadFunctionAddress,
								JmpFunctionAddress,
								(PVOID)HookFunctionProcessHookZone,
								&HookFunctionProcessPatchCodeLen,
								&HookFunctionProcessRet
								);
							return;
						}
						ulRunAddress = (ULONG)p - (ULONG)JmpFunctionAddress;   //执行到达hook点的时候，一共执行了多少长度的代码
						JmpReloadFunctionAddress = JmpReloadFunctionAddress + ulRunAddress;     //跳过前面执行的代码，继续往下执行 

						if (g_bDebugOn)
							KdPrint(("found hook---->%08x:%08x-%x-%08x",ulTemp + 0x5,p,ulRunAddress,JmpReloadFunctionAddress));


						//得到正确的跳转地址，直接hook人家的hook函数的头部，然后让它跳到reload代码的ulReloadAddress地址处继续执行剩下的代码，这样就绕过hook鸟
						ulTemp = ulTemp + 0x5;

						HookFunctionByHeaderAddress(
							(DWORD)JmpReloadFunctionAddress,
							ulTemp,
							(PVOID)HookFunctionProcessHookZone,
							&HookFunctionProcessPatchCodeLen,
							&HookFunctionProcessRet
							);
					}
				}
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	return;
}