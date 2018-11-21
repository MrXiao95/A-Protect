#ifndef _ANTI_INLINE_HOOK_H_
#define _ANTI_INLINE_HOOK_H_

#include "ntifs.h"
//#include "InlineHook.h"
#include "ntos.h"
#include "ldasm.h"
#include "libdasm.h"

DWORD JmpFunctionAddress;

ULONG ulRunAddress;  //一共执行了多少代码

int HookFunctionProcessPatchCodeLen;
PVOID HookFunctionProcessRet;

ULONG HookFunctionAddress;

extern BYTE *g_pNewSystemKernelModuleBase;
extern ULONG g_pOldSystemKernelModuleBase;
extern ULONG g_nSystemKernelModuleSize;

extern ULONG g_ulMyDriverBase;
extern ULONG g_ulMyDriverSize;

extern BOOL bKrnlPDBSuccess;

ULONG GetSystemRoutineAddress(
	int IntType,
	PVOID lpwzFunction
	);

unsigned long __fastcall GetFunctionCodeSize(void *Proc);

#endif