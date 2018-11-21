#ifndef _DRIVER_HIPS_H_
#define _DRIVER_HIPS_H_

#include "ntifs.h"
#include "ntos.h"
#include "ldasm.h"

typedef BOOLEAN (__stdcall *SeSinglePrivilegeCheck_1)(
	__in  LUID PrivilegeValue,
	__in  KPROCESSOR_MODE PreviousMode
	);

SeSinglePrivilegeCheck_1 OldSeSinglePrivilegeCheck;

int SeSinglePrivilegeCheckPatchCodeLen = 0;
PVOID SeSinglePrivilegeCheckRet;

int SeSinglePrivilegeCheckHooked = FALSE;

ULONG ulNtLoadDriverBase,ulReloadNtLoadDriverBase,ulNtLoadDriverSize;
ULONG ulZwSetSystemInformationBase,ulReloadZwSetSystemInformationBase,ulZwSetSystemInformationSize;

ULONG ulSeSinglePrivilegeCheck;
ULONG ulReloadSeSinglePrivilegeCheck;

extern BYTE *g_pNewSystemKernelModuleBase;
extern ULONG g_pOldSystemKernelModuleBase;
extern ULONG g_nSystemKernelModuleSize;

extern PEPROCESS g_protectEProcess;

extern BOOL g_bKernelSafeModule;

ULONG GetSystemRoutineAddress(
	int IntType,
	PVOID lpwzFunction
	);

NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size);

#endif