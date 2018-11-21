#ifndef _KERNEL_HOOK_CHECK_H
#define _KERNEL_HOOK_CHECK_H

#include "ntifs.h"
#include <ntimage.h>
#include "ntos.h"
#include "ldasm.h"
#include "libdasm.h"
#include "fixrelocation.h"

extern PSERVICE_DESCRIPTOR_TABLE g_pOriginalServiceDescriptorTable;

#define DEEP_LEN 0x03

#define NtosModule 0
#define SelectModule 1

extern WCHAR *g_szSystemKernelFilePath;
extern BYTE *g_pNewSystemKernelModuleBase;
extern ULONG g_pOldSystemKernelModuleBase;
extern ULONG g_nSystemKernelModuleSize;

typedef struct _INLINEHOOKINFO_INFORMATION {          //INLINEHOOKINFO_INFORMATION
	ULONG ulHookType;
	ULONG ulMemoryFunctionBase;    //���ҹ���ַ
	ULONG ulRealFunctionBase;      //ԭʼ��ַ
	ULONG ulMemoryHookBase;        //HOOK ��ַ
	CHAR lpszFunction[256];
	CHAR lpszHookModuleImage[256];
	ULONG ulHookModuleBase;
	ULONG ulHookModuleSize;

	WCHAR lpwzRealModuleImage[256];   //ԭʼģ��
	ULONG ulRealModuleBase;

} INLINEHOOKINFO_INFORMATION, *PINLINEHOOKINFO_INFORMATION;

typedef struct _INLINEHOOKINFO {          //InlineHook
	ULONG ulCount;
	INLINEHOOKINFO_INFORMATION InlineHook[1];
} INLINEHOOKINFO, *PINLINEHOOKINFO;

PINLINEHOOKINFO InlineHookInfo;

PINLINEHOOKINFO SelectModuleInlineHookInfo;

extern BOOL g_bDebugOn;
extern ULONG ulWin32kBase;
extern PDRIVER_OBJECT g_pDriverObject;

ULONG ulNtDllModuleBase;
int IntHookCount;

extern BOOL bKrnlPDBSuccess;  //�Ƿ��ring3���ȡ��pdb

HANDLE MapFileAsSection(
	PUNICODE_STRING FileName,
	PVOID *ModuleBase
	);

ULONG GetSystemRoutineAddress(
	int IntType,
	PVOID lpwzFunction
	);

BOOL IsAddressInSystem(
	ULONG ulDriverBase,
	ULONG *ulSysModuleBase,
	ULONG *ulSize,
	char *lpszSysModuleImage
	);

PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID ImageBase);

//ULONG GetEatHook(ULONG ulOldAddress,int x,ULONG ulSystemKernelModuleBase,ULONG ulSystemKernelModuleSize);

BOOL EatHookCheck(ULONG ulModuleBase,PINLINEHOOKINFO InlineHookInfo,PNTOSFUNCINFO FuncAddressInfo);

BOOL IsFuncInInitSection(ULONG ulFuncBase,ULONG ulSize);

VOID WcharToChar(__in WCHAR *wzFuncName,__out CHAR *FuncName);

PVOID GetKernelModuleBase(PDRIVER_OBJECT DriverObject,char *KernelModuleName);

#endif