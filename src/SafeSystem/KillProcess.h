#ifndef _KILL_PROCESS_H_
#define _KILL_PROCESS_H_

#include "ntifs.h"
//#include "stdlib.h"
#include "InitWindowsVersion.h"
#include "ntos.h"
//#include "Strsafe.h"

#define MM_TAG 'INFO'

extern BYTE *g_pNewSystemKernelModuleBase;
extern ULONG g_pOldSystemKernelModuleBase;
extern ULONG g_nSystemKernelModuleSize;

extern BOOL g_bDebugOn;

typedef NTSTATUS (*PSPTERMINATETHREADBYPOINTER_K)( PETHREAD,NTSTATUS,BOOLEAN);   //2003,vista,2008об
PSPTERMINATETHREADBYPOINTER_K PspTerminateThreadByPointer_K;

typedef NTSTATUS (*PSPTERMINATETHREADBYPOINTER_XP)( PETHREAD,NTSTATUS);             //xpоб
PSPTERMINATETHREADBYPOINTER_XP PspTerminateThreadByPointer_XP;

ULONG ThreadProc;
ULONG ThreadListHead;
ULONG ActiveProcessLinksOffset;
ULONG UniqueProcessIdOffset;
ULONG processpid;

NTSTATUS KillProcess(
	ULONG ulEprocess
	);

#endif