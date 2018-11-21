#ifndef _WORK_QUEUE_H_
#define _WORK_QUEUE_H_

#include "ntifs.h"
#include "InitWindowsVersion.h"
#include "ntos.h"
//---------------------------------------------------------------------------------------
//���������߳�
//---------------------------------------------------------------------------------------
typedef struct _WORKQUEUE_INFORMATION {          //WORKQUEUE_INFORMATION
	ULONG ulEthread;
	PUCHAR ulBasePriority;
	ULONG ulWorkerRoutine;
	CHAR lpszModule[256];                    //
	ULONG SuspendCount;               //��ͣ����
} WORKQUEUE_INFORMATION, *PWORKQUEUE_INFORMATION;

typedef struct _WORKQUEUE {          //���������߳�
	ULONG ulCount;
	WORKQUEUE_INFORMATION WorkQueueInfo[1];
} WORKQUEUE, *PWORKQUEUE;

PWORKQUEUE WorkQueueThread;

extern PEPROCESS g_systemEProcess;
extern BOOL g_bDebugOn;

VOID IniOffsetObject();

PETHREAD NTAPI GetNextProcessThread(
	IN PEPROCESS Process,
	IN PETHREAD Thread OPTIONAL,
	IN BOOL bIsQueryThread
	);

BOOL IsAddressInSystem(
	ULONG ulDriverBase,
	ULONG *ulSysModuleBase,
	ULONG *ulSize,
	char *lpszSysModuleImage
	);

#endif