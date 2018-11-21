#ifndef _SYSMODULE_H_
#define _SYSMODULE_H_

#include "ntifs.h"
#include "ntos.h"
#include "DpcTimer.h"

#define MAX_IRP_MJ_DISPATCH 28  //�����ǩ��10��

#define DriMagic 0x2c //"DRIV"��־��DriverObject�Ĳ�ֵ
//////////////////////////////////////////////////////////////////////////////////////

typedef struct _SYSINFO_INFORMATION {          //SYSINFO_INFORMATION
	ULONG ulSysBase;
	ULONG SizeOfImage;
	ULONG DriverObject;

	WCHAR lpwzFullSysName[256];
	WCHAR lpwzBaseSysName[256];
	WCHAR lpwzServiceName[256];

	int  IntHideType;     //�Ƿ�����

} SYSINFO_INFORMATION, *PSYSINFO_INFORMATION;
typedef struct _SYSINFO {          //sysmodule
	ULONG ulCount;
	SYSINFO_INFORMATION SysInfo[1];
} SYSINFO, *PSYSINFO;
PSYSINFO SysModuleInfo;

////////////////////////////////////////////////////////////////////////////////////////////
//����ṹ����������������driver_object
typedef struct _DRIVER_OBJECT_STRUCT_INFORMATION {
	ULONG ulDriverObject;
} DRIVER_OBJECT_STRUCT_INFORMATION, *PDRIVER_OBJECT_STRUCT_INFORMATION;

typedef struct _DRIVER_OBJECT_STRUCT {
	ULONG ulCount;
	DRIVER_OBJECT_STRUCT_INFORMATION Struct[1];
} DRIVER_OBJECT_STRUCT, *PDRIVER_OBJECT_STRUCT;
////////////////////////////////////////////////////////////////////////////////////////////

extern BOOL g_bDebugOn;


ULONG ulSearchStart;
ULONG ulSearchEnd;

BOOL bIsRealSearch;

NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size);

PKDDEBUGGER_DATA64 KdGetDebuggerDataBlock();

BOOLEAN ValidateUnicodeString(
	PUNICODE_STRING usStr
	);

BOOL MmIsAddressRangeValid(
	IN PVOID Address,
	IN ULONG Size
	);

NTSTATUS LookupProcessByName(
	IN PCHAR pcProcessName,
	OUT PEPROCESS *pEprocess
	);

#endif