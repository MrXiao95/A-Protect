#ifndef _FILE_H_
#define _FILE_H_

#include "ntifs.h"
#include "ntos.h"

extern PSERVICE_DESCRIPTOR_TABLE g_pOriginalServiceDescriptorTable;
int ZwWriteFileIndex;  //д�ļ�

extern BOOL g_bDebugOn;
extern BOOL bDisWriteFile;
extern PEPROCESS g_protectEProcess;

//д�ļ�
typedef NTSTATUS (__stdcall* ZWWRITEFILE)(
	__in      HANDLE FileHandle,
	__in_opt  HANDLE Event,
	__in_opt  PIO_APC_ROUTINE ApcRoutine,
	__in_opt  PVOID ApcContext,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in      PVOID Buffer,
	__in      ULONG Length,
	__in_opt  PLARGE_INTEGER ByteOffset,
	__in_opt  PULONG Key
	);

BOOL SystemCallEntryTableHook(
	PUNICODE_STRING FunctionName,
	int *Index,
	DWORD NewFuctionAddress
	);

NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size);

#endif