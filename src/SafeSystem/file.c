#include "file.h"

NTSTATUS __stdcall NewZwWriteFile(
	__in      HANDLE FileHandle,
	__in_opt  HANDLE Event,
	__in_opt  PIO_APC_ROUTINE ApcRoutine,
	__in_opt  PVOID ApcContext,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in      PVOID Buffer,
	__in      ULONG Length,
	__in_opt  PLARGE_INTEGER ByteOffset,
	__in_opt  PULONG Key
	)
{
	ZWWRITEFILE OldZwWriteFile;
	NTSTATUS status;
	PFILE_OBJECT FileObject;
	BOOL bInit = FALSE;
	ULONG WriteSize = 0;

	//���A���˳���
	if (!g_bIsInitSuccess)
		goto _FunctionRet;

	if (g_fnRPsGetCurrentProcess){
		if (g_fnRPsGetCurrentProcess() == g_protectEProcess){
			goto _FunctionRet;
		}
	}
	//�����ֹ��д�ļ�
	if (bDisWriteFile == FALSE){
		return STATUS_UNSUCCESSFUL;
	}
_FunctionRet:

	if (MmIsAddressValidEx((PVOID)g_pOriginalServiceDescriptorTable->ServiceTable[ZwWriteFileIndex]))
	{
		OldZwWriteFile =(ZWWRITEFILE) g_pOriginalServiceDescriptorTable->ServiceTable[ZwWriteFileIndex];
	}else
		OldZwWriteFile = (ZWWRITEFILE)KeServiceDescriptorTable->ServiceTable[ZwWriteFileIndex];

	return OldZwWriteFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		Buffer,
		Length,
		ByteOffset,
		Key
		);
}
BOOL InitWriteFile()
{
		UNICODE_STRING UnicdeFunction;

		//RtlInitUnicodeString(&UnicdeFunction,L"ZwWriteFile");
		if (SystemCallEntryTableHook(
			(PUNICODE_STRING)("ZwWriteFile"),
			&ZwWriteFileIndex,
			(DWORD)NewZwWriteFile) == TRUE)
		{
			if (g_bDebugOn)
				KdPrint(("Create Control Thread success 4\r\n"));
		}
		return TRUE;
}