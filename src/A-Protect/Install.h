#define WIN32_LEAN_AND_MEAN
#include "stdafx.h"
#include <windows.h>
#include <powrprof.h>
#include <cstdlib>
#include <stdio.h>
#include <Commctrl.h>
#include <winsvc.h> 
#include <Mscat.h>
#include <WinTrust.h>
#include <SoftPub.h>
#pragma comment(lib,"WinTrust.lib")
#include "..\SafeSystem\objfre_win7_x86\i386\KernelModule.h"
#include "..\Dll_Resource\dbghelp.dll_src.h"
#include "..\Dll_Resource\symsrv.dll_src.h"
//#include "..\Dll_Resource\symsrv.yes_src.h"
#pragma comment(lib,"ntdll.Lib") 
#define STATUS_SUCCESS        0x00000000 
typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING {
	USHORT  Length;     //UNICODEռ�õ��ڴ��ֽ���������*2��
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING ,*PUNICODE_STRING;
extern "C" NTSTATUS __stdcall  NtLoadDriver(
	IN PUNICODE_STRING  DriverServiceName
	);
extern "C" VOID __stdcall
	RtlInitUnicodeString(
	IN OUT PUNICODE_STRING  DestinationString,
	IN PCWSTR  SourceString
	);
extern "C" ULONG __stdcall
	RtlNtStatusToDosError(
	IN NTSTATUS  Status
	); 
BOOL Install(HWND hwndDlg);
extern VOID Install2();
BOOL LoadNTDriver(char* lpszDriverName,char* lpszDriverPath);
//HINSTANCE hDbgHelp;