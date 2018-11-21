#ifndef __SAFESYSTEM_H_VERSION__
#define __SAFESYSTEM_H_VERSION__ 100
//#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
//#endif
#include "drvcommon.h"
#include "drvversion.h"
#ifndef FILE_DEVICE_SAFESYSTEM
#define FILE_DEVICE_SAFESYSTEM 0x8000
#endif
BOOL g_bDebugOn = FALSE;
BOOL bKernelBooting = FALSE;
PDRIVER_OBJECT g_pDriverObject;
DWORD RetAddress;
PEPROCESS g_systemEProcess;
ULONG g_ulMyDriverBase;
ULONG g_ulMyDriverSize;
NTSTATUS ReLoadNtos(PDRIVER_OBJECT   DriverObject,DWORD RetAddress);
NTSTATUS LookupProcessByName(IN PCHAR pcProcessName,OUT PEPROCESS *pEprocess);
VOID WaitMicroSecond(LONG MicroSeconds);
BOOL DeleteRegKey(WCHAR *ServicesKey);
BOOL IsRegKeyInSystem(PWCHAR ServicesKey);
BOOL Safe_CreateValueKey(PWCHAR SafeKey,ULONG Reg_Type,PWCHAR ValueName,PWCHAR Value);
BOOL KeBugCheckCreateValueKey(PWCHAR SafeKey);
BOOL IsFileInSystem(WCHAR *lpwzFile);
ULONG PsGetProcessCount();
VOID ImageNotify(PUNICODE_STRING  FullImageName,HANDLE  ProcessId,PIMAGE_INFO  ImageInfo);
VOID MsGetMsgHookInfo();
#endif
