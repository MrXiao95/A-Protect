#ifndef _NTOS_H_
#define _NTOS_H_

#include "ntifs.h"
#include "InlineHook.h"
#include <ntimage.h>
#include "InitWindowsVersion.h"
#include "Protect.h"

extern BOOL g_bKernelSafeModule;
extern ULONG g_ShadowTable;
extern PSERVICE_DESCRIPTOR_TABLE g_OriginalShadowServiceDescriptorTable;
extern PSERVICE_DESCRIPTOR_TABLE g_Safe_ServiceDescriptorShadowSSDTTable;

extern ULONG g_ulMyDriverBase;
extern ULONG g_ulMyDriverSize;

//-------------------------------------------------------------------------
//保存所有导出的内核函数的一个结构
//-------------------------------------------------------------------------
typedef struct _KERNELFUNC_ADDRESS_INFORMATION {          //SAFESYSTEM_PROCESS_INFORMATION
	ULONG ulAddress;
	ULONG ulReloadAddress;
	WCHAR FuncName[50];
	int NumberOfFunctions; //函数在导出表里面的位置
}KERNELFUNC_ADDRESS_INFORMATION, *PKERNELFUNC_ADDRESS_INFORMATION;

typedef struct _NTOSFUNCINFO {          //PNTOSFUNCINFO
	ULONG ulCount;
	ULONG ulModuleBase;    //模块的基址
	WCHAR szModulePath[260];
	KERNELFUNC_ADDRESS_INFORMATION ntosFuncInfo[1];
} NTOSFUNCINFO, *PNTOSFUNCINFO;

PNTOSFUNCINFO g_pNtosFuncAddressInfo;       //没有解析符号的ntos内核函数信息结构
PNTOSFUNCINFO PDBNtosFuncAddressInfo;    //解析符号的ntos内核函数信息结构（包括导出未导出函数）
PNTOSFUNCINFO SelectModuleFuncInfo;      //当前选择的解析符号的驱动函数信息结构（包括导出未导出函数）
PNTOSFUNCINFO KernelFuncInfo;            //这个只是一个过度而已
//-------------------------------------------------------------------------

typedef struct _SAFESYSTEM_PROCESS_INFORMATION {          //SAFESYSTEM_PROCESS_INFORMATION
	int   IntHideType;
	ULONG ulPid;
	PEPROCESS EProcess;
	WCHAR lpwzFullProcessPath[256];
	ULONG ulInheritedFromProcessId;  //父进程
	ULONG ulKernelOpen;
}SAFESYSTEM_PROCESS_INFORMATION, *PSAFESYSTEM_PROCESS_INFORMATION;

typedef struct _PROCESSINFO {          //PROCESSINFO
	ULONG ulCount;
	SAFESYSTEM_PROCESS_INFORMATION ProcessInfo[1];
} PROCESSINFO, *PPROCESSINFO;

//--------------------------------------------------------------------------
PPROCESSINFO g_pNormalProcessInfo;
PPROCESSINFO g_pHideProcessInfo;


PSERVICE_DESCRIPTOR_TABLE g_pOriginalServiceDescriptorTable;
PSERVICE_DESCRIPTOR_TABLE g_pSafe_ServiceDescriptorTable;

#define NOHOOK 0;
#define SSDTHOOK 1
#define SSDTINLINEHOOK 2
#define INLINEHOOK 3

BYTE *g_pNewSystemKernelModuleBase;//重载后内核的地址
ULONG g_pOldSystemKernelModuleBase;//老内核地址
ULONG g_nSystemKernelModuleSize;//内核大小
WCHAR *g_szSystemKernelFilePath;//内核路径

DWORD g_dwOriginalKiServiceTable;

PVOID KiFastCallEntryRet;
int PatchCodeLength;

PVOID KiFastCallEntryTempRet;
int KiFastCallEntryTempPatchCodeLength;

PUCHAR ul360HookAddress;
BYTE ulHookCodeBak[5];
BYTE ulRealCodeBak[5];

BYTE ByteKiFastCallEntryBak[5];
BYTE ByteReloadKiFastCallEntryBak[5];

extern BOOL g_bIsInitSuccess;
extern BOOL bInitWin32K;

KEVENT WaitEvent;

VOID WaitMicroSecond(LONG MicroSeconds);

UCHAR *PsGetProcessImageFileName(
	__in PEPROCESS eprocess
	);

ULONG IsHideProcess(
	ULONG ulPid,
	PPROCESSINFO Info
	);

PVOID
	MiFindExportedRoutine (
	IN PVOID DllBase,
	BOOL ByName,
	IN char *RoutineName,
	DWORD Ordinal
	);

BOOL GetSystemKernelModuleInfo(
	WCHAR **SystemKernelModulePath,
	PDWORD SystemKernelModuleBase,
	PDWORD SystemKernelModuleSize
	);

BOOL PeLoad(
	WCHAR *FileFullPath,
	BYTE **ImageModeleBase,
	PDRIVER_OBJECT DeviceObject,
	DWORD ExistImageBase
	);

PVOID ReLoadNtosCALL(
	PVOID *pFuncSyntax,
	WCHAR *lpwzFuncTion,
	ULONG ulOldNtosBase,
	ULONG ulReloadNtosBase
	);

BOOL MmIsAddressValidEx(
	IN PVOID Pointer
	);
BOOL MmIsAddressRangeValid(
	IN PVOID Address,
	IN ULONG Size
	);

PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID ImageBase);

BOOL IsExitProcess(PEPROCESS Eprocess);
NTSTATUS ReloadWin32K();
ULONG PsGetProcessCount();
BOOL InitControl();  //通信控制
BOOL IsRegKeyInSystem(PWCHAR ServicesKey);


typedef BOOLEAN (__stdcall *ReloadKeDeregisterBugCheckCallback)(
	__inout  PKBUGCHECK_CALLBACK_RECORD CallbackRecord
	);
ReloadKeDeregisterBugCheckCallback g_fnRKeDeregisterBugCheckCallback;

typedef BOOLEAN (__stdcall *ReloadKeDeregisterBugCheckReasonCallback)(
	__inout PKBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord
	);
ReloadKeDeregisterBugCheckReasonCallback g_fnRKeDeregisterBugCheckReasonCallback;

typedef VOID (__stdcall *ReloadIoUnregisterShutdownNotification)(
	__in  PDEVICE_OBJECT DeviceObject
	);
ReloadIoUnregisterShutdownNotification g_fnRIoUnregisterShutdownNotification;

typedef NTSTATUS (__stdcall *ReloadSeUnregisterLogonSessionTerminatedRoutine)(
	IN PSE_LOGON_SESSION_TERMINATED_ROUTINE CallbackRoutine
	);
ReloadSeUnregisterLogonSessionTerminatedRoutine g_fnRSeUnregisterLogonSessionTerminatedRoutine;

typedef NTSTATUS (__stdcall *ReloadPsRemoveLoadImageNotifyRoutine)(
	__in  PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
	);
ReloadPsRemoveLoadImageNotifyRoutine g_fnRPsRemoveLoadImageNotifyRoutine;

typedef NTSTATUS (__stdcall *ReloadPsRemoveCreateThreadNotifyRoutine)(
	__in  PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
	);
ReloadPsRemoveCreateThreadNotifyRoutine g_fnRPsRemoveCreateThreadNotifyRoutine;

typedef NTSTATUS (__stdcall *ReloadPsSetCreateProcessNotifyRoutine)(
	__in  PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
	__in  BOOLEAN Remove
	);
ReloadPsSetCreateProcessNotifyRoutine g_fnRPsSetCreateProcessNotifyRoutine;

typedef BOOLEAN (__stdcall *ReloadKeCancelTimer)(
	__inout  PKTIMER Timer
	);
ReloadKeCancelTimer g_fnRKeCancelTimer;

typedef NTSTATUS (__stdcall *ReloadObQueryNameString)(
	__in       PVOID Object,
	__out_opt  POBJECT_NAME_INFORMATION ObjectNameInfo,
	__in       ULONG Length,
	__out      PULONG ReturnLength
	);
ReloadObQueryNameString g_fnRObQueryNameString;

typedef NTSTATUS (__stdcall *ReloadPsTerminateSystemThread)(
  __in  NTSTATUS ExitStatus
);
ReloadPsTerminateSystemThread g_fnRPsTerminateSystemThread;

typedef VOID (__stdcall *ReloadKeInitializeApc)(
	PKAPC Apc,
	PETHREAD Thread,
	ULONG Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
	);
ReloadKeInitializeApc g_fnRKeInitializeApc;

typedef BOOLEAN (__stdcall *ReloadKeInsertQueueApc)(
	PKAPC Apc,
	PVOID SystemArg1,
	PVOID SystemArg2,
	KPRIORITY Increment
	);
ReloadKeInsertQueueApc g_fnRKeInsertQueueApc;

typedef LONG (__stdcall * ReloadRtlCompareUnicodeString)(
	__in  PCUNICODE_STRING String1,
	__in  PCUNICODE_STRING String2,
	__in  BOOLEAN CaseInSensitive
	);
ReloadRtlCompareUnicodeString g_fnRRtlCompareUnicodeString;

typedef LONG (__stdcall * ReloadRtlCompareString)(
	__in  const STRING *String1,
	__in  const STRING *String2,
	__in  BOOLEAN CaseInSensitive
	);
ReloadRtlCompareString g_fnRRtlCompareString;

typedef VOID (__stdcall * ReloadRtlInitString)(
	__out     PSTRING DestinationString,
	__in_opt  PCSZ SourceString
	);
ReloadRtlInitString g_fnRRtlInitString;

typedef NTSTATUS (__stdcall * ReloadZwQueryVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN ULONG MemoryInformationClass,
	OUT PVOID               Buffer,
	IN ULONG                Length,
	OUT PULONG              ResultLength OPTIONAL
	);
ReloadZwQueryVirtualMemory g_fnRZwQueryVirtualMemory;

typedef NTSTATUS (__stdcall * ReloadIoQueryFileDosDeviceName)(
	IN PFILE_OBJECT  FileObject,
	OUT POBJECT_NAME_INFORMATION  *ObjectNameInformation
	);
ReloadIoQueryFileDosDeviceName g_fnRIoQueryFileDosDeviceName;

typedef UCHAR * (__stdcall * ReloadPsGetProcessImageFileName)(
	__in PEPROCESS eprocess
	);
ReloadPsGetProcessImageFileName g_fnRPsGetProcessImageFileName;


typedef PEPROCESS (__stdcall * ReloadIoThreadToProcess)(
    IN PETHREAD  Thread
    ); 
ReloadIoThreadToProcess g_fnRIoThreadToProcess;

typedef NTSTATUS (__stdcall * ReloadZwQueryDirectoryObject) (
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL
	);
ReloadZwQueryDirectoryObject g_fnRZwQueryDirectoryObject;

typedef NTSTATUS (__stdcall *ReloadZwOpenDirectoryObject)(
	__out PHANDLE  DirectoryHandle,
	__in ACCESS_MASK  DesiredAccess,
	__in POBJECT_ATTRIBUTES  ObjectAttributes
	);
ReloadZwOpenDirectoryObject g_fnRZwOpenDirectoryObject;

typedef VOID (__stdcall *ReloadIoSetCompletionRoutine)(
	__in      PIRP Irp,
	__in_opt  PIO_COMPLETION_ROUTINE CompletionRoutine,
	__in_opt  PVOID Context,
	__in      BOOLEAN InvokeOnSuccess,
	__in      BOOLEAN InvokeOnError,
	__in      BOOLEAN InvokeOnCancel
	);
ReloadIoSetCompletionRoutine g_fnRIoSetCompletionRoutine;

typedef PIRP (__stdcall *ReloadIoAllocateIrp)(
	__in  CCHAR StackSize,
	__in  BOOLEAN ChargeQuota
	);
ReloadIoAllocateIrp g_fnRIoAllocateIrp;

typedef LONG (__stdcall *ReloadKeSetEvent)(
	__inout  PRKEVENT Event,
	__in     KPRIORITY Increment,
	__in     BOOLEAN Wait
	);
ReloadKeSetEvent g_fnRKeSetEvent;

typedef NTSTATUS (__stdcall *ReloadIoCreateFile)(
	__out     PHANDLE FileHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in      POBJECT_ATTRIBUTES ObjectAttributes,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt  PLARGE_INTEGER AllocationSize,
	__in      ULONG FileAttributes,
	__in      ULONG ShareAccess,
	__in      ULONG Disposition,
	__in      ULONG CreateOptions,
	__in_opt  PVOID EaBuffer,
	__in      ULONG EaLength,
	__in      CREATE_FILE_TYPE CreateFileType,
	__in_opt  PVOID InternalParameters,
	__in      ULONG Options
	);
ReloadIoCreateFile g_fnRIoCreateFile;

typedef NTSTATUS (__stdcall *ReloadMmUnmapViewOfSection)(
	IN PEPROCESS Process, 
	IN ULONG BaseAddress 
	); 
ReloadMmUnmapViewOfSection g_fnRMmUnmapViewOfSection;

typedef NTSTATUS (__stdcall *ReloadPsLookupProcessByProcessId)(
	__in   HANDLE ProcessId,
	__out  PEPROCESS *Process
	);
ReloadPsLookupProcessByProcessId g_fnRPsLookupProcessByProcessId;

typedef HANDLE  (__stdcall *ReloadPsGetCurrentProcessId)(void);
ReloadPsGetCurrentProcessId RPsGetCurrentProcessId;

typedef PEPROCESS  (__stdcall *ReloadPsGetCurrentProcess)(void);
ReloadPsGetCurrentProcess g_fnRPsGetCurrentProcess;

typedef VOID (__stdcall *ReloadKeUnstackDetachProcess)(
	__in  PRKAPC_STATE ApcState
	);
ReloadKeUnstackDetachProcess g_fnRKeUnstackDetachProcess;

typedef VOID (__stdcall *ReloadKeStackAttachProcess)(
	__inout  PRKPROCESS Process,
	__out    PRKAPC_STATE ApcState
	);
ReloadKeStackAttachProcess g_fnRKeStackAttachProcess;

typedef VOID (__stdcall *ReloadKeDetachProcess)();
ReloadKeDetachProcess RKeDetachProcess;

typedef VOID (__stdcall *ReloadKeAttachProcess)(
	__inout  PRKPROCESS Process
	);
ReloadKeAttachProcess g_fnRKeAttachProcess;

typedef void *(__stdcall* Reloadmemcpy)(
	void *dest,
	const void *src,
	size_t count
	);
Reloadmemcpy g_fnRmemcpy;

typedef NTSTATUS (__stdcall *ReloadZwQueryInformationProcess)(
  __in       HANDLE ProcessHandle,
  __in       ULONG ProcessInformationClass,
  __out      PVOID ProcessInformation,
  __in       ULONG ProcessInformationLength,
  __out_opt  PULONG ReturnLength
);
ReloadZwQueryInformationProcess g_fnRZwQueryInformationProcess;

typedef NTSTATUS (__stdcall *ReloadObOpenObjectByPointer)(
  __in      PVOID Object,
  __in      ULONG HandleAttributes,
  __in_opt  PACCESS_STATE PassedAccessState,
  __in      ACCESS_MASK DesiredAccess,
  __in_opt  POBJECT_TYPE ObjectType,
  __in      KPROCESSOR_MODE AccessMode,
  __out     PHANDLE Handle
);
ReloadObOpenObjectByPointer g_fnRObOpenObjectByPointer;

typedef NTSTATUS (__stdcall *ReloadObReferenceObjectByName)( 
	IN PUNICODE_STRING ObjectName, 
	IN ULONG Attributes, 
	IN PACCESS_STATE AccessState OPTIONAL, 
	IN ACCESS_MASK DesiredAccess OPTIONAL, 
	IN POBJECT_TYPE ObjectType, 
	IN KPROCESSOR_MODE AccessMode, 
	IN OUT PVOID ParseContext OPTIONAL, 
	OUT PVOID *Object 
	);
ReloadObReferenceObjectByName g_fnRObReferenceObjectByName;

typedef NTSTATUS (__stdcall *ReloadIoCallDriver)(
	__in     PDEVICE_OBJECT DeviceObject,
	__inout  PIRP Irp
	);
ReloadIoCallDriver g_fnRIoCallDriver;

typedef NTSTATUS (__stdcall *ReloadKeWaitForSingleObject)(
	__in      PVOID Object,
	__in      KWAIT_REASON WaitReason,
	__in      KPROCESSOR_MODE WaitMode,
	__in      BOOLEAN Alertable,
	__in_opt  PLARGE_INTEGER Timeout
	);
ReloadKeWaitForSingleObject g_fnRKeWaitForSingleObject;


typedef VOID (__stdcall *ReloadKeInitializeEvent)(
	__out  PRKEVENT Event,
	__in   EVENT_TYPE Type,
	__in   BOOLEAN State
	);
ReloadKeInitializeEvent g_fnRKeInitializeEvent;

typedef PDEVICE_OBJECT (__stdcall *ReloadIoGetRelatedDeviceObject)(
	__in  PFILE_OBJECT FileObject
	);
ReloadIoGetRelatedDeviceObject g_fnRIoGetRelatedDeviceObject;

typedef NTSTATUS (__stdcall *ReloadObReferenceObjectByHandle)(
	__in       HANDLE Handle,
	__in       ACCESS_MASK DesiredAccess,
	__in_opt   POBJECT_TYPE ObjectType,
	__in       KPROCESSOR_MODE AccessMode,
	__out      PVOID *Object,
	__out_opt  POBJECT_HANDLE_INFORMATION HandleInformation
	);
ReloadObReferenceObjectByHandle g_fnRObReferenceObjectByHandle;

typedef NTSTATUS (__stdcall *ReloadZwCreateFile)(
	__out     PHANDLE FileHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in      POBJECT_ATTRIBUTES ObjectAttributes,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt  PLARGE_INTEGER AllocationSize,
	__in      ULONG FileAttributes,
	__in      ULONG ShareAccess,
	__in      ULONG CreateDisposition,
	__in      ULONG CreateOptions,
	__in_opt  PVOID EaBuffer,
	__in      ULONG EaLength
	);
ReloadZwCreateFile g_fnRZwCreateFile;

typedef NTSTATUS (__stdcall *ReloadZwOpenProcess)(
	__out     PHANDLE ProcessHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in      POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt  PCLIENT_ID ClientId
	);
ReloadZwOpenProcess g_fnRZwOpenProcess;

typedef NTSTATUS (__stdcall *ReloadZwTerminateProcess)(
	__in_opt  HANDLE ProcessHandle,
	__in      NTSTATUS ExitStatus
	);
ReloadZwTerminateProcess g_fnRZwTerminateProcess;

typedef NTSTATUS (__stdcall *ReloadZwClose)(
	__in  HANDLE Handle
	);
ReloadZwClose g_fnRZwClose;

typedef PVOID (__stdcall *ReloadMmGetSystemRoutineAddress)(
	__in  PUNICODE_STRING SystemRoutineName
	);
ReloadMmGetSystemRoutineAddress g_fnRMmGetSystemRoutineAddress;


typedef VOID (__stdcall *ReloadRtlInitUnicodeString)(
	__inout   PUNICODE_STRING DestinationString,
	__in_opt  PCWSTR SourceString
	);
ReloadRtlInitUnicodeString g_fnRRtlInitUnicodeString;


typedef BOOLEAN (__stdcall * ReloadMmIsAddressValid)(
	__in  PVOID VirtualAddress
	);
ReloadMmIsAddressValid g_fnRMmIsAddressValid;

typedef PVOID (__stdcall *ReloadExAllocatePoolWithTag)(
	__in  POOL_TYPE PoolType,
	__in  SIZE_T NumberOfBytes,
	__in  ULONG Tag
	);
ReloadExAllocatePoolWithTag g_fnRExAllocatePoolWithTag;

typedef PVOID (__stdcall *ReloadExAllocatePool)(
	__in  POOL_TYPE PoolType,
	__in  SIZE_T NumberOfBytes
	);
ReloadExAllocatePool g_fnRExAllocatePool;

typedef VOID (__stdcall *ReloadExFreePool)(
	__in  PVOID P
	);
ReloadExFreePool g_fnRExFreePool;

typedef NTSTATUS (__stdcall *ReloadZwOpenFile)(
	__out  PHANDLE FileHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PIO_STATUS_BLOCK IoStatusBlock,
	__in   ULONG ShareAccess,
	__in   ULONG OpenOptions
	);
ReloadZwOpenFile g_fnRZwOpenFile;

typedef NTSTATUS (__stdcall *ReloadZwCreateSection)(
	__out     PHANDLE SectionHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt  PLARGE_INTEGER MaximumSize,
	__in      ULONG SectionPageProtection,
	__in      ULONG AllocationAttributes,
	__in_opt  HANDLE FileHandle
	);
ReloadZwCreateSection g_fnRZwCreateSection;

typedef NTSTATUS (__stdcall *ReloadZwMapViewOfSection)(
	__in     HANDLE SectionHandle,
	__in     HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	__in     ULONG_PTR ZeroBits,
	__in     SIZE_T CommitSize,
	__inout  PLARGE_INTEGER SectionOffset,
	__inout  PSIZE_T ViewSize,
	__in     SECTION_INHERIT InheritDisposition,
	__in     ULONG AllocationType,
	__in     ULONG Win32Protect
	);
ReloadZwMapViewOfSection g_fnRZwMapViewOfSection;

typedef NTSTATUS (__stdcall *ReloadZwClose)(
	__in  HANDLE Handle
	);
ReloadZwClose g_fnRZwClose;

typedef NTSTATUS (__stdcall *ReloadZwQuerySystemInformation)(
	__in       ULONG SystemInformationClass,
	__inout    PVOID SystemInformation,
	__in       ULONG SystemInformationLength,
	__out_opt  PULONG ReturnLength
	);
ReloadZwQuerySystemInformation g_fnRZwQuerySystemInformation;

typedef NTSTATUS (__stdcall *ReloadZwOpenKey)(
	__out  PHANDLE KeyHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes
	);
ReloadZwOpenKey g_fnRZwOpenKey;

typedef NTSTATUS (__stdcall *ReloadZwEnumerateKey)(
	__in       HANDLE KeyHandle,
	__in       ULONG Index,
	__in       KEY_INFORMATION_CLASS KeyInformationClass,
	__out_opt  PVOID KeyInformation,
	__in       ULONG Length,
	__out      PULONG ResultLength
	);
ReloadZwEnumerateKey g_fnRZwEnumerateKey;

typedef NTSTATUS (__stdcall *ReloadZwQueryValueKey)(
	__in       HANDLE KeyHandle,
	__in       PUNICODE_STRING ValueName,
	__in       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	__out_opt  PVOID KeyValueInformation,
	__in       ULONG Length,
	__out      PULONG ResultLength
	);
ReloadZwQueryValueKey g_fnRZwQueryValueKey;

typedef NTSTATUS (__stdcall *ReloadZwCreateKey)(
	__out       PHANDLE KeyHandle,
	__in        ACCESS_MASK DesiredAccess,
	__in        POBJECT_ATTRIBUTES ObjectAttributes,
	__reserved  ULONG TitleIndex,
	__in_opt    PUNICODE_STRING Class,
	__in        ULONG CreateOptions,
	__out_opt   PULONG Disposition
	);
ReloadZwCreateKey g_fnRZwCreateKey;

typedef NTSTATUS (__stdcall *ReloadZwSetValueKey)(
	__in      HANDLE KeyHandle,
	__in      PUNICODE_STRING ValueName,
	__in_opt  ULONG TitleIndex,
	__in      ULONG Type,
	__in_opt  PVOID Data,
	__in      ULONG DataSize
	);
ReloadZwSetValueKey g_fnRZwSetValueKey;

typedef NTSTATUS (__stdcall *ReloadZwFlushKey)(
	__in  HANDLE KeyHandle
	);
ReloadZwFlushKey RZwFlushKey;

typedef PMDL (__stdcall *ReloadIoAllocateMdl)(
	__in_opt     PVOID VirtualAddress,
	__in         ULONG Length,
	__in         BOOLEAN SecondaryBuffer,
	__in         BOOLEAN ChargeQuota,
	__inout_opt  PIRP Irp
	);
ReloadIoAllocateMdl g_fnRIoAllocateMdl;

typedef VOID (__stdcall *ReloadMmBuildMdlForNonPagedPool)(
	__inout  PVOID MemoryDescriptorList
	);
ReloadMmBuildMdlForNonPagedPool RMmBuildMdlForNonPagedPool;

typedef VOID (__stdcall *ReloadMmProbeAndLockPages)(
	__inout  PVOID MemoryDescriptorList,
	__in     KPROCESSOR_MODE AccessMode,
	__in     LOCK_OPERATION Operation
	);
ReloadMmProbeAndLockPages g_fnRMmProbeAndLockPages;

typedef VOID (__stdcall *ReloadMmUnlockPages)(
	__inout  PVOID MemoryDescriptorList
	);
ReloadMmUnlockPages g_fnRMmUnlockPages;

typedef VOID (__stdcall *ReloadIoFreeMdl)(
	__in  PMDL Mdl
	);
ReloadIoFreeMdl g_fnRIoFreeMdl;

typedef VOID (__stdcall *ReloadIoStartTimer)(
	 __in  PDEVICE_OBJECT DeviceObject
	);
ReloadIoStartTimer g_fnRIoStartTimer;

typedef VOID (__stdcall *ReloadIoStopTimer)(
	__in  PDEVICE_OBJECT DeviceObject
	);
ReloadIoStopTimer g_fnRIoStopTimer;

#endif