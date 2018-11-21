#include "win32k.h"

//由base得到shadowssdt
// .data段第一个就是
BOOL MmQueryShadowSSDTAddr(ULONG ImageBase,DWORD *ShadowSSDTAddress)
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER Section;
	int i=0;
	BOOL bRetOK = FALSE;

	//KdPrint(("ImageBase %08x\n",ImageBase));

	DosHeader=(PIMAGE_DOS_HEADER)ImageBase;
	if (DosHeader->e_magic!=IMAGE_DOS_SIGNATURE){
		return bRetOK;
	}
	NtHeader=(PIMAGE_NT_HEADERS)((PBYTE)ImageBase+DosHeader->e_lfanew);
	if (NtHeader->Signature!=IMAGE_NT_SIGNATURE){
		return bRetOK;
	}
	Section = (PIMAGE_SECTION_HEADER) ((ULONG)NtHeader + sizeof(IMAGE_NT_HEADERS));
	for (i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		if (g_bDebugOn)
			KdPrint(("Section %s\n",Section->Name));

		if (_strnicmp(Section->Name,".data",strlen(".data")) == 0){

			*ShadowSSDTAddress = ImageBase+Section->VirtualAddress;

			if (g_bDebugOn)
				KdPrint(("Section %08x\n",*ShadowSSDTAddress));

			if (MmIsAddressValidEx((PVOID)(*ShadowSSDTAddress))){
				bRetOK = TRUE;
				break;
			}
		}
		Section++;
	}
	return bRetOK;
}
BOOL FixOriginalW32pTable(PDWORD w32pTable,PVOID ImageBase,DWORD Win32kBase)
{
	PIMAGE_NT_HEADERS NtHeaders;
	DWORD FuctionCount;
	DWORD Index;
	DWORD ImageSize;

	NtHeaders=RtlImageNtHeader(ImageBase);
	if (NtHeaders)
	{
		ImageSize=NtHeaders->OptionalHeader.SizeOfImage;
		ImageSize=AlignSize(ImageSize,NtHeaders->OptionalHeader.SectionAlignment);
	}
	FuctionCount = ShadowSSDTTable[1].TableSize;

	if (g_bDebugOn)
		KdPrint(("FuctionCount:%d"));

	for (Index=0;Index<FuctionCount;Index++)
	{
		w32pTable[Index]=w32pTable[Index]-Win32kBase+(DWORD)ImageBase;
		if (!MmIsAddressValidEx((PVOID)w32pTable[Index])){
			return FALSE;
		}
	}
	return TRUE;
}
BOOL InitReloadWin32K(PDRIVER_OBJECT pDriverObject,PSERVICE_DESCRIPTOR_TABLE ShadowSSDT,ULONG Win32kBase)
{
	UNICODE_STRING FileName;
	HANDLE hSection;
	PDWORD OriginalKiServiceTable;
	PDWORD CsRootkitOriginalKiServiceTable;
	int i=0;

	if (!PeLoad(L"\\SystemRoot\\System32\\win32k.sys",&Win32kImageModuleBase,pDriverObject,Win32kBase)){
		if (g_bDebugOn)
			KdPrint(("Safe->PeLoad failed\n"));
		return FALSE;
	}

	if (g_bDebugOn)
		KdPrint(("Safe->ModuleBase:%08x\r\n",Win32kImageModuleBase));

	OriginalKiServiceTable = ExAllocatePool(NonPagedPool,ShadowSSDT[1].TableSize*sizeof(DWORD));
	if (!OriginalKiServiceTable){
		if (g_bDebugOn)
			KdPrint(("OriginalKiServiceTable Failed\n"));
		return FALSE;
	}
	//获取原始OriginalKiServiceTable
	if(!MmQueryShadowSSDTAddr((ULONG)Win32kImageModuleBase,(DWORD*)(&OriginalKiServiceTable))){
		if (g_bDebugOn)
			KdPrint(("Safe->Get Original KiServiceTable Failed\n"));

		ExFreePool(OriginalKiServiceTable);
		return FALSE;
	}
	//重定位reload原始SSDT表里面的每一个原始函数
	if (!FixOriginalW32pTable(OriginalKiServiceTable,(PVOID)((DWORD)Win32kImageModuleBase),Win32kBase)){
		if (g_bDebugOn)
			KdPrint(("FixOriginalW32pTable Failed\n"));

		ExFreePool(OriginalKiServiceTable);
		return FALSE;
	}
	if (g_bDebugOn)
		KdPrint(("Safe->OriginalKiServiceTable %x-%x\n",OriginalKiServiceTable,ShadowSSDT[1].ServiceTable));

	g_OriginalShadowServiceDescriptorTable=ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	if (!g_OriginalShadowServiceDescriptorTable){
		ExFreePool(OriginalKiServiceTable);
		return FALSE;
	}
	RtlZeroMemory(g_OriginalShadowServiceDescriptorTable,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	//这是一个干净的原始表，每个表里所对应的SSDT函数的地址都是有效的~
	g_OriginalShadowServiceDescriptorTable->ServiceTable=(PDWORD)OriginalKiServiceTable;
	g_OriginalShadowServiceDescriptorTable->CounterTable=ShadowSSDT[1].CounterTable;
	g_OriginalShadowServiceDescriptorTable->TableSize=ShadowSSDT[1].TableSize;
	g_OriginalShadowServiceDescriptorTable->ArgumentTable=ShadowSSDT[1].ArgumentTable;

	CsRootkitOriginalKiServiceTable=ExAllocatePool(NonPagedPool,ShadowSSDT[1].TableSize*sizeof(DWORD));
	if (!CsRootkitOriginalKiServiceTable){
		ExFreePool(g_OriginalShadowServiceDescriptorTable);
		ExFreePool(OriginalKiServiceTable);
		return FALSE;

	}
	RtlZeroMemory(CsRootkitOriginalKiServiceTable,ShadowSSDT[1].TableSize*sizeof(DWORD));

	g_Safe_ServiceDescriptorShadowSSDTTable=ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	if (!g_Safe_ServiceDescriptorShadowSSDTTable){
		ExFreePool(g_OriginalShadowServiceDescriptorTable);
		ExFreePool(CsRootkitOriginalKiServiceTable);
		ExFreePool(OriginalKiServiceTable);
		return FALSE;
	}
	//这是一个干净的原始表，每个表里所对应的SSDT函数的地址都是原始函数
	RtlZeroMemory(g_Safe_ServiceDescriptorShadowSSDTTable,sizeof(SERVICE_DESCRIPTOR_TABLE)*4);
	//填充原始函数地址
	for (i=0;i<(int)ShadowSSDT[1].TableSize;i++)
	{
		CsRootkitOriginalKiServiceTable[i] = g_OriginalShadowServiceDescriptorTable->ServiceTable[i];
	}
	g_Safe_ServiceDescriptorShadowSSDTTable->ServiceTable = (PDWORD)CsRootkitOriginalKiServiceTable;
	g_Safe_ServiceDescriptorShadowSSDTTable->CounterTable=ShadowSSDT[1].CounterTable;
	g_Safe_ServiceDescriptorShadowSSDTTable->TableSize=ShadowSSDT[1].TableSize;
	g_Safe_ServiceDescriptorShadowSSDTTable->ArgumentTable=ShadowSSDT[1].ArgumentTable;
	return TRUE;
}
NTSTATUS ReloadWin32K()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ulKeAddSystemServiceTable;
	UNICODE_STRING UnicodeFunctionName;
	PULONG p;
	int i = 0;

	if (IsExitProcess(AttachGuiEProcess))
	{
		KeAttachProcess(AttachGuiEProcess);

		RtlInitUnicodeString(&UnicodeFunctionName,L"KeAddSystemServiceTable");
		ulKeAddSystemServiceTable = (DWORD)MmGetSystemRoutineAddress(&UnicodeFunctionName);
		if (MmIsAddressValidEx((PVOID)ulKeAddSystemServiceTable))
		{
			p = (PULONG)((ULONG)ulKeAddSystemServiceTable + 0x1a + 0x2);
			if (MmIsAddressValidEx(p))
			{
				ShadowSSDTTable = (PSERVICE_DESCRIPTOR_TABLE)(PULONG)(*p);

				if (g_bDebugOn)
					KdPrint(("ShadowSSDTTable:%x\n",ShadowSSDTTable[1]));
			}
		}
		ulWin32kBase =(ULONG) LookupKernelModuleByName(g_pDriverObject,"win32k.sys",&ulWin32kSize);
		if (MmIsAddressValidEx(ShadowSSDTTable) &&
			ulWin32kBase)
		{
			if (g_bDebugOn)
				KdPrint(("LookupKernelModuleByName success\n"));

			if (InitReloadWin32K(g_pDriverObject,ShadowSSDTTable,ulWin32kBase))
			{
				if (g_bDebugOn)
					KdPrint(("InitReloadWin32K success"));

				g_ShadowTable =(ULONG) ShadowSSDTTable[1].ServiceTable;

				InitShadowSSDTHook();  //SHADOW SSDT hook

				status = STATUS_SUCCESS;
			}
		}
		KeDetachProcess();
	}
	return status;
}
////////--------------------------