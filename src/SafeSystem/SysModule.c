#include "SysModule.h"

BOOL QueryDriverFromPsLoadedModuleList(PDRIVER_OBJECT DriverObject,PSYSINFO SysModuleInfo)
{
	PLDR_DATA_TABLE_ENTRY LdrDataTable,HideLdrDataTable;
	BOOL bRetOK = FALSE;
	int i = 0;

	__try
	{
		LdrDataTable=(PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		do 
		{

			//	KdPrint(("%wZ\n",&LdrDataTable->BaseDllName));
			if (LdrDataTable->BaseDllName.Length>0&&LdrDataTable->BaseDllName.Buffer!=NULL)
			{
				if(MmIsAddressValidEx(&LdrDataTable->BaseDllName.Buffer[LdrDataTable->BaseDllName.Length/2-1]))
				{
					SysModuleInfo->SysInfo[i].DriverObject = 0;
					SysModuleInfo->SysInfo[i].SizeOfImage = LdrDataTable->SizeOfImage;
					SysModuleInfo->SysInfo[i].ulSysBase = (ULONG)LdrDataTable->DllBase;
					SysModuleInfo->SysInfo[i].IntHideType = TRUE;

					if (ValidateUnicodeString(&LdrDataTable->FullDllName) &&
						LdrDataTable->FullDllName.Buffer != 0 &&
						LdrDataTable->FullDllName.Length > 0)
					{
						SafeCopyMemory(LdrDataTable->FullDllName.Buffer,SysModuleInfo->SysInfo[i].lpwzFullSysName,LdrDataTable->FullDllName.Length);
					}else{
						memcpy(SysModuleInfo->SysInfo[i].lpwzFullSysName,L"Unknown",wcslen(L"Unknown")*2);
					}

					if (ValidateUnicodeString(&LdrDataTable->BaseDllName) &&
						LdrDataTable->BaseDllName.Buffer != 0 &&
						LdrDataTable->BaseDllName.Length > 0)
					{
						SafeCopyMemory(LdrDataTable->BaseDllName.Buffer,SysModuleInfo->SysInfo[i].lpwzBaseSysName,LdrDataTable->BaseDllName.Length);

					}else{
						memcpy(SysModuleInfo->SysInfo[i].lpwzBaseSysName,L"Unknown",wcslen(L"Unknown")*2);
					}
					SysModuleInfo->ulCount = i;
					i++;
				}
			}
			LdrDataTable=(PLDR_DATA_TABLE_ENTRY)LdrDataTable->InLoadOrderLinks.Flink;

		} while ((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection!=LdrDataTable&&LdrDataTable!=NULL);
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
	}
	return bRetOK;
}
//TRUE ��������
//FALSE ��������
BOOL MmQueryDriverPath(PDRIVER_OBJECT DriverObject,ULONG ulDriverStart,WCHAR *BaseSysName,WCHAR *FullSysName)
{
	PLDR_DATA_TABLE_ENTRY LdrDataTable,HideLdrDataTable;
	BOOL bRetOK = FALSE;
	int i = 0;

	__try
	{
		LdrDataTable=(PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		do 
		{

			//	KdPrint(("%wZ\n",&LdrDataTable->BaseDllName));
			if (LdrDataTable->BaseDllName.Length>0&&LdrDataTable->BaseDllName.Buffer!=NULL)
			{
				if(MmIsAddressValidEx(&LdrDataTable->BaseDllName.Buffer[LdrDataTable->BaseDllName.Length/2-1]))
				{
					if (LdrDataTable->DllBase == (PVOID)ulDriverStart)
					{
						if (ValidateUnicodeString(&LdrDataTable->FullDllName) &&
							LdrDataTable->FullDllName.Buffer != 0 &&
							LdrDataTable->FullDllName.Length > 0)
						{
							SafeCopyMemory(LdrDataTable->FullDllName.Buffer,FullSysName,LdrDataTable->FullDllName.Length);
						}else{
							memcpy(FullSysName,L"Unknown",wcslen(L"Unknown")*2);
						}

						if (ValidateUnicodeString(&LdrDataTable->BaseDllName) &&
							LdrDataTable->BaseDllName.Buffer != 0 &&
							LdrDataTable->BaseDllName.Length > 0)
						{
							SafeCopyMemory(LdrDataTable->BaseDllName.Buffer,BaseSysName,LdrDataTable->BaseDllName.Length);

						}else{
							memcpy(BaseSysName,L"Unknown",wcslen(L"Unknown")*2);
						}
						bRetOK = TRUE;
						break;
					}
				}
			}
			LdrDataTable=(PLDR_DATA_TABLE_ENTRY)LdrDataTable->InLoadOrderLinks.Flink;

		} while ((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection!=LdrDataTable&&LdrDataTable!=NULL);
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
	}
	return bRetOK;
}
VOID ScanDriverObject(PDRIVER_OBJECT PDriverObject,PDRIVER_OBJECT_STRUCT DriverStruct)
{
	ULONG ulScan=0;
	ULONG ulCount=0;
	PDRIVER_OBJECT pTmpDriObject;
	PKDDEBUGGER_DATA64 pKdData64;
	BOOL bRetOK = FALSE;
	POBJECT_TYPE pObjectType;
	ULONG ulKey;
	WIN_VER_DETAIL WinVer;
	ULONG ulKeyOffset = 0;
	int i=0,x=0,y=0;
	BOOL bRealDriver = TRUE;
	//KIRQL oldIrql;
	//KSPIN_LOCK    DpcSpinLock;

	//û������֮ǰ��ulSearchStart��Ϊ��ʼ��ַӦ�ò���䣬���Եڶ��ξͲ���Ҫ���»�ȡ��
	if (bIsRealSearch &&
		MmIsAddressValidEx((PVOID)ulSearchStart) &&
		ulSearchEnd == ulSearchStart + 0xf000000)
	{
		goto search;
	}
	pKdData64 = KdGetDebuggerDataBlock();
	if (MmIsAddressValidEx(pKdData64)){
		if (MmIsAddressValidEx((PVOID)pKdData64->MmNonPagedPoolStart)){
				ulSearchStart = *(PULONG)pKdData64->MmNonPagedPoolStart;

				//MmSizeOfPagedPoolInBytes�Ĵ�С��start���֮���ܴ�С�ᳬ��0xFFFFFFFF�������͵��¸������⡣
				//��˲���MmSizeOfPagedPoolInBytes��Ϊ�жϣ�����Ҳ��Ч�ʡ�
				//�κ�driver_object�ĵ�ַ���Բ������ MmNonPagedPoolStart + 0xf000000�����ȡ��ֵ��Ϊend

				if (MmIsAddressValidEx((PVOID)ulSearchStart)){
					ulSearchEnd = ulSearchStart + 0xf000000;
					bRetOK = TRUE;
				}
		}
	}
	if (!bRetOK){
		return;
	}
search:
	WinVer = GetWindowsVersion();
	switch (WinVer)
	{
	case WINDOWS_VERSION_XP:
	case WINDOWS_VERSION_2K3:
	case WINDOWS_VERSION_2K3_SP1_SP2:
		ulKeyOffset = 0xac;
		break;
	case WINDOWS_VERSION_7_7000:
	case WINDOWS_VERSION_7_7600_UP:
		ulKeyOffset = 0x7c;
		break;
	}

	/*
	lkd> dt_OBJECT_TYPE
	nt!_OBJECT_TYPE
	+0x000 Mutex            : _ERESOURCE
	+0x038 TypeList         : _LIST_ENTRY
	+0x040 Name             : _UNICODE_STRING
	+0x048 DefaultObject    : Ptr32 Void
	+0x04c Index            : Uint4B
	+0x050 TotalNumberOfObjects : Uint4B
	+0x054 TotalNumberOfHandles : Uint4B
	+0x058 HighWaterNumberOfObjects : Uint4B
	+0x05c HighWaterNumberOfHandles : Uint4B
	+0x060 TypeInfo         : _OBJECT_TYPE_INITIALIZER
	+0x0ac Key              : Uint4B
	+0x0b0 ObjectLocks      : [4] _ERESOURCE
	*/
	pObjectType=(POBJECT_TYPE)(*(PULONG)IoDriverObjectType);
	if (!MmIsAddressValidEx((PVOID)(pObjectType + ulKeyOffset))){
		return;
	}
	ulKey=*(PULONG)((ULONG)pObjectType + ulKeyOffset)|0x80000000;

	if (g_bDebugOn)
		KdPrint(("start:%08x %08x\n",ulSearchStart,ulSearchEnd));

	i = 0;

	//����
	//oldIrql = KeRaiseIrqlToDpcLevel();
	//KeAcquireSpinLockAtDpcLevel(&DpcSpinLock);

	__try
	{
		for(ulScan=ulSearchStart;ulScan< ulSearchEnd;ulScan+=4)
		{
			//������ʵҲ������MmIsAddressValidEx������Ч�ʺ�����ֻ����ԭ��RMmIsAddressValid��
			if (MmIsAddressValidEx((PVOID)ulScan))
			{
				if(*(PULONG)ulScan == ulKey)
				{
					//KdPrint(("Search:%s\n",PsGetProcessImageFileName(PsGetCurrentProcess())));

					//���趼�������������
					bRealDriver = TRUE;

					pTmpDriObject=NULL;
					pTmpDriObject=(PDRIVER_OBJECT)(ulScan+DriMagic);
					if (!MmIsAddressValidEx(pTmpDriObject) ||
						!MmIsAddressValidEx((pTmpDriObject + 0x38)) ){  //0x38 �� MajorFunction��Ա��ƫ�ƣ�Ҳ��driver_object����Ա��������Է��ʣ�������ԱҲ����
						continue;
					}
					//�������������MajorFunction[28]�����ǿ��Է��ʵģ�ֻҪ��һ�����ܷ��ʣ�˵���������������
					if (MmIsAddressValidEx(pTmpDriObject->MajorFunction)){
						for (x=0;x<MAX_IRP_MJ_DISPATCH;x++)
						{
							if (!MmIsAddressValidEx(pTmpDriObject->MajorFunction[x])){
								bRealDriver = FALSE;
							}
						}
					}
					if(*(PULONG)(pTmpDriObject) == 0x00a80004 ||
						bRealDriver == TRUE)
					{
						//������ΪTRUE��˵����ʱ��ulSearchStart����ȷ��
						bIsRealSearch = TRUE;

						//���������ȷ����������
						if (g_bDebugOn)
							KdPrint(("RealDriver:[%d]%08x\n",i,pTmpDriObject));

						//�������
						if (i > 700)
							goto FuncRet;

						DriverStruct->Struct[i].ulDriverObject =(ULONG) pTmpDriObject;
						i++;
						DriverStruct->ulCount = i;
					}
					ulScan += sizeof(DRIVER_OBJECT);
				}
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
		goto FuncRet;
	}
FuncRet:
	//KeReleaseSpinLockFromDpcLevel(&DpcSpinLock);
	//KeLowerIrql(oldIrql);

	return;
}
VOID EnumKernelModule(PDRIVER_OBJECT PDriverObject,PSYSINFO SysModuleInfo)
{
	PDRIVER_OBJECT pTmpDriObject;
	PDRIVER_OBJECT_STRUCT DriverObjectStruct = NULL;
	int i=0;
	int x=0;
	int fix=0;
	BOOL bFoundDriver = FALSE;
	WIN_VER_DETAIL WinVer;
	PEPROCESS VMwareEProcess;

	//�ȴ�����ȡ
	QueryDriverFromPsLoadedModuleList(PDriverObject,SysModuleInfo);
	fix = SysModuleInfo->ulCount;

	//�ӱ��������ṹ��ȡ�����������ļ���
	for (i=0;i<(int)g_pLogDefenseInfo->ulCount;i++)
	{
		if (g_pLogDefenseInfo->LogDefense[i].Type == 6)
		{
			for (x=0;x<(int)SysModuleInfo->ulCount;x++)
			{
				//�����Ļ�ַҪ���ڣ����Ҵ�����ϵͳ��
				if (SysModuleInfo->SysInfo[x].ulSysBase == g_pLogDefenseInfo->LogDefense[i].EProcess)
				{
					bFoundDriver = TRUE;
					break;
				}
			}
			//���ˣ���������������
			if (!bFoundDriver &&
				MmIsAddressValidEx((PVOID)g_pLogDefenseInfo->LogDefense[i].EProcess))  //������ľ��ж��
			{
				fix++;
				SysModuleInfo->SysInfo[fix].DriverObject = 0;
				SysModuleInfo->SysInfo[fix].SizeOfImage = g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID;
				SysModuleInfo->SysInfo[fix].ulSysBase = g_pLogDefenseInfo->LogDefense[i].EProcess;

				SysModuleInfo->SysInfo[fix].IntHideType = FALSE;  //��ʾ�޷�ʶ�����������
				memcpy(SysModuleInfo->SysInfo[fix].lpwzFullSysName,L"*",wcslen(L"*")*2);
				memcpy(SysModuleInfo->SysInfo[fix].lpwzBaseSysName,L"*",wcslen(L"*")*2);
				memcpy(SysModuleInfo->SysInfo[fix].lpwzServiceName,L"*",wcslen(L"*")*2);
				SysModuleInfo->ulCount = fix;
			}
		}
	}
// 	//***************************************************************************************
// 	//����������ģ��������������ˣ��ݣ��������������Ļ����޷����������һ��~~~��������
// 	//***************************************************************************************
// 	if (LookupProcessByName("VMwareTray.exe",&VMwareEProcess) != STATUS_SUCCESS)
// 	{
// 		if (DebugOn)
// 			KdPrint(("Is not in VMware\r\n"));
// 
// 		return;
// 	}

	bFoundDriver = FALSE;

	if (g_bDebugOn)
		KdPrint(("KeGetCurrentIrql -> %d\n",KeGetCurrentIrql()));

	if (KeGetCurrentIrql() != PASSIVE_LEVEL){
		return;
	}
	if (g_bDebugOn)
		KdPrint(("%d\n",SysModuleInfo->ulCount));

	//�ٴα���ö��driver_object�����ұ��浽�ڴ棬
	//ִ�е����˵��RExAllocatePool��ַ����ȷ�ģ�ֱ�ӵ�����
	DriverObjectStruct = (PDRIVER_OBJECT_STRUCT)g_fnRExAllocatePool(NonPagedPool,sizeof(DRIVER_OBJECT_STRUCT)*264);
	if (!DriverObjectStruct){
		return;
	}
	memset(DriverObjectStruct,0,sizeof(DRIVER_OBJECT_STRUCT)*264);
	ScanDriverObject(PDriverObject,DriverObjectStruct);

	if (DriverObjectStruct->ulCount)
	{
		for (i=0;i<(int)DriverObjectStruct->ulCount;i++)
		{
			pTmpDriObject = (PDRIVER_OBJECT)(DriverObjectStruct->Struct[i].ulDriverObject);
			bFoundDriver = FALSE;

			for (x=0;x<(int)SysModuleInfo->ulCount;x++)
			{
				//�ҵ���
				if (SysModuleInfo->SysInfo[x].ulSysBase == (ULONG)pTmpDriObject->DriverStart)
				{
					SysModuleInfo->SysInfo[x].DriverObject =(ULONG) pTmpDriObject;  //���driver_object
					//������
					if (ValidateUnicodeString(&pTmpDriObject->DriverName) &&
						pTmpDriObject->DriverName.Buffer != 0 &&
						pTmpDriObject->DriverName.Length > 0)
					{
						SafeCopyMemory(pTmpDriObject->DriverName.Buffer,SysModuleInfo->SysInfo[x].lpwzServiceName,pTmpDriObject->DriverName.Length);
					}else{
						memcpy(SysModuleInfo->SysInfo[x].lpwzServiceName,L"Unknown",wcslen(L"Unknown")*2);
					}
					SysModuleInfo->SysInfo[x].IntHideType = TRUE;
					bFoundDriver = TRUE;
					break;
				}
			}
			//���㹫�꣬ľ���ҵ�
			if (!bFoundDriver){
				fix++;
				SysModuleInfo->SysInfo[fix].DriverObject =(ULONG) pTmpDriObject;
				SysModuleInfo->SysInfo[fix].SizeOfImage = pTmpDriObject->DriverSize;
				SysModuleInfo->SysInfo[fix].ulSysBase = (ULONG)pTmpDriObject->DriverStart;

				SysModuleInfo->SysInfo[fix].IntHideType = FALSE;  //��ʾ�޷�ʶ�����������
				memcpy(SysModuleInfo->SysInfo[fix].lpwzFullSysName,L"-",wcslen(L"-")*2);
				memcpy(SysModuleInfo->SysInfo[fix].lpwzBaseSysName,L"-",wcslen(L"-")*2);

				if (ValidateUnicodeString(&pTmpDriObject->DriverName) &&
					pTmpDriObject->DriverName.Buffer != 0 &&
					pTmpDriObject->DriverName.Length > 0)
				{
					SafeCopyMemory(pTmpDriObject->DriverName.Buffer,SysModuleInfo->SysInfo[fix].lpwzServiceName,pTmpDriObject->DriverName.Length);
				}else{
					memcpy(SysModuleInfo->SysInfo[fix].lpwzServiceName,L"Unknown",wcslen(L"Unknown")*2);
				}
				if (g_bDebugOn)
					KdPrint(("can't found :[%d]%x-%ws\n",fix,SysModuleInfo->SysInfo[fix].DriverObject,SysModuleInfo->SysInfo[fix].lpwzServiceName));
			}
		}
		SysModuleInfo->ulCount = fix;
	}
/*
	for (i=0;i<SysModuleInfo->ulCount;i++)
	{
		KdPrint(("[%d]SysModule\r\n"
			"����:%08x\r\n"
			"��ַ:%08x\r\n"
			"��С:%x\r\n"
			"������:%ws\r\n"
			"����·��:%ws\r\n"
			"����:%ws\r\n"
			"��������:%d\r\n\r\n",
			i,
			SysModuleInfo->SysInfo[i].DriverObject,
			SysModuleInfo->SysInfo[i].ulSysBase,
			SysModuleInfo->SysInfo[i].SizeOfImage,
			SysModuleInfo->SysInfo[i].lpwzBaseSysName,
			SysModuleInfo->SysInfo[i].lpwzFullSysName,
			SysModuleInfo->SysInfo[i].lpwzServiceName,
			SysModuleInfo->SysInfo[i].IntHideType
			));
	}
*/
	g_fnRExFreePool(DriverObjectStruct);
	return;
}