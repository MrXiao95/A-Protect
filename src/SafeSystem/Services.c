#include "Services.h"



NTSTATUS QueryServicesRegistry(PSERVICESREGISTRY ServicesRegistry)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	WCHAR InterfacesPath[] = L"\\Parameters\\";
	WCHAR DriverServiceNamePath[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
	OBJECT_ATTRIBUTES NetworkClassKeyObject;
	OBJECT_ATTRIBUTES SubKeyObject;
	HANDLE NetworkClassKeyHandle;
	HANDLE SubKeyHandle;
	ULONG i, SubkeyIndex, ResultLength, InterfacesKeyStringLength;
	PWCHAR InterfacesKeyString;
	UNICODE_STRING NetworkClassKey, InterfacesKey, ServiceDll, DriverServiceName, ImagePath;
	PKEY_BASIC_INFORMATION KeyInformation;
	PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation;

	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwOpenKey),L"ZwOpenKey",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExAllocatePool),L"ExAllocatePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);

	ReLoadNtosCALL((PVOID)(&g_fnRZwEnumerateKey),L"ZwEnumerateKey",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwQueryValueKey),L"ZwQueryValueKey",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRZwClose),L"ZwClose",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRRtlInitUnicodeString &&
		g_fnRZwOpenKey &&
		g_fnRExAllocatePool &&
		g_fnRExFreePool &&
		g_fnRZwEnumerateKey &&
		g_fnRZwQueryValueKey &&
		g_fnRZwClose)
	{
		bInit = TRUE;
	}
	if (!bInit)
	{
		return Status;
	}
	if (g_bDebugOn)
		KdPrint(("Starting"));

	g_fnRRtlInitUnicodeString(&ServiceDll, L"ServiceDll");
	g_fnRRtlInitUnicodeString(&ImagePath, L"ImagePath");
	g_fnRRtlInitUnicodeString(&NetworkClassKey,DriverServiceNamePath);

	InitializeObjectAttributes(
		&NetworkClassKeyObject, 
		&NetworkClassKey, 
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL
		);
	Status = g_fnRZwOpenKey(
		&NetworkClassKeyHandle, 
		KEY_ALL_ACCESS, 
		&NetworkClassKeyObject
		);
	if (!NT_SUCCESS(Status))
	{
		if (g_bDebugOn)
			DbgPrint("Failed to open Network Class key\n");

		return Status;
	}
	if (g_bDebugOn)
		KdPrint(("ZwOpenKey success"));

	SubkeyIndex = 0;
	i = 0;

	while ((Status = g_fnRZwEnumerateKey(NetworkClassKeyHandle, SubkeyIndex, KeyBasicInformation, NULL, 0, &ResultLength)) != STATUS_NO_MORE_ENTRIES) 
	{
		if ((Status != STATUS_SUCCESS) && (Status != STATUS_BUFFER_OVERFLOW) && (Status != STATUS_BUFFER_TOO_SMALL))
		{
			if (g_bDebugOn)
				DbgPrint("ZwEnumerateKey 1 failed in SetupRegistry (%lx)\n", Status);
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
		if ((KeyInformation = (PKEY_BASIC_INFORMATION)g_fnRExAllocatePool(NonPagedPool, ResultLength)) == NULL)
		{
			if (g_bDebugOn)
				DbgPrint("ExAllocatePool KeyData failed in SetupRegistry\n");
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
		memset(KeyInformation,0,ResultLength);
		Status = g_fnRZwEnumerateKey(
			NetworkClassKeyHandle,
			SubkeyIndex, 
			KeyBasicInformation, 
			KeyInformation, 
			ResultLength, 
			&ResultLength
			);
		if (!NT_SUCCESS(Status))
		{
			if (g_bDebugOn)
				DbgPrint("ZwEnumerateKey 2 failed in SetupRegistry\n");

			Status = STATUS_UNSUCCESSFUL;
			g_fnRExFreePool(KeyInformation);
			break;
		}
		//键值
		//DbgPrint("KeyInformation:%ws\n",KeyInformation->Name);
		memset(ServicesRegistry->SrvReg[i].lpwzSrvName,0,sizeof(ServicesRegistry->SrvReg[i].lpwzSrvName));
		SafeCopyMemory(KeyInformation->Name,ServicesRegistry->SrvReg[i].lpwzSrvName,KeyInformation->NameLength);

		if (g_bDebugOn)
			KdPrint(("RZwEnumerateKey success:%ws",ServicesRegistry->SrvReg[i].lpwzSrvName));

		//读取 ImagePath
		g_fnRRtlInitUnicodeString(&DriverServiceName,ServicesRegistry->SrvReg[i].lpwzSrvName);

		InitializeObjectAttributes(
			&SubKeyObject, 
			&DriverServiceName, 
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
			NetworkClassKeyHandle, 
			NULL
			);
		Status = g_fnRZwOpenKey(
			&SubKeyHandle, 
			KEY_ALL_ACCESS, 
			&SubKeyObject
			);
		if (NT_SUCCESS(Status)) 
		{
			if ((Status = g_fnRZwQueryValueKey(SubKeyHandle, &ImagePath, KeyValuePartialInformation, NULL, 0, &ResultLength)) != STATUS_OBJECT_NAME_NOT_FOUND)
			{
				if ((Status != STATUS_SUCCESS) && (Status != STATUS_BUFFER_OVERFLOW) && (Status != STATUS_BUFFER_TOO_SMALL))
				{
					g_fnRZwClose(SubKeyHandle);
					g_fnRExFreePool(KeyInformation);
					break;
				}
				KeyValueInformation = (PKEY_VALUE_PARTIAL_INFORMATION)g_fnRExAllocatePool(NonPagedPool, ResultLength);
				if (KeyValueInformation)
				{
					memset(KeyValueInformation,0,ResultLength);
					Status = g_fnRZwQueryValueKey(
						SubKeyHandle, 
						&ImagePath, 
						KeyValuePartialInformation,
						KeyValueInformation,
						ResultLength, 
						&ResultLength
						);
					if (NT_SUCCESS(Status))
					{
						//DbgPrint("ImagePath:%ws\n",KeyValueInformation->Data);
						memset(ServicesRegistry->SrvReg[i].lpwzImageName,0,sizeof(ServicesRegistry->SrvReg[i].lpwzImageName));
						if (MmIsAddressValidEx(KeyValueInformation->Data) &&
							KeyValueInformation->DataLength > 0)
						{
							SafeCopyMemory(KeyValueInformation->Data,ServicesRegistry->SrvReg[i].lpwzImageName,KeyValueInformation->DataLength);
							if (g_bDebugOn)
								KdPrint(("lpwzImageName success:%ws",ServicesRegistry->SrvReg[i].lpwzImageName));
						}
					}
					g_fnRExFreePool(KeyValueInformation);
				}

			}
			g_fnRZwClose(SubKeyHandle);
		}
		//开始读取Parameters
		InterfacesKeyStringLength = KeyInformation->NameLength + sizeof(InterfacesPath);
		InterfacesKeyString = (PWCHAR)g_fnRExAllocatePool(NonPagedPool, InterfacesKeyStringLength);
		if (!InterfacesKeyString)
		{
			Status = STATUS_UNSUCCESSFUL;
			g_fnRExFreePool(KeyInformation);
			break;
		}
		memset(InterfacesKeyString,0,InterfacesKeyStringLength);
		memcpy(InterfacesKeyString, KeyInformation->Name, KeyInformation->NameLength);
		memcpy(&InterfacesKeyString[(KeyInformation->NameLength / sizeof(WCHAR))], InterfacesPath, sizeof(InterfacesPath));

		g_fnRRtlInitUnicodeString(&InterfacesKey, InterfacesKeyString);
		//Parameters
		//DbgPrint("KeyInformation:%ws\n",InterfacesKeyString);

		//如果打开成功，说明是svchost启动，则读取servicedll
		InitializeObjectAttributes(
			&SubKeyObject, 
			&InterfacesKey, 
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
			NetworkClassKeyHandle, 
			NULL
			);
		Status = g_fnRZwOpenKey(
			&SubKeyHandle, 
			KEY_ALL_ACCESS, 
			&SubKeyObject
			);
		if (NT_SUCCESS(Status)) 
		{
			if ((Status = g_fnRZwQueryValueKey(SubKeyHandle, &ServiceDll, KeyValuePartialInformation, NULL, 0, &ResultLength)) != STATUS_OBJECT_NAME_NOT_FOUND)
			{
				if ((Status != STATUS_SUCCESS) && (Status != STATUS_BUFFER_OVERFLOW) && (Status != STATUS_BUFFER_TOO_SMALL))
				{
					g_fnRZwClose(SubKeyHandle);
					g_fnRExFreePool(InterfacesKeyString);
					g_fnRExFreePool(KeyInformation);
					break;
				}
				KeyValueInformation = (PKEY_VALUE_PARTIAL_INFORMATION)g_fnRExAllocatePool(NonPagedPool, ResultLength);
				if (KeyValueInformation)
				{
					memset(KeyValueInformation,0,ResultLength);
					Status = g_fnRZwQueryValueKey(
						SubKeyHandle, 
						&ServiceDll, 
						KeyValuePartialInformation,
						KeyValueInformation,
						ResultLength, 
						&ResultLength
						);
					if (NT_SUCCESS(Status))
					{
						//DbgPrint("KeyValueInformation:%ws\n",KeyValueInformation->Data);
						memset(ServicesRegistry->SrvReg[i].lpwzDLLPath,0,sizeof(ServicesRegistry->SrvReg[i].lpwzDLLPath));
						if (MmIsAddressValidEx(KeyValueInformation->Data) &&
							KeyValueInformation->DataLength > 0)
						{
							SafeCopyMemory(KeyValueInformation->Data,ServicesRegistry->SrvReg[i].lpwzDLLPath,KeyValueInformation->DataLength);
						}
					}
					g_fnRExFreePool(KeyValueInformation);
				}
				
			}
			g_fnRZwClose(SubKeyHandle);
		}
		g_fnRExFreePool(InterfacesKeyString);
 		g_fnRExFreePool(KeyInformation);

		InterfacesKeyString = NULL;
		KeyInformation = NULL;

		i++;
		SubkeyIndex++;
	}
	ServicesRegistry->ulCount = SubkeyIndex;

	if (NetworkClassKeyHandle)
		g_fnRZwClose(NetworkClassKeyHandle);

	if (ServicesRegistry->ulCount > 10)
	{
		Status = STATUS_SUCCESS;
	}
	return Status;        
}
NTSTATUS _stdcall NewZwSetValueKey(
	__in      HANDLE KeyHandle,
	__in      PUNICODE_STRING ValueName,
	__in_opt  ULONG TitleIndex,
	__in      ULONG Type,
	__in_opt  PVOID Data,
	__in      ULONG DataSize
	)
{
	NTSTATUS Status;
	ZWSETVALUEKEY OldZwSetValueKey;
	PVOID KeyObject;
	POBJECT_NAME_INFORMATION KeyNameInfo;
	WCHAR *KeyPath = NULL;
	UNICODE_STRING UnicodeRegLocation;
	UNICODE_STRING UnicodeComPareKey;
	UNICODE_STRING UnicodeStartValueName;
	UNICODE_STRING UnicodeServiceDllValueName;
	UNICODE_STRING UnicodeImagePathValueName;
	BOOL bInitApi = FALSE;
	BOOL bIsTrue = FALSE;
	KPROCESSOR_MODE PreviousMode;

	if (!g_bIsInitSuccess)
		goto _FunctionRet;

	//初步过滤
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		goto _FunctionRet;

	if (g_fnRPsGetCurrentProcess)
	{
		if (g_fnRPsGetCurrentProcess() == g_protectEProcess)
		{
			goto _FunctionRet;
		}
	}
	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByHandle),L"ObReferenceObjectByHandle",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&RPsGetCurrentProcessId),L"PsGetCurrentProcessId",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRRtlCompareUnicodeString),L"RtlCompareUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExAllocatePool),L"ExAllocatePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRExFreePool),L"ExFreePool",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRObReferenceObjectByHandle &&
		RPsGetCurrentProcessId &&
		g_fnRRtlInitUnicodeString &&
		g_fnRRtlCompareUnicodeString &&
		g_fnRExAllocatePool &&
		g_fnRExFreePool)
	{
		bInitApi = TRUE;
	}
	if (!bInitApi)
		goto _FunctionRet;

	//严格判断下PUNICODE_STRING ValueName
	if (ValueName &&
		ValidateUnicodeString(ValueName) &&
		ValueName->Length > 0 &&
		ValueName->Buffer != 0)
	{
		//只监控这三个键值
		g_fnRRtlInitUnicodeString(&UnicodeStartValueName,L"Start");
		g_fnRRtlInitUnicodeString(&UnicodeServiceDllValueName,L"ServiceDll");
		g_fnRRtlInitUnicodeString(&UnicodeImagePathValueName,L"ImagePath");
		
		if (g_fnRRtlCompareUnicodeString(&UnicodeStartValueName,ValueName,TRUE) == 0 ||
			g_fnRRtlCompareUnicodeString(&UnicodeServiceDllValueName,ValueName,TRUE) == 0 ||
			g_fnRRtlCompareUnicodeString(&UnicodeImagePathValueName,ValueName,TRUE) == 0)
		{
			bIsTrue = TRUE;
		}
		if (!bIsTrue)
			goto _FunctionRet;

		if (bDisResetSrv == FALSE)  //禁止服务回写
			return STATUS_UNSUCCESSFUL;

		if (!ARGUMENT_PRESENT(KeyHandle))
			goto _FunctionRet;

		PreviousMode = KeGetPreviousMode();
		if (PreviousMode != KernelMode)
		{
			__try{
				ProbeForRead(KeyHandle,sizeof(HANDLE),sizeof(ULONG));
			}__except (EXCEPTION_EXECUTE_HANDLER) {
				goto _FunctionRet;
			}
		}
		Status = g_fnRObReferenceObjectByHandle(
			KeyHandle,
			0,
			NULL,
			KernelMode,
			&KeyObject,
			NULL
			);
		if (NT_SUCCESS(Status))
		{
			ObDereferenceObject(KeyObject);

			__try
			{
				if (SafeQueryNameString(KeyObject,&KeyNameInfo) == STATUS_SUCCESS)
				{
					if (ValidateUnicodeString(&KeyNameInfo->Name) &&
						KeyNameInfo->Name.Length > 0 &&
						KeyNameInfo->Name.Buffer != 0)
					{
						KeyPath = (WCHAR *)g_fnRExAllocatePool(NonPagedPool,KeyNameInfo->Name.Length*sizeof(WCHAR));
						if (!KeyPath)
						{
							if (KeyNameInfo)
								g_fnRExFreePool(KeyNameInfo);
							goto _FunctionRet;
						}
						//L"\\Registry\\Machine\\SYSTEM\\ControlSet001\\services"
						g_fnRRtlInitUnicodeString(&UnicodeRegLocation,L"\\Registry\\Machine\\SYSTEM\\ControlSet001\\serviceS");

						if (KeyNameInfo->Name.Length > UnicodeRegLocation.Length &&
							Data != NULL &&
							MmIsAddressValidEx(Data) &&
							DataSize > 0 &&
							DataSize < 1024)
						{
							memset(KeyPath,0,KeyNameInfo->Name.Length*sizeof(WCHAR));
							SafeCopyMemory(KeyNameInfo->Name.Buffer,KeyPath,UnicodeRegLocation.Length); //和谐copy相等长度的，不然见到蓝蓝的天空~~~~~

							g_fnRRtlInitUnicodeString(&UnicodeComPareKey,KeyPath);
							if (g_fnRRtlCompareUnicodeString(&UnicodeRegLocation,&UnicodeComPareKey,TRUE) == 0)  //不区分大小写
							{
								if (g_bDebugOn)
									KdPrint(("ValueName:%ws Key:%ws\r\n",ValueName->Buffer,KeyNameInfo->Name.Buffer));

								if (g_pLogDefenseInfo->ulCount < 1000 &&
									ulLogCount < 1000)   //记录超过1000条，则不记录。
								{
									g_pLogDefenseInfo->LogDefense[ulLogCount].Type = 5;  //服务监控
									g_pLogDefenseInfo->LogDefense[ulLogCount].EProcess = (ULONG)g_fnRPsGetCurrentProcess();
									g_pLogDefenseInfo->LogDefense[ulLogCount].ulInheritedFromProcessId = GetInheritedProcessPid(g_fnRPsGetCurrentProcess());
									g_pLogDefenseInfo->LogDefense[ulLogCount].ulPID = (ULONG)RPsGetCurrentProcessId();

									memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess));
									memset(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents,0,sizeof(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents));
									//下面开始记录
									switch (Type)
									{
									case REG_SZ:
										SafeCopyMemory(KeyNameInfo->Name.Buffer,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,KeyNameInfo->Name.Length);
										swprintf(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents,L"%ws ==> %ws",ValueName->Buffer,Data);
										break;
									case REG_EXPAND_SZ:
										SafeCopyMemory(KeyNameInfo->Name.Buffer,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,KeyNameInfo->Name.Length);
										swprintf(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents,L"%ws ==> %ws",ValueName->Buffer,Data);
										break;
									case REG_DWORD:
										SafeCopyMemory(KeyNameInfo->Name.Buffer,g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzCreateProcess,KeyNameInfo->Name.Length);
										swprintf(g_pLogDefenseInfo->LogDefense[ulLogCount].lpwzMoreEvents,L"%ws ==> %d",ValueName->Buffer,*(PULONG)Data);
										break;
									}
									ulLogCount++;
								}
							}
						}
					}
					if (KeyPath)
						g_fnRExFreePool(KeyPath);

					if (KeyNameInfo)
						g_fnRExFreePool(KeyNameInfo);
				}
			}__except (EXCEPTION_EXECUTE_HANDLER) {
				goto _FunctionRet;
			}
		}
	}

_FunctionRet:

	if (MmIsAddressValidEx((PVOID)g_pOriginalServiceDescriptorTable->ServiceTable[ZwSetValueKeyIndex]))
		OldZwSetValueKey =(ZWSETVALUEKEY) g_pOriginalServiceDescriptorTable->ServiceTable[ZwSetValueKeyIndex];
	else
		OldZwSetValueKey = (ZWSETVALUEKEY)KeServiceDescriptorTable->ServiceTable[ZwSetValueKeyIndex];

	return OldZwSetValueKey(
		KeyHandle,
		ValueName,
		TitleIndex,
		Type,
		Data,
		DataSize
		);
}
BOOL InitZwSetValueKey()
{
	UNICODE_STRING UnicdeFunction;

	//RtlInitUnicodeString(&UnicdeFunction,L"ZwWriteFile");
	if (SystemCallEntryTableHook(
		(PUNICODE_STRING)("ZwSetValueKey"),
		&ZwSetValueKeyIndex,
		(DWORD)NewZwSetValueKey) == TRUE)
	{
		if (g_bDebugOn)
			KdPrint(("Create Control Thread success 5\r\n"));
	}
	return TRUE;
}