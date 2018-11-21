#include "Startup.h"


//L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
NTSTATUS ReadRegistry(PSTARTUP_INFO Startup,WCHAR *DriverServiceNamePath,WCHAR *ReadKey)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	OBJECT_ATTRIBUTES NetworkClassKeyObject;
	OBJECT_ATTRIBUTES SubKeyObject;
	HANDLE NetworkClassKeyHandle;
	HANDLE SubKeyHandle;
	ULONG i, SubkeyIndex, ResultLength, InterfacesKeyStringLength;
	PWCHAR InterfacesKeyString;
	UNICODE_STRING NetworkClassKey, InterfacesKey, UnicodeReadKey, DriverServiceName;
	PKEY_BASIC_INFORMATION KeyInformation;
	PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation;
	WCHAR *KeyName = NULL;
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

	g_fnRRtlInitUnicodeString(&UnicodeReadKey,ReadKey);
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
	i = Startup->ulCount;

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
		if ((KeyName = (WCHAR *)g_fnRExAllocatePool(NonPagedPool, 260*sizeof(WCHAR))) == NULL){
			continue;
		}
		memset(KeyName,0,260*sizeof(WCHAR));
		SafeCopyMemory(KeyInformation->Name,KeyName,KeyInformation->NameLength);

		//KdPrint(("Key:%ws\n",KeyName));

		//读取UnicodeReadKey
		g_fnRRtlInitUnicodeString(&DriverServiceName,KeyName);
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
			if ((Status = g_fnRZwQueryValueKey(SubKeyHandle, &UnicodeReadKey, KeyValuePartialInformation, NULL, 0, &ResultLength)) != STATUS_OBJECT_NAME_NOT_FOUND)
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
						&UnicodeReadKey, 
						KeyValuePartialInformation,
						KeyValueInformation,
						ResultLength, 
						&ResultLength
						);
					if (NT_SUCCESS(Status))
					{
						//KdPrint(("%ws -> %ws\n",KeyName,KeyValueInformation->Data));
						if (MmIsAddressValidEx(KeyValueInformation->Data) &&
							KeyValueInformation->DataLength > 0)
						{
							SafeCopyMemory(DriverServiceName.Buffer,Startup->Startup[i].lpwzName,DriverServiceName.Length);
							SafeCopyMemory(DriverServiceNamePath,Startup->Startup[i].lpwzKeyPath,wcslen(DriverServiceNamePath)*2);
							SafeCopyMemory(KeyValueInformation->Data,Startup->Startup[i].lpwzKeyValue,KeyValueInformation->DataLength);
							i++;
		                    Startup->ulCount = i;

							if (g_bDebugOn)
								KdPrint(("%ws -> %ws\n",KeyName,KeyValueInformation->Data));
						}
					}
					g_fnRExFreePool(KeyValueInformation);
				}

			}
			g_fnRZwClose(SubKeyHandle);
		}
		g_fnRExFreePool(KeyName);
 		g_fnRExFreePool(KeyInformation);

		KeyName = NULL;
		KeyInformation = NULL;

		SubkeyIndex++;
	}

	if (NetworkClassKeyHandle)
		g_fnRZwClose(NetworkClassKeyHandle);

	return Status;        
}
VOID QueryStartup(PSTARTUP_INFO Startup)
{

	ReadRegistry(Startup,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",L"DllName");

	//其实是读取Winlogon下的Userinit、UIHost、Shell
	ReadRegistry(Startup,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"Userinit");
	ReadRegistry(Startup,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"UIHost");
	ReadRegistry(Startup,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"Shell");

	ReadRegistry(Startup,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components",L"Stubpath");

	ReadRegistry(Startup,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",L"Driver");
	ReadRegistry(Startup,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers",L"Name");
}