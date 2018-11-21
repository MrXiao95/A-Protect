#include "DeleteFile.h"

HANDLE
SkillIoOpenFile(
				IN PCWSTR FileName,
				IN ACCESS_MASK DesiredAccess,
				IN ULONG ShareAccess
				)
{
	NTSTATUS              ntStatus;
	UNICODE_STRING        uniFileName;
	OBJECT_ATTRIBUTES     objectAttributes;
	HANDLE                ntFileHandle;
	IO_STATUS_BLOCK       ioStatus;
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRRtlInitUnicodeString),L"RtlInitUnicodeString",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoCreateFile),L"IoCreateFile",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRRtlInitUnicodeString &&
		g_fnRIoCreateFile)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return 0;

	g_fnRRtlInitUnicodeString(&uniFileName, FileName);

	InitializeObjectAttributes(&objectAttributes, &uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = g_fnRIoCreateFile(&ntFileHandle,
		DesiredAccess,
		&objectAttributes,
		&ioStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		ShareAccess,
		FILE_OPEN,
		0,
		NULL,
		0,
		0,
		NULL,
		IO_NO_PARAMETER_CHECKING);

	if (!NT_SUCCESS(ntStatus))
	{
		return 0;
	}

	return ntFileHandle;
}

NTSTATUS
SkillSetFileCompletion(
					   IN PDEVICE_OBJECT DeviceObject,
					   IN PIRP Irp,
					   IN PVOID Context
					   )
{
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRKeSetEvent),L"KeSetEvent",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRKeSetEvent)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return STATUS_UNSUCCESSFUL;

	Irp->UserIosb->Status = Irp->IoStatus.Status;
	Irp->UserIosb->Information = Irp->IoStatus.Information;

	g_fnRKeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

BOOLEAN
SKillStripFileAttributes(
						 IN HANDLE    FileHandle
						 )
{
	NTSTATUS          ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT      fileObject;
	PDEVICE_OBJECT    DeviceObject;
	PIRP              Irp;
	KEVENT            event;
	FILE_BASIC_INFORMATION    FileInformation;
	IO_STATUS_BLOCK ioStatus;
	PIO_STACK_LOCATION irpSp;

	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByHandle),L"ObReferenceObjectByHandle",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRKeInitializeEvent),L"KeInitializeEvent",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoAllocateIrp),L"IoAllocateIrp",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoCallDriver),L"IoCallDriver",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRKeWaitForSingleObject),L"KeWaitForSingleObject",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRObReferenceObjectByHandle &&
		g_fnRKeInitializeEvent &&
		g_fnRIoAllocateIrp &&
		g_fnRIoCallDriver &&
		g_fnRKeWaitForSingleObject)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return FALSE;

	ntStatus = g_fnRObReferenceObjectByHandle(FileHandle,
		DELETE,
		*IoFileObjectType,
		KernelMode,
		&fileObject,
		NULL);

	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}

	DeviceObject = IoGetRelatedDeviceObject(fileObject);
	Irp = g_fnRIoAllocateIrp(DeviceObject->StackSize, TRUE);

	if (Irp == NULL)
	{
		ObDereferenceObject(fileObject);
		return FALSE;
	}

	g_fnRKeInitializeEvent(&event, SynchronizationEvent, FALSE);

	memset(&FileInformation,0,0x28);

	FileInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &event;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_BASIC_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileBasicInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;

	IoSetCompletionRoutine(
		Irp,
		SkillSetFileCompletion,
		&event,
		TRUE,
		TRUE,
		TRUE);

	g_fnRIoCallDriver(DeviceObject, Irp);

	g_fnRKeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);

	ObDereferenceObject(fileObject);

	return TRUE;
}


BOOLEAN
SKillDeleteFile(
				IN HANDLE    FileHandle
				)
{
	NTSTATUS          ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT      fileObject;
	PDEVICE_OBJECT    DeviceObject;
	PIRP              Irp;
	KEVENT            event;
	FILE_DISPOSITION_INFORMATION    FileInformation;
	IO_STATUS_BLOCK ioStatus;
	PIO_STACK_LOCATION irpSp;
	PSECTION_OBJECT_POINTERS pSectionObjectPointer;     ////////////////////
	BOOL bInit = FALSE;

	ReLoadNtosCALL((PVOID)(&g_fnRObReferenceObjectByHandle),L"ObReferenceObjectByHandle",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRKeInitializeEvent),L"KeInitializeEvent",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoAllocateIrp),L"IoAllocateIrp",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRIoCallDriver),L"IoCallDriver",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	ReLoadNtosCALL((PVOID)(&g_fnRKeWaitForSingleObject),L"KeWaitForSingleObject",g_pOldSystemKernelModuleBase,(ULONG)g_pNewSystemKernelModuleBase);
	if (g_fnRObReferenceObjectByHandle &&
		g_fnRKeInitializeEvent &&
		g_fnRIoAllocateIrp &&
		g_fnRIoCallDriver &&
		g_fnRKeWaitForSingleObject)
	{
		bInit = TRUE;
	}
	if (!bInit)
		return FALSE;

	SKillStripFileAttributes( FileHandle);          //ȥ��ֻ�����ԣ�����ɾ��ֻ���ļ�

	ntStatus = g_fnRObReferenceObjectByHandle(FileHandle,
		DELETE,
		*IoFileObjectType,
		KernelMode,
		&fileObject,
		NULL);

	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}

	DeviceObject = IoGetRelatedDeviceObject(fileObject);
	Irp = g_fnRIoAllocateIrp(DeviceObject->StackSize, TRUE);
	if (Irp == NULL)
	{
		ObDereferenceObject(fileObject);
		return FALSE;
	}

	g_fnRKeInitializeEvent(&event, SynchronizationEvent, FALSE);

	FileInformation.DeleteFile = TRUE;

	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &event;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;


	IoSetCompletionRoutine(
		Irp,
		SkillSetFileCompletion,
		&event,
		TRUE,
		TRUE,
		TRUE);

	//�ټ������������д��� ��MmFlushImageSection    ����ͨ������ṹ������Ƿ����ɾ���ļ���
	//�����Hook
	ulImageSectionObject = 0;
	ulDataSectionObject = 0;
	ulSharedCacheMap = 0;

	pSectionObjectPointer = NULL;
	pSectionObjectPointer = fileObject->SectionObjectPointer;
	if (MmIsAddressValidEx(pSectionObjectPointer))
	{
		ulImageSectionObject = (ULONG)pSectionObjectPointer->ImageSectionObject; // ����֮~~~
		pSectionObjectPointer->ImageSectionObject = 0; //���㣬׼��ɾ��

		ulDataSectionObject =(ULONG) pSectionObjectPointer->DataSectionObject;  //����֮
		pSectionObjectPointer->DataSectionObject = 0;       //���㣬׼��ɾ��

		ulSharedCacheMap = (ULONG)pSectionObjectPointer->SharedCacheMap;
		pSectionObjectPointer->SharedCacheMap = 0;
	}

	//��irpɾ��
	g_fnRIoCallDriver(DeviceObject, Irp);

	//�ȴ��������
	g_fnRKeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);

	//ɾ���ļ�֮�󣬴ӱ�������������
	pSectionObjectPointer = NULL;
	pSectionObjectPointer = fileObject->SectionObjectPointer;

	if (MmIsAddressValidEx(pSectionObjectPointer))
	{
		if (ulImageSectionObject)
			pSectionObjectPointer->ImageSectionObject =(PVOID) ulImageSectionObject; //����������Ȼ����Ŷ

		if (ulDataSectionObject)
			pSectionObjectPointer->DataSectionObject =(PVOID) ulDataSectionObject;

		if (ulSharedCacheMap)
			pSectionObjectPointer->SharedCacheMap =(PVOID) ulSharedCacheMap;
	}

	ObDereferenceObject(fileObject);
	fileObject = NULL;

	return TRUE;
}