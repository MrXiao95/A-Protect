/*
д��ǰ��Ļ���
���YYYͬѧ�ڷ���ĳһ�������ʱ�򣬱�XXX��Ϊ����͵ZZZ�Ĵ��룬Ȼ��XXX�ͺܲ�ˬ��������YYYͬѧ����Ϣ����������ľ�����
����˵���ǣ�����Ա�ǵ��£�˭д���벻��A��Aȥ�ġ�
XXXͬѧûA����ZZZͬѧ��û���ù�ctrl+c��ctrl+v�𣿻������˼ҵĸ�����Ϣ�������ַ���˽����Ϊ��ʮ����Ľ�����������ʦ�ˡ�
�������ڵĻ����治�ʺ�free��open��share��
�Һܴ󷽵ĳ��ϣ�A�ܵĴ���98%����A�ģ����ڴ���ų������Ͻ��������~~
PS���İ�Ȩ��ͬѧ�Ժ������׶��Ǵ��׵�~
�м������ⷢemail��hack.x86.asm@gmail.com
or QQ:136618866
*/
#include "ntifs.h"
#include "services.h"
#include "SafeSystem.h"
//#pragma code_seg("INIT")
/////////////////////////////////////////////////////////
VOID DriverUnload(IN PDRIVER_OBJECT	DriverObject)
{
	DbgPrint("Driver Unload Called\n");
}

VOID IsKernelBooting(IN PVOID Context)
{
	NTSTATUS status;
	PUCHAR fnKiFastCallEntry;
	ULONG EProcess;
	int i=0;
	ULONG ImageBase;

	if (PsGetProcessCount() <= 2)
		bKernelBooting = TRUE;
	else 
		goto _InitThread;  
	while (1)
	{
		if (bKernelBooting)
		{
			if (PsGetProcessCount() >= 3)
			{
				break;
			}
		}
		WaitMicroSecond(88);
	}
	if (IsRegKeyInSystem(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\KeBugCheck")){
		return;
	}
	KeBugCheckCreateValueKey(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\KeBugCheck");
_InitThread:
	//��ȡKiFastCallEntry
	_asm
	{
		pushad;
		mov ecx, 0x176;
		rdmsr;//ִ����� �ὫKiFastCallEntry�ĵ�ַ����Eax
		mov fnKiFastCallEntry, eax;
		popad;
	}
	//�ж�KiFastCallEntryͷ����û�б�hook e9==jmp
	if (*fnKiFastCallEntry == 0xe9)
	{
		DbgPrint("Terminate System Thread\n");
		return;
	}
	//�ں�����
	if (ReLoadNtos(g_pDriverObject,RetAddress) == STATUS_SUCCESS)
	{
		PsSetLoadImageNotifyRoutine(ImageNotify);
		if (bKernelBooting)
		{
			DepthServicesRegistry = (PSERVICESREGISTRY)ExAllocatePool(NonPagedPool,sizeof(SERVICESREGISTRY)*1024);
			if (DepthServicesRegistry)
			{
				memset(DepthServicesRegistry,0,sizeof(SERVICESREGISTRY)*1024);
				status = QueryServicesRegistry(DepthServicesRegistry);
				if (status == STATUS_SUCCESS)
				{
 					Safe_CreateValueKey(
 						L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\A-Protect",
						REG_SZ,L"QueryServicesRegistry",L"success");
				}
			}
		}
	}
	bKernelBooting = FALSE;
}

NTSTATUS DriverEntry( IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING theRegistryPath )
{
	ULONG ulSize;
	ULONG ulKeServiceDescriptorTable;
	int i = 0;
	HANDLE hThreadHandle;

	pDriverObject->DriverUnload = DriverUnload;
	g_pDriverObject = pDriverObject;
	//��ȡ���ص�ַ
	RetAddress=*(DWORD*)((DWORD)&pDriverObject-4);
	g_ulMyDriverBase =(ULONG) pDriverObject->DriverStart;
	g_ulMyDriverSize = pDriverObject->DriverSize;
	g_bDebugOn = TRUE;  //������ʽ��Ϣ
	DbgPrint("//***************************************//\r\n"
	       	"//   A-Protect Anti-Rootkit Kernel Module  //\r\n"
			"//   Kernel Module Version LE 2012-0.4.4  //\r\n"
		   "//  website:http://www.3600safe.com       //\r\n"
	      "//***************************************//\r\n");
	//��������system���أ����������ǻ�ȡsystem��_EPROCESS
	g_systemEProcess = PsGetCurrentProcess();
	g_WinVersion = GetWindowsVersion();
	if (g_WinVersion)
		DbgPrint("Init Windows version Success\r\n");
	DepthServicesRegistry = NULL;
	if (PsCreateSystemThread(&hThreadHandle,0,NULL,NULL,NULL,IsKernelBooting,NULL) == STATUS_SUCCESS)
	{
		ZwClose(hThreadHandle);
	}
	return STATUS_SUCCESS;
}