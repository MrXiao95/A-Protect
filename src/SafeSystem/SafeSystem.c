/*
写在前面的话：
最近YYY同学在发布某一个代码的时候，被XXX认为是在偷ZZZ的代码，然后XXX就很不爽的人肉了YYY同学的信息。这是事情的经过。
我想说的是，程序员那点事，谁写代码不是A来A去的。
XXX同学没A过吗？ZZZ同学就没有用过ctrl+c和ctrl+v吗？还发布人家的个人信息，这是侵犯隐私的行为，十几年的教育都还给老师了。
看来国内的环境真不适合free、open、share。
我很大方的承认，A盾的代码98%都是A的，现在代码放出来，赶紧来认领吧~~
PS：改版权的同学以后买套套都是穿孔的~
有技术问题发email：hack.x86.asm@gmail.com
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
	//获取KiFastCallEntry
	_asm
	{
		pushad;
		mov ecx, 0x176;
		rdmsr;//执行这个 会将KiFastCallEntry的地址放入Eax
		mov fnKiFastCallEntry, eax;
		popad;
	}
	//判断KiFastCallEntry头部有没有被hook e9==jmp
	if (*fnKiFastCallEntry == 0xe9)
	{
		DbgPrint("Terminate System Thread\n");
		return;
	}
	//内核重载
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
	//获取返回地址
	RetAddress=*(DWORD*)((DWORD)&pDriverObject-4);
	g_ulMyDriverBase =(ULONG) pDriverObject->DriverStart;
	g_ulMyDriverSize = pDriverObject->DriverSize;
	g_bDebugOn = TRUE;  //开启调式信息
	DbgPrint("//***************************************//\r\n"
	       	"//   A-Protect Anti-Rootkit Kernel Module  //\r\n"
			"//   Kernel Module Version LE 2012-0.4.4  //\r\n"
		   "//  website:http://www.3600safe.com       //\r\n"
	      "//***************************************//\r\n");
	//驱动是由system加载，所以这里是获取system的_EPROCESS
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