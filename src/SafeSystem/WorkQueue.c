#include "WorkQueue.h"

VOID QueryWorkQueue(PWORKQUEUE WorkQueueThread)
{
	ULONG ulBasePriority;
	ULONG ulKernelStack;

	ULONG ulSizeOfSystemWorkThread;
	ULONG ulSizeOfOtherWorkThread;

	ULONG ulSizeOfSystemWorkSuspendThread;
	ULONG ulSizeOfOtherWorkSuspendThread;

	ULONG ulSuspendCount;  //��ͣ�������kernelstack�ֲ�һ����
	ULONG SuspendCount;

	ULONG i=0,x=0;
	PEPROCESS Process;
	PETHREAD  Thread;
	BOOL bIsWorkTrue = FALSE;

	PUCHAR KernelStack = NULL;

	ULONG ulModuleBase;
	ULONG ulModuleSize;
	ULONG ulText;
	WIN_VER_DETAIL WinVer;
	PUCHAR BasePriority = 0;
	BYTE WorkThreadCode[1] = {0x6a};
	BYTE WorkThreadCode1[1] = {0x8b};
	int Index=0;

	//ThreadProc ThreadListHead
	IniOffsetObject();

	WinVer = GetWindowsVersion();
	switch (WinVer)
	{
	case WINDOWS_VERSION_XP:
		ulBasePriority = 0x06c;
		ulKernelStack = 0x028;
		ulSuspendCount = 0x1b9;

		ulSizeOfSystemWorkThread = 0x08c;
		ulSizeOfOtherWorkThread = 0x0a8;

		ulSizeOfSystemWorkSuspendThread = 0x12c;
	    ulSizeOfOtherWorkSuspendThread = 0x148;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		ulBasePriority = 0x121;
		ulKernelStack = 0x20;
		ulSuspendCount = 0x150;

		ulSizeOfSystemWorkThread = 0x0a8;
		ulSizeOfOtherWorkThread = 0x0c0;

		ulSizeOfSystemWorkSuspendThread = 0x170;
	    ulSizeOfOtherWorkSuspendThread = 0x188;
		break;
	case WINDOWS_VERSION_7_7000:
		ulBasePriority = 0x139;
		ulKernelStack = 0x30;
		ulSuspendCount = 0x18c;

		ulSizeOfSystemWorkThread = 0x182;
		ulSizeOfOtherWorkThread = 0x184;

		ulSizeOfSystemWorkSuspendThread = 0x364;
	    ulSizeOfOtherWorkSuspendThread = 0x364;
		break;
	case WINDOWS_VERSION_7_7600_UP:
		ulBasePriority = 0x135;
		ulKernelStack = 0x30;
		ulSuspendCount = 0x188;

		ulSizeOfSystemWorkThread = 0x128;
		ulSizeOfOtherWorkThread = 0x130;

		ulSizeOfSystemWorkSuspendThread = 0x270;
	    ulSizeOfOtherWorkSuspendThread = 0x278;
		break;
	}
	Process = g_systemEProcess;

	i=0;

	for (Thread = GetNextProcessThread(Process, NULL,TRUE);
		Thread != NULL;
		Thread = GetNextProcessThread(Process, Thread,TRUE))
	{
		BasePriority =(PUCHAR) ((ULONG)Thread+ulBasePriority);

		if (!PsIsThreadTerminating(Thread) &&
			MmIsAddressValidEx(BasePriority) &&
			MmIsAddressValidEx((PVOID)((ULONG)Thread+ulSuspendCount)))
		{
			bIsWorkTrue = FALSE;

			if (*BasePriority == 12 ||
				*BasePriority == 13 ||
				*BasePriority == 15)
			{
				bIsWorkTrue = TRUE;
			}
			if (!bIsWorkTrue){
				continue;
			}
			//��ȡ�߳���ͣ״̬ 0 Ϊ���� ������Ϊ��ͣ����
			SuspendCount = *(PULONG)((ULONG)Thread+ulSuspendCount);

			if (g_bDebugOn)
				KdPrint(("[%08x]SuspendCount:%d\n",Thread,SuspendCount));

			WorkQueueThread->WorkQueueInfo[i].ulBasePriority = (PUCHAR)(*BasePriority);
			WorkQueueThread->WorkQueueInfo[i].ulEthread =(ULONG) Thread;
			WorkQueueThread->WorkQueueInfo[i].SuspendCount = SuspendCount;

			KernelStack =(PUCHAR) (*(PULONG)((ULONG)Thread+ulKernelStack));

			//��ȡϵͳ�Ĺ����߳�
			if (SuspendCount){
				ulText =(ULONG) ((ULONG)KernelStack + ulSizeOfSystemWorkSuspendThread);  //������Ӳ���룬��ͣ�̵߳�ʱ��work��ڵ�ַƫ��
			}else{
				ulText =(ULONG) ((ULONG)KernelStack + ulSizeOfSystemWorkThread);  //������Ӳ���룬�߳�������ʱ��work��ڵ�ַƫ��
			}
			//����������RMmIsAddressValidEx�жϲ�׼ȷ����������~~
			//��������ʵ����û���ж�VCS_TRANSITION���ͣ��������Ҳ���޷����ʣ�
			if (MmIsAddressValidEx((PVOID)ulText))
			{
				x = *(PULONG)(ulText);
				if (MmIsAddressValidEx((PVOID)x))
				{
					//��������Ĺ���������һ���ļ��
					/*
					lkd> u 83CEB1D7
						nt!CcWorkerThread:
					83ceb1d7 6a2c            push    2Ch
					*/
					/*
					lkd> u 8AB06510
					8ab06510 8bff            mov     edi,edi
					8ab06512 55              push    ebp
					8ab06513 8bec            mov     ebp,esp
                    */
					if (memcmp((PVOID)x,(PVOID)WorkThreadCode,1) == 0 ||
						memcmp((PVOID)x,(PVOID)WorkThreadCode1,1) == 0)
					{
						//���

						WorkQueueThread->WorkQueueInfo[i].ulWorkerRoutine = x;
						memset(WorkQueueThread->WorkQueueInfo[i].lpszModule,0,sizeof(WorkQueueThread->WorkQueueInfo[i].lpszModule));
						if (!IsAddressInSystem(
							x,
							&ulModuleBase,
							&ulModuleSize,
							WorkQueueThread->WorkQueueInfo[i].lpszModule))
						{
							strcat(WorkQueueThread->WorkQueueInfo[i].lpszModule,"Unknown");
						}
					}
				}
			}

			//��ȡ������������
		    //�߳���ͣ�����ʱ���С�ͱ��ˡ�
			if (SuspendCount){
				ulText =(ULONG) ((ULONG)KernelStack + ulSizeOfOtherWorkSuspendThread);  //������Ӳ���룬��ͣ�̵߳�ʱ��work��ڵ�ַƫ��
			}else
				ulText =(ULONG) ((ULONG)KernelStack + ulSizeOfOtherWorkThread);  //������Ӳ���룬�߳�������ʱ��work��ڵ�ַƫ��

			//����������RMmIsAddressValidEx�жϲ�׼ȷ����������~~
			//��������ʵ����û���ж�VCS_TRANSITION���ͣ��������Ҳ���޷����ʣ�
			if (MmIsAddressValidEx((PVOID)ulText))
			{
				x = *(PULONG)(ulText);
				if (MmIsAddressValidEx((PVOID)x))
				{
					//��������Ĺ���������һ���ļ��
					/*
					lkd> u 83CEB1D7
						nt!CcWorkerThread:
					83ceb1d7 6a2c            push    2Ch
					*/
					/*
					lkd> u 8AB06510
					8ab06510 8bff            mov     edi,edi
					8ab06512 55              push    ebp
					8ab06513 8bec            mov     ebp,esp
                    */
					if (memcmp((PVOID)x,(PVOID)WorkThreadCode,1) == 0 ||
						memcmp((PVOID)x,(PVOID)WorkThreadCode1,1) == 0)
					{
							WorkQueueThread->WorkQueueInfo[i].ulWorkerRoutine = x;
							memset(WorkQueueThread->WorkQueueInfo[i].lpszModule,0,sizeof(WorkQueueThread->WorkQueueInfo[i].lpszModule));
							if (!IsAddressInSystem(
								x,
								&ulModuleBase,
								&ulModuleSize,
								WorkQueueThread->WorkQueueInfo[i].lpszModule))
							{
								strcat(WorkQueueThread->WorkQueueInfo[i].lpszModule,"Unknown");
							}
					}
				}
			}
			i++;
			WorkQueueThread->ulCount = i;
		}
	}
	if (g_bDebugOn){
		for (i=0;i<WorkQueueThread->ulCount;i++)
		{
			KdPrint(("[%d]���������߳�\r\n"
				"EHTREAD��%08X\r\n"
				"���ͣ�%d\r\n"
				"������ڣ�%08X\r\n"
				"�����������ģ�飺%s\r\n\r\n",
				i,
				WorkQueueThread->WorkQueueInfo[i].ulEthread,
				WorkQueueThread->WorkQueueInfo[i].ulBasePriority,
				WorkQueueThread->WorkQueueInfo[i].ulWorkerRoutine,
				WorkQueueThread->WorkQueueInfo[i].lpszModule));
		}
	}
	return;
}