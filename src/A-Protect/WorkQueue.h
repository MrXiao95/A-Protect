#include "stdafx.h"
//---------------------------------------------------------------------------------------
//���������߳�
//---------------------------------------------------------------------------------------
typedef struct _WORKQUEUE_INFORMATION {          //WORKQUEUE_INFORMATION
	ULONG ulEthread;
	PUCHAR ulBasePriority;
	ULONG ulWorkerRoutine;
	CHAR lpszModule[256];                    //
	ULONG SuspendCount;               //��ͣ����
} WORKQUEUE_INFORMATION, *PWORKQUEUE_INFORMATION;
typedef struct _WORKQUEUE {          //���������߳�
	ULONG ulCount;
	WORKQUEUE_INFORMATION WorkQueueInfo[1];
} WORKQUEUE, *PWORKQUEUE;
PWORKQUEUE WorkQueueThread;
CImageList WorkQueueImg;//ͼ��