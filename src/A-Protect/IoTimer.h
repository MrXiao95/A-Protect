#include "stdafx.h"
//***********************************************************
typedef struct _MyIoTimerInfo{
	ULONG  ulStatus;        //ѭ�����
	ULONG  DeviceObject;      //�豸����
	ULONG  IoTimerRoutineAddress;  //���̵�ַ
	char   lpszModule[260];
}MyIoTimerInfo,*PMyIoTimerInfo;
typedef struct _MyIoTimer{
	ULONG  ulCount;
	MyIoTimerInfo MyTimer[1];
}MyIoTimer,*PMyIoTimer;
PMyIoTimer IoTimer; 
CImageList IoTimerImg;// ����ͼ��
CHAR* setClipboardText(CHAR* str);