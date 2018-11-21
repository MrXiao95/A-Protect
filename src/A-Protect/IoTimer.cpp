#include "stdafx.h"
#include "A-ProtectView.h"
#include "IoTimer.h"

void QueryIoTimer(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	DWORD dwReadByte;
	int i=0;
	int ItemNum = m_list->GetItemCount();

	SHFILEINFO shfileinfo;
	IoTimerImg.Create(16,16, ILC_COLOR32, 2, 80);
	HIMAGELIST hImageList = NULL;

	SetDlgItemTextW(m_hWnd,ID,L"����ɨ��IoTimer�����Ժ�...");

	if (IoTimer)
	{
		VirtualFree(IoTimer,(sizeof(MyIoTimer)+sizeof(MyIoTimerInfo))*260,MEM_RESERVE | MEM_COMMIT);
		IoTimer = 0;
	}
	IoTimer = (PMyIoTimer)VirtualAlloc(0,(sizeof(MyIoTimer)+sizeof(MyIoTimerInfo))*260,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (IoTimer)
	{
		memset(IoTimer,0,(sizeof(MyIoTimer)+sizeof(MyIoTimerInfo))*260);

		ReadFile((HANDLE)LIST_IO_TIMER,IoTimer,(sizeof(MyIoTimer)+sizeof(MyIoTimerInfo))*260,&dwReadByte,0);

		for (i=0;i< (int)IoTimer->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",IoTimer->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzDeviceObject[256] = {0};
			WCHAR lpwzStatus[256] = {0};
			WCHAR lpwzIoRoutineAddress[256] = {0};
			WCHAR lpwzFullSysName[256] = {0};

			memset(lpwzDeviceObject,0,sizeof(lpwzDeviceObject));
			memset(lpwzStatus,0,sizeof(lpwzStatus));

			memset(lpwzIoRoutineAddress,0,sizeof(lpwzIoRoutineAddress));
			memset(lpwzFullSysName,0,sizeof(lpwzFullSysName));

			MultiByteToWideChar(
				CP_ACP,
				0, 
				IoTimer->MyTimer[i].lpszModule,
				-1, 
				lpwzFullSysName, 
				strlen(IoTimer->MyTimer[i].lpszModule)
				);
//********************************************************************
			WCHAR lpwzDosFullPath[256];
			WCHAR lpwzWinDir[256];
			WCHAR lpwzSysDisk[256];

			memset(lpwzWinDir,0,sizeof(lpwzWinDir));
			memset(lpwzSysDisk,0,sizeof(lpwzSysDisk));
			memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));

			GetWindowsDirectoryW(lpwzWinDir,sizeof(lpwzWinDir));
			memcpy(lpwzSysDisk,lpwzWinDir,4);

			if (wcsstr(lpwzFullSysName,L"\\??\\"))
			{
				//��ʼ����·���Ĵ���
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcsncpy(lpwzDosFullPath,lpwzFullSysName+wcslen(L"\\??\\"),wcslen(lpwzFullSysName)-wcslen(L"\\??\\"));
				goto Next;
			}
			if (wcsstr(lpwzFullSysName,L"\\WINDOWS\\system32\\"))
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat(lpwzDosFullPath,lpwzSysDisk);
				wcscat(lpwzDosFullPath,lpwzFullSysName);
				//MessageBoxW(lpwzDosFullPath,lpwzFullSysName,0);
				goto Next;
			}
			if (wcsstr(lpwzFullSysName,L"\\SystemRoot\\"))
			{
				WCHAR lpwzTemp[256];
				memset(lpwzTemp,0,sizeof(lpwzTemp));
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat(lpwzTemp,lpwzSysDisk);
				wcscat(lpwzTemp,L"\\WINDOWS\\");
				wcscat(lpwzDosFullPath,lpwzTemp);
				wcsncpy(lpwzDosFullPath+wcslen(lpwzTemp),lpwzFullSysName+wcslen(L"\\SystemRoot\\"),wcslen(lpwzFullSysName) - wcslen(L"\\SystemRoot\\"));
				goto Next;
			}
			if (!wcsstr(lpwzFullSysName,L"\\"))
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat(lpwzDosFullPath,lpwzSysDisk);
				wcscat(lpwzDosFullPath,L"\\WINDOWS\\system32\\drivers\\");
				wcscat(lpwzDosFullPath,lpwzFullSysName);
				goto Next;
			}
Next:

//********************************************************************
			wsprintfW(lpwzDeviceObject,L"0x%08X",IoTimer->MyTimer[i].DeviceObject);
			wsprintfW(lpwzIoRoutineAddress,L"0x%08X",IoTimer->MyTimer[i].IoTimerRoutineAddress);
			if (IoTimer->MyTimer[i].ulStatus == 0)
			{
				wcscat(lpwzStatus,L"ֹͣ");

			}else if (IoTimer->MyTimer[i].ulStatus == 1)
			{
				wcscat(lpwzStatus,L"����");
			}

			if (_wcsnicmp(lpwzDosFullPath,L"Unknown",wcslen(lpwzDosFullPath)) == 0)
			{
				m_list->InsertItem(i,lpwzDeviceObject,RGB(255,20,147));
			}else
			{
				m_list->InsertItem(i,lpwzDeviceObject,RGB(77,77,77));
			}
			m_list->SetItemText(i,1,lpwzIoRoutineAddress);
			m_list->SetItemText(i,2,lpwzStatus);
			m_list->SetItemText(i,3,lpwzDosFullPath);


			hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzDosFullPath,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
			IoTimerImg.Add(shfileinfo.hIcon);
			m_list->SetImageList(&IoTimerImg);
			m_list->SetItemImageId(i,i);
			DestroyIcon(shfileinfo.hIcon);
		}
	}else{
		WCHAR lpwzTextOut[100];
		memset(lpwzTextOut,0,sizeof(lpwzTextOut));
		wsprintfW(lpwzTextOut,L"�����ڴ���� ����������A��\r\n�������:%d\n",GetLastError());
		MessageBox(0,lpwzTextOut,0,0);
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"IoTimerɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);
}
/*
VOID KillIoTimerThread(int i)
{
	DWORD dwReadByte;

	ReadFile((HANDLE)KILL_Io_TIMER,0,IoTimer->MyTimer[i].TimerAddress,&dwReadByte,0);

	return;
}
*/
void IoTimerControl(HWND m_hWnd,ULONG ID,CMyList *m_list,ULONG ulCommand)
{
	DWORD dwReadByte;
	CString IoTimerNum;
	WCHAR lpwzAdd[50];

	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	//ȡdeviceobject
	IoTimerNum.Format(L"%s",m_list->GetItemText(Item,0));

	for (int i = 0;i< (int)IoTimer->ulCount;i++)
	{
		memset(lpwzAdd,0,sizeof(lpwzAdd));
		wsprintfW(lpwzAdd,L"0x%08X",IoTimer->MyTimer[i].DeviceObject);

		if (_wcsicmp(lpwzAdd,IoTimerNum) == 0)
		{
			ReadFile((HANDLE)ulCommand,0,IoTimer->MyTimer[i].DeviceObject,&dwReadByte,0);
			break;
		}
	}
	//ɾ����ǰѡ���һ��
	m_list->DeleteAllItems();
	QueryIoTimer(m_hWnd,ID,m_list);
}
void CopyIoTimerDataToClipboard(HWND m_hWnd,CMyList *m_list)
{
	CString FunctionName;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	FunctionName.Format(L"%s",m_list->GetItemText(Item,3));

	WCHAR lpwzFunctionName[260];

	memset(lpwzFunctionName,0,sizeof(lpwzFunctionName));
	wcscat_s(lpwzFunctionName,FunctionName);
	CHAR lpszFunctionName[1024];
	char *lpString = NULL;

	memset(lpwzFunctionName,0,sizeof(lpwzFunctionName));
	memset(lpszFunctionName,0,sizeof(lpszFunctionName));
	wcscat_s(lpwzFunctionName,FunctionName);
	WideCharToMultiByte( CP_ACP,
		0,
		lpwzFunctionName,
		-1,
		lpszFunctionName,
		wcslen(lpwzFunctionName)*2,
		NULL,
		NULL
		);
	lpString = setClipboardText(lpszFunctionName);
	if (lpString)
	{
		MessageBoxW(m_hWnd,L"�����ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
	}
}