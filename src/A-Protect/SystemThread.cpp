// SystemThread.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-Protectview.h"
#include "SystemThread.h"

void QuerySystemThread(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	DWORD dwReadByte;
	int i=0;
	SetDlgItemTextW(m_hWnd,ID,L"����ɨ��ϵͳ�̣߳����Ժ�...");

	SHFILEINFO shfileinfo;
	SystemThreadImg.Create(16,16, ILC_COLOR32, 2, 80);
	HIMAGELIST hImageList = NULL;

	if (bIsPhysicalCheck){
		SaveToFile("\r\n\r\n[---ϵͳ�߳�---]\r\n",PhysicalFile);
	}

	if (SystemThread)
	{
		VirtualFree(SystemThread,sizeof(SYSTEM_THREAD_INFO)*257,MEM_RESERVE | MEM_COMMIT);
		SystemThread = NULL;
	}
	SystemThread = (PSYSTEM_THREAD_INFO)VirtualAlloc(0, sizeof(SYSTEM_THREAD_INFO)*257,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (SystemThread)
	{
		memset(SystemThread,0,sizeof(SYSTEM_THREAD_INFO)*257);

		ReadFile((HANDLE)LIST_SYSTEM_THREAD,SystemThread, sizeof(SYSTEM_THREAD_INFO)*257,&dwReadByte,0);

		for ( i=0;i< (int)SystemThread->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",SystemThread->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzThreadID[256];
			WCHAR lpwzKernelThread[256];
			WCHAR lpwzTEB[256];
			WCHAR lpwzThreadStart[256];
			WCHAR lpwzHideDebug[256];            //�����0������ʾ��ɫ
			WCHAR lpwzThreadModule[256];
			WCHAR lpwzWaitStatus[256];

			WCHAR lpwzPriority[256];    //���ȼ�
			WCHAR lpwzContextSwitches[256];

			memset(lpwzThreadID,0,sizeof(lpwzThreadID));
			memset(lpwzKernelThread,0,sizeof(lpwzKernelThread));
			memset(lpwzTEB,0,sizeof(lpwzTEB));
			memset(lpwzThreadStart,0,sizeof(lpwzThreadStart));
			memset(lpwzHideDebug,0,sizeof(lpwzHideDebug));
			memset(lpwzThreadModule,0,sizeof(lpwzThreadModule));
			memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));

			memset(lpwzPriority,0,sizeof(lpwzPriority));
			memset(lpwzContextSwitches,0,sizeof(lpwzContextSwitches));

			wsprintfW(lpwzThreadID,L"%d",SystemThread->SystemThreadInfo[i].ThreadID);
			wsprintfW(lpwzHideDebug,L"%X",SystemThread->SystemThreadInfo[i].HideDebug);
			wsprintfW(lpwzKernelThread,L"0x%08X",SystemThread->SystemThreadInfo[i].KernelThread);

			if (SystemThread->SystemThreadInfo[i].TEB)
				wsprintfW(lpwzTEB,L"0x%08X",SystemThread->SystemThreadInfo[i].TEB);
			else
				wsprintfW(lpwzTEB,L"%ws",L"-");

			wsprintfW(lpwzThreadStart,L"0x%08X",SystemThread->SystemThreadInfo[i].ThreadStart);
			wsprintfW(lpwzPriority,L"%d",SystemThread->SystemThreadInfo[i].ulPriority);
			wsprintfW(lpwzContextSwitches,L"%d",SystemThread->SystemThreadInfo[i].ulContextSwitches);

			switch (SystemThread->SystemThreadInfo[i].ulStatus)
			{
			case StateInitialized:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Initialized");
				break;
			case StateReady:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Ready");
				break;
			case StateRunning:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Running");
				break;
			case StateStandby:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Standby");
				break;
			case StateTerminated:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Terminated");
				break;
			case StateWaiting:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Waiting");
				break;
			case StateTransition:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Transition");
				break;
			case StateUnknown:
				memset(lpwzWaitStatus,0,sizeof(lpwzWaitStatus));
				wcscat_s(lpwzWaitStatus,L"Unknown");
				break;
			}
			MultiByteToWideChar(
				CP_ACP,
				0,
				SystemThread->SystemThreadInfo[i].lpszThreadModule,
				strlen(SystemThread->SystemThreadInfo[i].lpszThreadModule),
				lpwzThreadModule,
				sizeof(lpwzThreadModule)
				);
			/////////////////////////////
			/////
			WCHAR lpwzDosFullPath[256];
			WCHAR lpwzWinDir[256];
			WCHAR lpwzSysDisk[256];

			memset(lpwzWinDir,0,sizeof(lpwzWinDir));
			memset(lpwzSysDisk,0,sizeof(lpwzSysDisk));

			GetWindowsDirectoryW(lpwzWinDir,sizeof(lpwzWinDir));
			memcpy(lpwzSysDisk,lpwzWinDir,4);

			if (wcsstr(lpwzThreadModule,L"Unknown") != NULL)
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat_s(lpwzDosFullPath,lpwzThreadModule);
				goto Next;
			}

			if (wcsstr(lpwzThreadModule,L"\\??\\"))
			{
				//��ʼ����·���Ĵ���
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcsncat(lpwzDosFullPath,lpwzThreadModule+wcslen(L"\\??\\"),wcslen(lpwzThreadModule)-wcslen(L"\\??\\"));
				goto Next;
			}
			if (wcsstr(lpwzThreadModule,L"\\WINDOWS\\system32\\"))
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat_s(lpwzDosFullPath,lpwzSysDisk);
				wcscat_s(lpwzDosFullPath,lpwzThreadModule);
				goto Next;
			}
			if (wcsstr(lpwzThreadModule,L"\\SystemRoot\\"))
			{
				WCHAR lpwzTemp[256];
				memset(lpwzTemp,0,sizeof(lpwzTemp));
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat_s(lpwzTemp,lpwzSysDisk);
				wcscat_s(lpwzTemp,L"\\WINDOWS\\");
				wcscat_s(lpwzDosFullPath,lpwzTemp);
				wcsncat(lpwzDosFullPath+wcslen(lpwzTemp),lpwzThreadModule+wcslen(L"\\SystemRoot\\"),wcslen(lpwzThreadModule) - wcslen(L"\\SystemRoot\\"));
				goto Next;
			}
			if (!wcsstr(lpwzThreadModule,L"\\"))
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat_s(lpwzDosFullPath,lpwzSysDisk);
				wcscat_s(lpwzDosFullPath,L"\\WINDOWS\\system32\\drivers\\");
				wcscat_s(lpwzDosFullPath,lpwzThreadModule);
				goto Next;
			}
Next:
			/////
			//����MD5
			//����md5
			char lpszFullPath[5024] = {0};
			WCHAR lpwzMD5[256];
			WCHAR lpwzTrue[256];

			memset(lpszFullPath,0,sizeof(lpszFullPath));
			memset(lpwzMD5,0,sizeof(lpwzMD5));
			memset(lpwzTrue,0,sizeof(lpwzTrue));
			WideCharToMultiByte( CP_ACP,
				0,
				lpwzDosFullPath,
				-1,
				lpszFullPath,
				wcslen(lpwzDosFullPath)*2,
				NULL,
				NULL);
			FILE * fp=fopen(lpszFullPath,"rb");
			if(fp)
			{
				MD5VAL val;
				val = md5File(fp);
				wsprintfW(lpwzMD5,L"%08x%08x%08x%08x",conv(val.a),conv(val.b),conv(val.c),conv(val.d));
				FileVerify(lpszFullPath,lpwzMD5,lpwzTrue);
				//MessageBoxW(lpwzDosFullPath,lpwzMD5,0);
				fclose(fp);
			}
			//�ļ�������
			if (GetFileAttributesA(lpszFullPath) == -1)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat_s(lpwzTrue,L"�ļ������ڣ��޷���֤");
			}
			///////////////////////////////////////////
			//������һ���������ݣ�����Ҫ���������
			if (bIsPhysicalCheck){
				//���û��hook���ͷ���
				if (!SystemThread->SystemThreadInfo[i].HideDebug ||
					_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0 ||
					SystemThread->SystemThreadInfo[i].ulHideType == 1)   //HideDebug = 0 ����ʾ��ɫ

				{
					WCHAR lpwzSaveBuffer[1024] ={0};
					CHAR lpszSaveBuffer[2024] ={0};
					memset(lpwzSaveBuffer,0,sizeof(lpwzSaveBuffer));
					memset(lpszSaveBuffer,0,sizeof(lpszSaveBuffer));

					wsprintfW(lpwzSaveBuffer,L"          --> ���ֲ���ȫϵͳ�̣߳��߳�ID:%ws | �߳����:%ws | �߳�ģ��:%ws | �߳�״̬:%ws\r\n",
						lpwzThreadID,lpwzThreadStart,lpwzDosFullPath,lpwzWaitStatus);

					m_list->InsertItem(0,L"ϵͳ�߳�",RGB(77,77,77));
					m_list->SetItemText(0,1,lpwzSaveBuffer);

					WideCharToMultiByte( CP_ACP,
						0,
						lpwzSaveBuffer,
						-1,
						lpszSaveBuffer,
						wcslen(lpwzSaveBuffer)*2,
						NULL,
						NULL
						);
					SaveToFile(lpszSaveBuffer,PhysicalFile);
				}
				continue;
			}
			switch (SystemThread->SystemThreadInfo[i].ulHideType)
			{
			case 0:
				if (!SystemThread->SystemThreadInfo[i].HideDebug ||
					_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0)   //HideDebug = 0 ����ʾ��ɫ
				{
					m_list->InsertItem(i,lpwzThreadID,RGB(238,118,0));
				}else
					m_list->InsertItem(i,lpwzThreadID,RGB(77,77,77));

				break;
			case 1:
				m_list->InsertItem(i,lpwzThreadID,RGB(255,20,147));
				break;
			}
			m_list->SetItemText(i,1,lpwzKernelThread);
			m_list->SetItemText(i,2,lpwzTEB);
			m_list->SetItemText(i,3,lpwzThreadStart);
			m_list->SetItemText(i,4,lpwzHideDebug);

			m_list->SetItemText(i,5,lpwzPriority);
			m_list->SetItemText(i,6,lpwzContextSwitches);
			
			m_list->SetItemText(i,7,lpwzDosFullPath);
			m_list->SetItemText(i,8,lpwzWaitStatus);
			m_list->SetItemText(i,9,lpwzTrue);

			hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzDosFullPath,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
			SystemThreadImg.Add(shfileinfo.hIcon);
			m_list->SetImageList(&SystemThreadImg);
			m_list->SetItemImageId(i,i);
			DestroyIcon(shfileinfo.hIcon);
		}
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"ϵͳ�߳�ɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

}
BOOL IsNumber(char *lpszNumber);

void KillThread(HWND hWnd,CMyList *m_list,HANDLE ulCommand)
{
	CString PidNum;
	DWORD dwReadByte;

	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	PidNum.Format(L"%s",m_list->GetItemText(Item,0));

	WCHAR lpwzNum[50];
	char lpszNum[50];

	memset(lpszNum,0,sizeof(lpszNum));
	memset(lpwzNum,0,sizeof(lpwzNum));
	wcscat_s(lpwzNum,PidNum);

	if (!wcslen(lpwzNum))
	{
		return;
	}
	if ((ULONG)ulCommand == KILL_SYSTEM_THREAD)
	{
		if (MessageBoxW(hWnd,L"�����߳��п���ʹϵͳ�������Ƿ�ȷ����\r\n",L"A�ܵ��Է���",MB_YESNO | MB_ICONWARNING) == IDNO)
		{
			return;
		}
	}
	WideCharToMultiByte (CP_OEMCP,NULL,lpwzNum,-1,lpszNum,wcslen(lpwzNum)*2,NULL,FALSE);
	//if (IsNumber(lpszNum))
	//{
		for (int i=0;i<(int)SystemThread->ulCount;i++)
		{
			if (SystemThread->SystemThreadInfo[i].ThreadID == atoi(lpszNum))
			{
				ReadFile(ulCommand,0,SystemThread->SystemThreadInfo[i].KernelThread,&dwReadByte,0);
				break;
			}
		}
	//}
}
void KillSystemThread(HWND hWnd,ULONG ID,CMyList *m_list)
{
	KillThread(hWnd,m_list,(HANDLE)KILL_SYSTEM_THREAD);

	m_list->DeleteAllItems();
	QuerySystemThread(hWnd,ID,m_list);
}
//��ͣ�߳�
void SuspendThread(HWND hWnd,CMyList *m_list)
{
	KillThread(hWnd,m_list,(HANDLE)SUSPEND_THREAD);
}
//�ָ��߳�����
void ResumeThread(HWND hWnd,CMyList *m_list)
{
	KillThread(hWnd,m_list,(HANDLE)RESUME_THREAD);
}