#include "stdafx.h"
#include "A-ProtectView.h"
#include "HipsLog.h"
#include "A-Protect.h"

BOOL PrintfDosPath(__in LPCTSTR lpwzNtFullPath,__out LPCTSTR lpwzCreateProcess);

void GetSaveFileLog(WCHAR *lpwzFilePath)
{
	CString			m_path;
	WCHAR lpwzForMat[256];
	DWORD dwReadByte;

	memset(lpwzFilePath,0,sizeof(lpwzFilePath));
	memset(lpwzForMat,0,sizeof(lpwzForMat));

	//��ͣ��Ȼ�޷���Ϊ������win7���޷��򿪶Ի���
	ReadFile((HANDLE)SUSPEND_PROTECT,0,0,&dwReadByte,0);

	CFileDialog dlg( FALSE,L"txt",0, OFN_OVERWRITEPROMPT|OFN_HIDEREADONLY,L"�����ļ�|*.*");
	dlg.m_ofn.lpstrTitle= L"���������־���ļ�";
	if ( dlg.DoModal() == IDOK )
	{
		m_path = dlg.GetPathName();
		wsprintfW(lpwzFilePath,L"%ws",m_path);

		ReadFile((HANDLE)RESUME_PROTECT,0,0,&dwReadByte,0);

// 		wsprintfW(lpwzForMat,L"�����ɹ�����¼�ļ�������:%ws",m_path);
// 		MessageBoxW(lpwzForMat,0,MB_ICONWARNING);
	}
	//�ټ��������Լ��Ľ���
	ReadFile((HANDLE)RESUME_PROTECT,0,0,&dwReadByte,0);
}
VOID HipsLog(HWND m_hWnd,ULONG ID,CMyList *m_list,int Type)
{
	DWORD dwReadByte;
	int i=0;
	int ItemNum = m_list->GetItemCount();
	WCHAR lpwzFilePath[256];
	BOOL bIsSaveLogFile = FALSE;

	CMyAProtectApp *imgApp=(CMyAProtectApp*)AfxGetApp();
	SHFILEINFO shfileinfo;
	HipsLogImg.Create(16,16, ILC_COLOR32, 2, 500);
	HIMAGELIST hImageList = NULL;
	bool HasFile=TRUE;

	SetDlgItemText(m_hWnd,ID,L"����ɨ�������־�����Ժ�...");
	if (bIsPhysicalCheck){
		SaveToFile("\r\n\r\n[---��������---]\r\n",PhysicalFile);
	}
	LogDefenseInfo = (PLOGDEFENSE)VirtualAlloc(0, sizeof(LOGDEFENSE)*1025,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (LogDefenseInfo)
	{
		ReadFile((HANDLE)LIST_LOG,LogDefenseInfo,sizeof(LOGDEFENSE)*1025,&dwReadByte,0);

		//������־��
		if (Type == 1)
		{
			GetSaveFileLog(lpwzFilePath);
			bIsSaveLogFile = TRUE;
		}
		if (LogDefenseInfo->ulCount >= 1024)
		{
			if (MessageBoxW(m_hWnd,L"������־�Ѿ����ڴ棬�޷��ڼ�¼���Ƿ񵼳����ļ���",L"A�ܵ��Է���",MB_YESNO | MB_ICONWARNING) == IDYES)
			{
				GetSaveFileLog(lpwzFilePath);
				bIsSaveLogFile = TRUE;
			}
		}
		for (i=0;i<(int) LogDefenseInfo->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",LogDefenseInfo->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzType[100];
			WCHAR lpwzPID[100];
			WCHAR lpwzInherited[100];
			WCHAR lpwzProName[256];
			WCHAR lpwzEProcess[100];
			WCHAR lpwzMoreEvents[1024];

			memset(lpwzType,0,sizeof(lpwzType));
			memset(lpwzPID,0,sizeof(lpwzPID));
			memset(lpwzInherited,0,sizeof(lpwzInherited));
			memset(lpwzProName,0,sizeof(lpwzProName));
			memset(lpwzEProcess,0,sizeof(lpwzEProcess));
			memset(lpwzMoreEvents,0,sizeof(lpwzMoreEvents));

			if (LogDefenseInfo->LogDefense[i].Type == 1)
			{
				wcscat(lpwzType,L"���̽���");
				if (LogDefenseInfo->LogDefense[i].ulPID)
					wsprintfW(lpwzMoreEvents,L"����[[%d]��ͼ���� A�ܵ��Է������ѱ���ֹ",LogDefenseInfo->LogDefense[i].ulPID);
				else
					wcscat(lpwzMoreEvents,L"(���˳�)����[Unknown]��ͼ���� A�ܵ��Է������ѱ���ֹ");

			}else if (LogDefenseInfo->LogDefense[i].Type == 2)
			{
				wcscat(lpwzType,L"��������");

				if (LogDefenseInfo->LogDefense[i].ulPID)
					wsprintfW(lpwzMoreEvents,L"����[[%d]��ͼ��������(��ͨ)",LogDefenseInfo->LogDefense[i].ulPID);
				else
					wcscat(lpwzMoreEvents,L"(���˳�)����[Unknown]��ͼ��������(��ͨ)");
			}
			else if (LogDefenseInfo->LogDefense[i].Type == 3)
			{
				wcscat(lpwzType,L"���̴���");

				if (LogDefenseInfo->LogDefense[i].ulPID)
					wsprintfW(lpwzMoreEvents,L"����[%d]�������̣����ɵ�ľ����Ϊ(��������Լ������Ļ�)/(Σ��)",LogDefenseInfo->LogDefense[i].ulPID);
				else
					wcscat(lpwzMoreEvents,L"(���˳�)����[Unknown]�������̣����ɵ�ľ����Ϊ(��������Լ������Ļ�)/(Σ��)");

			}else if (LogDefenseInfo->LogDefense[i].Type == 4)
			{
				wcscat(lpwzType,L"DLLЮ��");

				if (LogDefenseInfo->LogDefense[i].ulPID)
					wsprintfW(lpwzMoreEvents,L"���ֽ���[%d]��DllЮ�֣��Ѿܾ���",LogDefenseInfo->LogDefense[i].ulPID);
			}
			else if (LogDefenseInfo->LogDefense[i].Type == 5)
			{
				wcscat(lpwzType,L"ϵͳ���񴴽����޸�");

				if (LogDefenseInfo->LogDefense[i].ulPID)
					wsprintfW(lpwzMoreEvents,L"����[%d]��ͼ����/�޸�һ������:%ws",LogDefenseInfo->LogDefense[i].ulPID,LogDefenseInfo->LogDefense[i].lpwzMoreEvents);
			}
			else if (LogDefenseInfo->LogDefense[i].Type == 6)
			{
				wcscat(lpwzType,L"��������");

				wcscat(lpwzMoreEvents,L"һ�����������ѱ����ؽ�ϵͳ�ںˣ����������ʶ���������������ϵͳ�ѱ�rootkit����");
			}
			wsprintfW(lpwzPID,L"%d",LogDefenseInfo->LogDefense[i].ulPID);
			wsprintfW(lpwzInherited,L"%d",LogDefenseInfo->LogDefense[i].ulInheritedFromProcessId);

			if (strlen(LogDefenseInfo->LogDefense[i].lpszProName))
			{
				MultiByteToWideChar(CP_ACP,0,LogDefenseInfo->LogDefense[i].lpszProName,strlen(LogDefenseInfo->LogDefense[i].lpszProName),lpwzProName,sizeof(lpwzProName));
			}else
				wcscat(lpwzProName,L"Unknown");

			WCHAR lpwzCreateProcess[260];
			memset(lpwzCreateProcess,0,sizeof(lpwzCreateProcess));

			//�����DLLЮ�֣����ӡ����·��
			if (LogDefenseInfo->LogDefense[i].Type == 4)
			{
				PrintfDosPath(LogDefenseInfo->LogDefense[i].lpwzCreateProcess,lpwzCreateProcess);
			}
			else if (LogDefenseInfo->LogDefense[i].Type == 6)
			{
				WCHAR lpwzWinDir[256];
				WCHAR lpwzSysDisk[256];
				WCHAR lpwzHookModuleImage[256];

				memset(lpwzWinDir,0,sizeof(lpwzWinDir));
				memset(lpwzSysDisk,0,sizeof(lpwzSysDisk));
				memset(lpwzCreateProcess,0,sizeof(lpwzCreateProcess));
				memset(lpwzHookModuleImage,0,sizeof(lpwzHookModuleImage));

				wcscat(lpwzHookModuleImage,LogDefenseInfo->LogDefense[i].lpwzCreateProcess);

				GetWindowsDirectoryW(lpwzWinDir,sizeof(lpwzWinDir));
				memcpy(lpwzSysDisk,lpwzWinDir,4);

				if (wcsstr(lpwzHookModuleImage,L"\\??\\"))
				{
					//��ʼ����·���Ĵ���
					memset(lpwzCreateProcess,0,sizeof(lpwzCreateProcess));
					wcsncpy(lpwzCreateProcess,lpwzHookModuleImage+wcslen(L"\\??\\"),wcslen(lpwzHookModuleImage)-wcslen(L"\\??\\"));
					goto Next;
				}
				if (wcsstr(lpwzHookModuleImage,L"\\WINDOWS\\system32\\"))
				{
					memset(lpwzCreateProcess,0,sizeof(lpwzCreateProcess));
					wcscat(lpwzCreateProcess,lpwzSysDisk);
					wcscat(lpwzCreateProcess,lpwzHookModuleImage);
					//MessageBoxW(lpwzCreateProcess,lpwzFullSysName,0);
					goto Next;
				}
				if (wcsstr(lpwzHookModuleImage,L"\\SystemRoot\\"))
				{
					WCHAR lpwzTemp[256];
					memset(lpwzTemp,0,sizeof(lpwzTemp));
					memset(lpwzCreateProcess,0,sizeof(lpwzCreateProcess));
					wcscat(lpwzTemp,lpwzSysDisk);
					wcscat(lpwzTemp,L"\\WINDOWS\\");
					wcscat(lpwzCreateProcess,lpwzTemp);
					wcsncpy(lpwzCreateProcess+wcslen(lpwzTemp),lpwzHookModuleImage+wcslen(L"\\SystemRoot\\"),wcslen(lpwzHookModuleImage) - wcslen(L"\\SystemRoot\\"));
					goto Next;
				}
				memset(lpwzCreateProcess,0,sizeof(lpwzCreateProcess));
				wcscat(lpwzCreateProcess,lpwzSysDisk);
				wcscat(lpwzCreateProcess,L"\\WINDOWS\\system32\\drivers\\");
				wcscat(lpwzCreateProcess,lpwzHookModuleImage);
			}else{
				wcscat(lpwzCreateProcess,LogDefenseInfo->LogDefense[i].lpwzCreateProcess);
			}
Next:
			char lpszDLLPath[256] = {0};
			WCHAR lpwzMd5[256] = {0};
			WCHAR lpwzTrue[256] = {0};

			memset(lpszDLLPath,0,sizeof(lpszDLLPath));
			memset(lpwzMd5,0,sizeof(lpwzMd5));
			memset(lpwzTrue,0,sizeof(lpwzTrue));
			if (LogDefenseInfo->LogDefense[i].Type == 3 ||
				LogDefenseInfo->LogDefense[i].Type == 4 ||
				LogDefenseInfo->LogDefense[i].Type == 6)
			{
				WideCharToMultiByte( CP_ACP,
					0,
					lpwzCreateProcess,
					-1,
					lpszDLLPath,
					wcslen(lpwzCreateProcess)*2,
					NULL,
					NULL
					);
				FILE * fp=fopen(lpszDLLPath,"rb");
				if(fp)
				{
					MD5VAL val;
					val = md5File(fp);
					wsprintfW(lpwzMd5,L"%08x%08x%08x%08x",conv(val.a),conv(val.b),conv(val.c),conv(val.d));
					FileVerify(lpszDLLPath,lpwzMd5,lpwzTrue);

					fclose(fp);
				}
			}
			if (LogDefenseInfo->LogDefense[i].EProcess)
			{
				if (LogDefenseInfo->LogDefense[i].Type == 6)
					wsprintfW(lpwzEProcess,L"������ַ:0x%08X",LogDefenseInfo->LogDefense[i].EProcess);
				else
					wsprintfW(lpwzEProcess,L"0x%08X",LogDefenseInfo->LogDefense[i].EProcess);

			}
			else{

				if (LogDefenseInfo->LogDefense[i].Type == 6)
					wcscat(lpwzEProcess,L"������ж��");
				else
					wcscat(lpwzEProcess,L"-");
			}

			WCHAR lpwzLog[1024];
			CHAR lpszLog[2024];
			//�����ļ�
			if (bIsSaveLogFile)
			{
				memset(lpwzLog,0,sizeof(lpwzLog));
				memset(lpszLog,0,sizeof(lpszLog));
				wsprintfW(lpwzLog,L"����ID:%ws\r\n������ID:%ws\r\nӳ��·��:%ws\r\nEPROCESS:%ws\r\n�¼�:%ws\r\n�¼���ϸ����:%ws\r\n����������:%ws\r\nMD5/����ǩ��:%ws\r\n\r\n",
								   lpwzPID,
								   lpwzInherited,
								   lpwzProName,
								   lpwzEProcess,
								   lpwzType,
								   lpwzMoreEvents,
								   lpwzCreateProcess,
								   lpwzTrue);

				WideCharToMultiByte( CP_ACP,
					0,
					lpwzLog,
					-1,
					lpszLog,
					wcslen(lpwzLog)*2,
					NULL,
					NULL
					);
				SaveToFile(lpszLog,lpwzFilePath);
			}
			if (!wcslen(lpwzProName))
			{
				wcscat_s(lpwzProName,L"-");
			}
			if (!wcslen(lpwzMoreEvents))
			{
				wcscat_s(lpwzMoreEvents,L"-");
			}
			if (!wcslen(lpwzCreateProcess))
			{
				wcscat_s(lpwzCreateProcess,L"-");
				HasFile=FALSE;
			}
			//������һ���������ݣ�����Ҫ���������
			if (bIsPhysicalCheck){
				//���û��hook���ͷ���
				if (_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0 ||
					_wcsnicmp(lpwzTrue,L"�ļ������ڣ��޷���֤",wcslen(L"�ļ������ڣ��޷���֤")) == 0 ||
					LogDefenseInfo->LogDefense[i].Type == 5)    //�����޸ķ���Ҫͻ��
				{
					WCHAR lpwzSaveBuffer[1024] ={0};
					CHAR lpszSaveBuffer[2024] ={0};
					memset(lpwzSaveBuffer,0,sizeof(lpwzSaveBuffer));
					memset(lpszSaveBuffer,0,sizeof(lpszSaveBuffer));

					wsprintfW(lpwzSaveBuffer,L"          --> ��������:����PID:%ws | ������:%ws | EPROCESS:%ws | �¼�:%ws | ����:%ws\r\n",
						lpwzPID,lpwzProName,lpwzEProcess,lpwzMoreEvents,lpwzCreateProcess);

					m_list->InsertItem(0,L"��������",RGB(77,77,77));
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
			if (_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0)
			{
				m_list->InsertItem(i,lpwzPID,RGB(255,20,147));

			}else
			{
				if (LogDefenseInfo->LogDefense[i].Type == 5 ||
					LogDefenseInfo->LogDefense[i].Type == 4 )  //�ر��ע��Ҫͻ��
					m_list->InsertItem(i,lpwzPID,RGB(255,20,147));
				else
					m_list->InsertItem(i,lpwzPID,RGB(77,77,77));
			}

			m_list->SetItemText(i,1,lpwzInherited);
			m_list->SetItemText(i,2,lpwzProName);
			m_list->SetItemText(i,3,lpwzEProcess);
			m_list->SetItemText(i,4,lpwzType);
			m_list->SetItemText(i,5,lpwzMoreEvents);
			m_list->SetItemText(i,6,lpwzCreateProcess);
			m_list->SetItemText(i,7,lpwzTrue);

			if(HasFile)
			{
				hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzCreateProcess,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
				HipsLogImg.Add(shfileinfo.hIcon);
			}else
			{
				HipsLogImg.Add(imgApp->LoadIconW(IDI_WHITE));
			}
			m_list->SetImageList(&HipsLogImg);
			m_list->SetItemImageId(i,i);
			DestroyIcon(shfileinfo.hIcon);
			HasFile=TRUE;
		}
		VirtualFree(LogDefenseInfo,sizeof(LOGDEFENSE)*1025,MEM_RESERVE | MEM_COMMIT);
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"������־ɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

	//����ǵ�����־�Ļ����Ͳ���Ҫ�����
	if (Type == 0 &&
		bIsSaveLogFile)
	{
		ReadFile((HANDLE)CLEAR_LIST_LOG,0,0,&dwReadByte,0);
		bIsSaveLogFile = FALSE;
	}
}
void ClearListLog(CMyList *m_list)
{
	DWORD dwReadByte;
	m_list->DeleteAllItems();
	ReadFile((HANDLE)CLEAR_LIST_LOG,0,0,&dwReadByte,0);
}
void ConnectScan(HWND m_hWnd)
{
	DWORD dwReadByte;
	if (MessageBoxW(m_hWnd,L"�˹��ܽ���ϵͳ�������Զ��ռ�ȫ���Ŀ�����Ϊ\r\nϵͳ�����������鿴������־������\r\n�Ƿ�������\r\n\r\n���ؾ��棺ʹ�ô˹������ȹرջ�����ͣɱ�����������ɱ�������ɾ��A���ͷŵ��ļ��ᵼ��ϵͳ��������\r\n"
		,L"A�ܵ��Է���",MB_YESNO | MB_ICONWARNING) == IDYES)
	{
		ReadFile((HANDLE)KERNEL_SAFE_MODULE,0,0,&dwReadByte,0);

		if (InstallDepthServicesScan("A-Protect"))
		{
			ReadFile((HANDLE)EXIT_PROCESS,0,0,&dwReadByte,0);
			Sleep(2000);
			ShutdownWindows(EWX_REBOOT | EWX_FORCE);
			ExitProcess(0);
		}
		ReadFile((HANDLE)NO_KERNEL_SAFE_MODULE,0,0,&dwReadByte,0);
	}
}
void SaveToFile(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	m_list->DeleteAllItems();
	HipsLog(m_hWnd,ID,m_list,1);
}