// Process.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-ProtectView.h"
#include "Process.h"
#include "A-Protect.h"/////////

BOOL VerifyEmbeddedSignature( LPCWSTR lpFileName );

LPSTR ExtractFileName(LPSTR lpcFullFileName)
{
	lpcFullFileName = strrchr(lpcFullFileName, '\\') + 1;
	return lpcFullFileName;
}
VOID QuerySystemProcess(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	DWORD dwReadByte;
	int ItemNum = m_list->GetItemCount();
	HANDLE hProcess;
	hProcess=(HANDLE)0;
	int i=0;
	//�������һ�����̣���Ȼ�޷��о����һ��ִ�еĽ���
	//hProcess = RunAProcess("ping 127.0.0.1 -n 100");
	//WinExec("ping 127.0.0.1 -n 5",SW_HIDE);

	if (bIsPhysicalCheck){
		SaveToFile("\r\n\r\n[---ϵͳ����---]\r\n",PhysicalFile);
	}
	SetDlgItemTextW(m_hWnd,ID,L"����ɨ��ϵͳ���̣����Ժ�...");

	if (NormalProcessInfo)
	{
		VirtualFree(NormalProcessInfo,sizeof(PROCESSINFO)*900,MEM_RESERVE | MEM_COMMIT);
		NormalProcessInfo = NULL;
	}

	NormalProcessInfo = (PPROCESSINFO)VirtualAlloc(0, sizeof(PROCESSINFO)*900,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NormalProcessInfo)
	{
		//Ϊ����ͼ�����
		SHFILEINFO shfileinfo;
		ProcessImg.Create(16,16, ILC_COLOR32, 2, 100);
		HIMAGELIST hImageList = NULL;
		CMyAProtectApp *imgApp=(CMyAProtectApp*)AfxGetApp();
		bool PathEmpty=true;

		memset(NormalProcessInfo,0,sizeof(PROCESSINFO)*900);
		ReadFile((HANDLE)LIST_PROCESS,NormalProcessInfo,sizeof(PROCESSINFO)*900,&dwReadByte,0);

		for ( i=0;i<(int)NormalProcessInfo->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",NormalProcessInfo->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzProcName[100];
			WCHAR lpwzPid[50];
			WCHAR lpwzInheritedPid[50];
			WCHAR lpwzFullProcName[256];

			WCHAR lpwzEProcess[100];
			WCHAR lpwzStatus[50];

			WCHAR lpwzFileServices[256];
			WCHAR lpwzTrue[256];

			memset(lpwzProcName,0,sizeof(lpwzProcName));
			memset(lpwzPid,0,sizeof(lpwzPid));
			memset(lpwzInheritedPid,0,sizeof(lpwzInheritedPid));
			memset(lpwzFullProcName,0,sizeof(lpwzFullProcName));
			memset(lpwzEProcess,0,sizeof(lpwzEProcess));
			memset(lpwzStatus,0,sizeof(lpwzStatus));
			memset(lpwzFileServices,0,sizeof(lpwzFileServices));

			//��ȡ����DOS·��
			WCHAR lpwzWinDir[256];
			WCHAR lpwzSysDisk[10];


			char  lpszString[256];
			char  lpszFullString[5024];
			WCHAR lpwzFullString[256];
			memset(lpszString,0,sizeof(lpszString));
			memset(lpszFullString,0,sizeof(lpszFullString));
			memset(lpwzFullString,0,sizeof(lpwzFullString));

			memset(lpwzTrue,0,sizeof(lpwzTrue));
			memset(lpwzWinDir,0,sizeof(lpwzWinDir));
			memset(lpwzSysDisk,0,sizeof(lpwzSysDisk));

			if (_wcsicmp(NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath,L"System") == 0)
			{
				wcscat(lpwzFullString,L"System");
				wcscat(lpwzProcName,L"System");
				goto Next;
			}
			if (_wcsicmp(NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath,L"System Idle") == 0)
			{
				wcscat(lpwzFullString,L"System Idle");
				wcscat(lpwzProcName,L"System Idle");
				goto Next;
			}

			if (wcsstr(NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath,L"\\Device\\") != NULL)
			{
				//��ʼ����dos·��
				NtFilePathToDosFilePath(NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath,lpwzFullString);
			}else
			{
				wcsncat(lpwzFullString,NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath,wcslen(NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath));
			}
			//----------------------
			WideCharToMultiByte( CP_ACP,
				0,
				lpwzFullString,
				-1,
				lpszFullString,
				wcslen(lpwzFullString)*2,
				NULL,
				NULL);
			char *p = strstr(lpszFullString,"\\");
			if (p)
			{
				wsprintfA(lpszString,"%s",ExtractFileName(lpszFullString));
				MultiByteToWideChar(
					CP_ACP,
					0, 
					lpszString,
					-1, 
					lpwzProcName, 
					strlen(lpszString)
					);
			}
			FILE * fp=fopen(lpszFullString,"rb");
			if(fp)
			{
				PathEmpty=false;
				if (!bIsProcMD5Check)
				{
					wcscat(lpwzTrue,L"δ֪(�Ҽ�ɨ��)");
					fclose(fp);
					goto Next;
				}
				MD5VAL val;
				val = md5File(fp);
				wsprintfW(lpwzFileServices,L"%08x%08x%08x%08x",conv(val.a),conv(val.b),conv(val.c),conv(val.d));
				FileVerify(lpszFullString,lpwzFileServices,lpwzTrue);
				fclose(fp);
			}
			//MessageBoxW(NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath,lpwzFullProcName,0);
Next:
			wsprintfW(lpwzPid,L"%d",NormalProcessInfo->ProcessInfo[i].ulPid);
			wsprintfW(lpwzInheritedPid,L"%d",NormalProcessInfo->ProcessInfo[i].ulInheritedFromProcessId);
			wsprintfW(lpwzEProcess,L"0x%08X",NormalProcessInfo->ProcessInfo[i].EProcess);
			//wsprintfW(lpwzStatus,L"%d",NormalProcessInfo->ProcessInfo[i].ulKernelOpen);

			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,NormalProcessInfo->ProcessInfo[i].ulPid);
			if (hProcess)
			{
				wcscat(lpwzStatus,L"Yes/");
				CloseHandle(hProcess);
			}else
				wcscat(lpwzStatus,L"No/");

			if (NormalProcessInfo->ProcessInfo[i].ulKernelOpen == 1)
			{
				wcscat(lpwzStatus,L"Yes");
			}else
				wcscat(lpwzStatus,L"No");

			//������һ���������ݣ�����Ҫ���������
			if (bIsPhysicalCheck){
				//���û��hook���ͷ���
				if (NormalProcessInfo->ProcessInfo[i].IntHideType == 1 ||
					_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0)
				{
					WCHAR lpwzSaveBuffer[1024] ={0};
					CHAR lpszSaveBuffer[2024] ={0};
					memset(lpwzSaveBuffer,0,sizeof(lpwzSaveBuffer));
					memset(lpszSaveBuffer,0,sizeof(lpszSaveBuffer));

					wsprintfW(lpwzSaveBuffer,L"          --> �����޷�ʶ����̣�����Pid:%ws | ������:%ws | EPROCESS:%ws | ����·��:%ws\r\n",
						lpwzPid,lpwzProcName,lpwzEProcess,lpwzFullString);

					m_list->InsertItem(0,L"ϵͳ����",RGB(77,77,77));
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
			if (NormalProcessInfo->ProcessInfo[i].IntHideType == 1)
			{
				m_list->InsertItem(i,lpwzPid,RGB(255,20,147));  //����
				memset(lpwzStatus,0,sizeof(lpwzStatus));
				wcscat(lpwzStatus,L"���ؽ���");
			}
			else
			{
				if (_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0)
				{
					m_list->InsertItem(i,lpwzPid,RGB(238,118,0));

				}
				else
				{
					if (!wcslen(lpwzProcName))
					{
						wcscat(lpwzFullString,L"* (Warning:�����ļ��ѱ��ƶ�)");
						PathEmpty=true;
						wcscat(lpwzProcName,L"*");
						m_list->InsertItem(i,lpwzPid,RGB(255,20,147));

					}else
						m_list->InsertItem(i,lpwzPid,RGB(77,77,77));

				}
			}

			//m_list->InsertItem(ItemNum,lpwzHideType);
			m_list->SetItemText(i,1,lpwzInheritedPid);
			m_list->SetItemText(i,2,lpwzProcName);
			m_list->SetItemText(i,3,lpwzFullString);
			m_list->SetItemText(i,4,lpwzEProcess);
			m_list->SetItemText(i,5,lpwzStatus);
			m_list->SetItemText(i,6,lpwzTrue);

			if(PathEmpty)
				ProcessImg.Add(imgApp->LoadIconW(IDI_WHITE));
			else
			{
				hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzFullString,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
				ProcessImg.Add(shfileinfo.hIcon);
			}
			m_list->SetImageList(&ProcessImg);
			m_list->SetItemImageId(i,i);
			DestroyIcon(shfileinfo.hIcon);
			PathEmpty=true;
		}
		//VirtualFree(NormalProcessInfo,sizeof(NormalProcessInfo)*1050*200,MEM_RESERVE | MEM_COMMIT);
	}else{
		WCHAR lpwzTextOut[100];
		memset(lpwzTextOut,0,sizeof(lpwzTextOut));
		wsprintfW(lpwzTextOut,L"�����ڴ���� ����������A��\r\n�������:%d\n",GetLastError());
		MessageBox(0,lpwzTextOut,0,0);
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"ϵͳ����ɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

}
void Processmodule()
{
}
extern BOOL IsNumber(char *lpszString);

void KillProcess(HWND hWnd,ULONG ID,CMyList *m_list)
{
	// TODO: �ڴ���������������
	//m_list->DeleteAllItems();
	//Insert();
	CString PidNum;
	DWORD dwReadByte;

	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	PidNum.Format(L"%s",m_list->GetItemText(Item,0));

	WCHAR lpwzNum[50];
	char lpszNum[50];

	memset(lpszNum,0,sizeof(lpszNum));
	memset(lpwzNum,0,sizeof(lpwzNum));
	wcscat(lpwzNum,PidNum);

	WideCharToMultiByte (CP_OEMCP,NULL,lpwzNum,-1,lpszNum,wcslen(lpwzNum)*2,NULL,FALSE);
	if (IsNumber(lpszNum))
	{
		if (MessageBoxW(hWnd,L"�������̿��ܵ���ϵͳ���ȶ�!!\r\n\r\n�Ƿ������\r\n",L"A�ܵ��Է���",MB_YESNO | MB_ICONWARNING) == IDYES)
		{
			for (int i=0;i<(int)NormalProcessInfo->ulCount;i++)
			{
				if (NormalProcessInfo->ProcessInfo[i].ulPid == atoi(lpszNum))
				{
					ReadFile((HANDLE)KILL_PROCESS_BY_PID,0,NormalProcessInfo->ProcessInfo[i].EProcess,&dwReadByte,0);
					break;
				}
			}
			m_list->DeleteAllItems();
			Sleep(1000);
			QuerySystemProcess(hWnd,ID,m_list);
		}
	}
}
void  KillProcessDeleteFile(HWND hWnd,ULONG ID,CMyList *m_list)
{
	// TODO: �ڴ���������������
	//m_list->DeleteAllItems();
	//Insert();
	CString PidNum;
	DWORD dwReadByte;


	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	PidNum.Format(L"%ws",m_list->GetItemText(Item,4));

	WCHAR lpwzNum[50];
	WCHAR lpszEProcessNum[50];

	memset(lpwzNum,0,sizeof(lpwzNum));
	wcscat(lpwzNum,PidNum);

	if (MessageBoxW(hWnd,L"������ɾ�������ļ������ܵ���ϵͳ���ȶ�!!\r\n\r\n�Ƿ������\r\n",L"A�ܵ��Է���",MB_YESNO | MB_ICONWARNING) == IDYES)
	{
		for (int i=0;i<(int)NormalProcessInfo->ulCount;i++)
		{
			memset(lpszEProcessNum,0,sizeof(lpszEProcessNum));
			wsprintfW(lpszEProcessNum,L"0x%x",NormalProcessInfo->ProcessInfo[i].EProcess);
			if (_wcsnicmp(lpszEProcessNum,lpwzNum,wcslen(lpwzNum)) == 0)
			{
				ReadFile((HANDLE)KILL_PROCESS_BY_PID,0,NormalProcessInfo->ProcessInfo[i].EProcess,&dwReadByte,0);

				WCHAR lpwzDeletedFile[256];
				memset(lpwzDeletedFile,0,sizeof(lpwzDeletedFile));
				wsprintfW(lpwzDeletedFile,L"%ws",NormalProcessInfo->ProcessInfo[i].lpwzFullProcessPath);

				ReadFile((HANDLE)DELETE_FILE,lpwzDeletedFile,wcslen(lpwzDeletedFile),&dwReadByte,0);
				break;
			}
		}
		m_list->DeleteAllItems();
		Sleep(1000);
		QuerySystemProcess(hWnd,ID,m_list);
	}
}
void ProcessVerify(HWND hWnd,CMyList *m_list,int Type)
{
	CString PidNum;
	CString FilePath;
	DWORD dwReadByte;
	dwReadByte=0;
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	FilePath.Format(L"%s",m_list->GetItemText(Item,3));

	WCHAR lpwzNum[50];
	WCHAR lpwzFilePath[260];
	WCHAR lpwzTrue[260];
	CHAR lpszFilePath[5024];

	memset(lpwzNum,0,sizeof(lpwzNum));
	memset(lpszFilePath,0,sizeof(lpszFilePath));
	memset(lpwzFilePath,0,sizeof(lpwzFilePath));

	wcscat(lpwzFilePath,FilePath);
	if (!wcslen(lpwzFilePath))
	{
		return;
	}
	if (GetFileAttributes(lpwzFilePath) == INVALID_FILE_ATTRIBUTES)
	{
		MessageBoxW(hWnd,L"�ļ��޷����ʣ�",L"A�ܵ��Է���",0);
		return;
	}
	//1Ϊ��֤����ǩ��
	if (Type == 1){
		if (VerifyEmbeddedSignature(lpwzFilePath)){
			AfxMessageBox(L"ͨ������ǩ����֤");
		}else
			AfxMessageBox(L"û��ͨ������ǩ����֤");
		return;
	}
	WideCharToMultiByte (CP_OEMCP,NULL,lpwzFilePath,-1,lpszFilePath,wcslen(lpwzFilePath)*2,NULL,FALSE);

	FILE * fp=fopen(lpszFilePath,"rb");
	if(fp)
	{
		MD5VAL val;
		val = md5File(fp);
		wsprintfW(lpwzNum,L"%08x%08x%08x%08x",conv(val.a),conv(val.b),conv(val.c),conv(val.d));
		fclose(fp);
	}
	FileVerify(lpszFilePath,lpwzNum,lpwzTrue);

	WCHAR lpwzMessageBox[256] = {0};
	WCHAR lpszSuccess[256];

	memset(lpszSuccess,0,sizeof(lpszSuccess));
	memset(lpwzMessageBox,0,sizeof(lpwzMessageBox));

	if (_wcsnicmp(lpwzTrue,L"��֧�ֵ�ǰϵͳ",wcslen(L"��֧�ֵ�ǰϵͳ")) == 0)
	{
		wsprintfW(lpwzMessageBox,L"%s\r\n\r\n�Ƿ�����\"A�ܵ��Է���\"�ռ����ļ�����汾�Ա���Ϊ�����汾���£�",L"��֧�ֵ�ǰϵͳ");
		if (MessageBoxW(hWnd,lpwzMessageBox,L"A�ܵ��Է���",MB_YESNO | MB_ICONWARNING) == IDYES)
		{
			//��ʼ�ռ�ϵͳ��Ϣ
		}
	}
	else if (_wcsnicmp(lpwzTrue,L"MD5(��)/ǩ��(-)",wcslen(L"MD5(��)/ǩ��(-)")) == 0)
	{
		wsprintfW(lpszSuccess,L"�ļ�:%ws\r\nMD5ֵ:%ws\r\n\r\n�Ѿ�ͨ����֤������ϵͳԭ���ļ���\r\n",lpwzFilePath,lpwzNum);
		AfxMessageBox(lpszSuccess);
	}
	else
	{
		wsprintfW(lpszSuccess,L"�ļ�:%ws\r\nMD5ֵ:%ws\r\n\r\n%ws��\r\n",lpwzFilePath,lpwzNum,lpwzTrue);
		AfxMessageBox(lpszSuccess);
	}
}
void CopyProcessMD5ToClipboard(HWND hWnd,CMyList *m_list)
{
	CString ProcessPath;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	ProcessPath.Format(L"%s",m_list->GetItemText(Item,3));

	WCHAR lpwzProcessPath[260];
	CHAR lpszProcessPath[1024];
	char *lpString = NULL;
	memset(lpwzProcessPath,0,sizeof(lpwzProcessPath));
	memset(lpszProcessPath,0,sizeof(lpszProcessPath));
	wcscat(lpwzProcessPath,ProcessPath);
	WideCharToMultiByte( CP_ACP,
		0,
		lpwzProcessPath,
		-1,
		lpszProcessPath,
		wcslen(lpwzProcessPath)*2,
		NULL,
		NULL
		);
	CHAR lpszNum[100] = {0};
	FILE * fp=fopen(lpszProcessPath,"rb");
	if(fp)
	{
		MD5VAL val;
		val = md5File(fp);
		wsprintfA(lpszNum,"%08x%08x%08x%08x",conv(val.a),conv(val.b),conv(val.c),conv(val.d));
		fclose(fp);
	}
	lpString = setClipboardText(lpszNum);
	if (lpString)
	{
		MessageBoxW(hWnd,L"�����ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
	}
}
void CopyProcessDataToClipboard(HWND hWnd,CMyList *m_list)
{
	CString ProcessPath;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	ProcessPath.Format(L"%s",m_list->GetItemText(Item,3));

	WCHAR lpwzProcessPath[260];
	CHAR lpszProcessPath[1024];
	char *lpString = NULL;
	memset(lpwzProcessPath,0,sizeof(lpwzProcessPath));
	memset(lpszProcessPath,0,sizeof(lpszProcessPath));
	wcscat(lpwzProcessPath,ProcessPath);
	WideCharToMultiByte( CP_ACP,
		0,
		lpwzProcessPath,
		-1,
		lpszProcessPath,
		wcslen(lpwzProcessPath)*2,
		NULL,
		NULL
		);
	lpString = setClipboardText(lpszProcessPath);
	if (lpString)
	{
		MessageBoxW(hWnd,L"�����ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
	}
}
void SuspendOrResumeProcess(CMyList *m_list,ULONG ulCommand)
{
	CString PidNum;
	DWORD dwReadByte;


	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	PidNum.Format(L"%ws",m_list->GetItemText(Item,4));

	WCHAR lpwzNum[50];
	WCHAR lpszEProcessNum[50];

	memset(lpwzNum,0,sizeof(lpwzNum));
	wcscat(lpwzNum,PidNum);
	if (!wcslen(lpwzNum)){
		return;
	}
	for (int i=0;i<(int)NormalProcessInfo->ulCount;i++)
	{
		memset(lpszEProcessNum,0,sizeof(lpszEProcessNum));
		wsprintfW(lpszEProcessNum,L"0x%x",NormalProcessInfo->ProcessInfo[i].EProcess);
		if (_wcsnicmp(lpszEProcessNum,lpwzNum,wcslen(lpwzNum)) == 0)
		{
			ReadFile((HANDLE)ulCommand,0,NormalProcessInfo->ProcessInfo[i].EProcess,&dwReadByte,0);
			break;
		}
	}
}