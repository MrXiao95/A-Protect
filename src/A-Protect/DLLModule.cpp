// Process.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-ProtectView.h"
#include "submodule.h"
#include "DLLModule.h"
//#include "Process.h"
#include "UnloadDllModule.h"
#include "A-Protect.h"

VOID EnumModule(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	CString PidNum;
	DWORD dwReadByte;
	BOOL bInit = FALSE;
	BOOL bIsSvchostRun = FALSE;
	BOOL bIsDllNormal = TRUE;
	int i = 0,x = 0;

	int ItemNum = m_list->GetItemCount();
	SHFILEINFO shfileinfo;
	DllModuleImg.Create(16,16, ILC_COLOR32, 2, 80);
	HIMAGELIST hImageList = NULL;
	CMyAProtectApp *imgApp=(CMyAProtectApp*)AfxGetApp();
	bool PathEmpty=true;

	SetDlgItemTextW(m_hWnd,ID,L"����ɨ�����ģ�飬���Ժ�...");

	if (DLLServicesRegistry)
	{
		VirtualFree(DLLServicesRegistry,sizeof(SERVICESREGISTRY)*1025,MEM_RESERVE | MEM_COMMIT);
		DLLServicesRegistry = 0;
	}
	//================================================================================
	//�ȶ�ȡһ�η���
	DLLServicesRegistry = NULL;
	DLLServicesRegistry = (PSERVICESREGISTRY)VirtualAlloc(0, sizeof(SERVICESREGISTRY)*1025,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (DLLServicesRegistry)
	{
		memset(DLLServicesRegistry,0,sizeof(SERVICESREGISTRY)*1025);
		ReadFile((HANDLE)LIST_SERVICES,DLLServicesRegistry,sizeof(SERVICESREGISTRY)*1025,&dwReadByte,0);
	}
	char lpszNum[50];
	memset(lpszNum,0,sizeof(lpszNum));

	WideCharToMultiByte (CP_OEMCP,NULL,lpwzNum,-1,lpszNum,wcslen(lpwzNum)*2,NULL,FALSE);
	if (IsNumber(lpszNum))
	{
		for (x=0;x<(int)NormalProcessInfo->ulCount;x++)
		{
			if (NormalProcessInfo->ProcessInfo[x].ulPid == atoi(lpszNum))
			{
				ulPID = atoi(lpszNum);
				ReadFile((HANDLE)INIT_PROCESS_LIST_PROCESS_MODULE,0,NormalProcessInfo->ProcessInfo[x].EProcess,&dwReadByte,0);

				//ȡ��ǰ�����̷�
				memset(lpwzCurrentDiskString,0,sizeof(lpwzCurrentDiskString));
				memcpy(lpwzCurrentDiskString,NormalProcessInfo->ProcessInfo[x].lpwzFullProcessPath,6);
				bInit = TRUE;
				break;
			}
		}
	}

	if (bInit)
	{
		Sleep(1000);

		PDll = (PDLLINFO)VirtualAlloc(0,(sizeof(DLLINFO)+sizeof(DLL_INFORMATION))*810,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (PDll)
		{
			m_list->DeleteAllItems();

			memset(PDll,0,(sizeof(DLLINFO)+sizeof(DLL_INFORMATION))*810);
			ReadFile((HANDLE)LIST_PROCESS_MODULE,PDll,(sizeof(DLLINFO)+sizeof(DLL_INFORMATION))*810,&dwReadByte,0);
			for (i=0;i<(int)PDll->ulCount;i++)
			{
				WCHAR lpwzTextOut[100];
				memset(lpwzTextOut,0,sizeof(lpwzTextOut));
				wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",PDll->ulCount,i);
				SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

				WCHAR lpwzDLLPath[256];
				CHAR lpszDLLPath[5024];
				WCHAR lpwzBase[256];
				WCHAR lpwzDLLSize[256];
				WCHAR lpwzMd5[50];
				WCHAR lpwzTrue[260];

				memset(lpwzTrue,0,sizeof(lpwzTrue));
				memset(lpwzMd5,0,sizeof(lpwzMd5));

				memset(lpwzDLLPath,0,sizeof(lpwzDLLPath));
				memset(lpszDLLPath,0,sizeof(lpszDLLPath));

				memset(lpwzBase,0,sizeof(lpwzBase));
				memset(lpwzDLLSize,0,sizeof(lpwzDLLSize));

				WCHAR lpwzWinDir[260];
				WCHAR lpwzSysDisk[260];
				memset(lpwzWinDir,0,sizeof(lpwzWinDir));
				memset(lpwzSysDisk,0,sizeof(lpwzSysDisk));

				if (wcsstr(PDll->DllInfo[i].lpwzDllModule,L"\\??\\") != NULL)
				{
					wcsncat_s(lpwzDLLPath,PDll->DllInfo[i].lpwzDllModule+wcslen(L"\\??\\"),wcslen(PDll->DllInfo[i].lpwzDllModule)-wcslen(L"\\??\\"));
					goto Next;
				}
				if (wcsstr(PDll->DllInfo[i].lpwzDllModule,L"\\") == NULL)
				{
					continue;
				}
				//MessageBoxW(PDll->DllInfo[i].lpwzDllModule,lpwzDLLPath,0);

				if (wcsstr(PDll->DllInfo[i].lpwzDllModule,L"\\Device\\") != NULL)
				{
					if (NtFilePathToDosFilePath(PDll->DllInfo[i].lpwzDllModule,lpwzDLLPath) == FALSE)
					{
						bIsDllNormal = FALSE;   // dll��������GetFileAttributesW �޷�����
					}
					//MessageBoxW(PDll->DllInfo[i].lpwzDllModule,lpwzDLLPath,0);

					goto Next;
				}
				if (wcsstr(PDll->DllInfo[i].lpwzDllModule,L":") == NULL)
				{
					//��ȡdll·��
					if (PrintfDosPath(PDll->DllInfo[i].lpwzDllModule,lpwzDLLPath) == FALSE)
					{
						bIsDllNormal = FALSE;   // dll��������GetFileAttributesW �޷�����
					}
				}
				if (!wcslen(lpwzDLLPath))
				{
					wcsncat_s(lpwzDLLPath,PDll->DllInfo[i].lpwzDllModule,wcslen(PDll->DllInfo[i].lpwzDllModule));
				}
				//MessageBoxW(PDll->DllInfo[i].lpwzDllModule,lpwzDLLPath,0);
Next:
				wsprintfW(lpwzBase,L"%08X",PDll->DllInfo[i].ulBase);
				WideCharToMultiByte( CP_ACP,
					0,
					lpwzDLLPath,
					-1,
					lpszDLLPath,
					wcslen(lpwzDLLPath)*2,
					NULL,
					NULL
					);
				FILE * fp=NULL;
				fopen_s(&fp,lpszDLLPath,"rb");
				if(fp)
				{
					MD5VAL val;
					val = md5File(fp);
					wsprintfW(lpwzMd5,L"%08x%08x%08x%08x",conv(val.a),conv(val.b),conv(val.c),conv(val.d));
					FileVerify(lpszDLLPath,lpwzMd5,lpwzTrue);
					fclose(fp);
					PathEmpty=false;
				}
				wsprintfW(lpwzDLLSize,L"%d KB",GetDLLFileSize(lpszDLLPath));
				//================================================================================
				CHAR lpszDLLPathInServices[1024] = {0};
				CHAR lpszDLLNameInServices[256] = {0};
				CHAR lpszDLLNameInServices1[256] = {0};
				WCHAR lpwzSrvRun[256];

				memset(lpwzSrvRun,0,sizeof(lpwzSrvRun));
				for (int x=0;x<(int)DLLServicesRegistry->ulCount;x++)
				{
					memset(lpszDLLPathInServices,0,sizeof(lpszDLLPathInServices));
					memset(lpszDLLNameInServices,0,sizeof(lpszDLLNameInServices));
					memset(lpszDLLNameInServices1,0,sizeof(lpszDLLNameInServices1));

					if (wcslen(DLLServicesRegistry->SrvReg[x].lpwzDLLPath) < 10 ||
						wcsstr(DLLServicesRegistry->SrvReg[x].lpwzDLLPath,L"\\") == 0)
					{
						continue;
					}
					WideCharToMultiByte(CP_ACP,
						0,
						DLLServicesRegistry->SrvReg[x].lpwzDLLPath,
						-1,
						lpszDLLPathInServices,
						wcslen(DLLServicesRegistry->SrvReg[x].lpwzDLLPath)*2,
						NULL,
						NULL
						);
					if (strlen(lpszDLLPathInServices) < 10 ||
						strstr(lpszDLLPathInServices,"\\") == 0 ||
						strstr(lpszDLLPath,"\\") == 0)
					{
						continue;
					}
					wsprintfA(lpszDLLNameInServices,"%s",ExtractFileName(lpszDLLPathInServices));
					wsprintfA(lpszDLLNameInServices1,"%s",ExtractFileName(lpszDLLPath));

					if (StrCmpIA(lpszDLLNameInServices,lpszDLLNameInServices1) == 0)
					{
						//memset(lpwzForMat,0,sizeof(lpwzForMat));
						//wsprintfW(lpwzForMat,L"��֤ͨ����\r\n\r\nģ��:%ws ��svchostϵͳ����(%ws)������\r\n",lpwzDLLPath,DLLServicesRegistry->SrvReg[x].lpwzSrvName);
						wcscat_s(lpwzSrvRun,DLLServicesRegistry->SrvReg[x].lpwzSrvName);
						bIsSvchostRun = TRUE;
						break;
					}
				}
				if (!bIsSvchostRun)
					wcscat_s(lpwzSrvRun,L"-");

				bIsSvchostRun = FALSE;  //�ָ���־

				if (DLLServicesRegistry)
					VirtualFree(DLLServicesRegistry,sizeof(SERVICESREGISTRY)*1025,MEM_RESERVE | MEM_COMMIT);
				//================================================================================
				//m_list->InsertItem(0,_T("fds"),RGB(77,77,77));
				if (_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0)
				{
					//m_list->InsertItem(Item,lpwzDLLPath);
					m_list->InsertItem(i,lpwzBase,RGB(238,118,0));

				}else
				{
					if (!bIsDllNormal)
					{
						memset(lpwzTrue,0,sizeof(lpwzTrue));
						wcscat_s(lpwzTrue,L"DLLģ����ڣ������ļ��޷�����");
						m_list->InsertItem(i,lpwzBase,RGB(255,20,147));

					}else
						m_list->InsertItem(i,lpwzBase,RGB(77,77,77));
				}

				//MessageBoxW(lpwzDLLPath,lpwzBase,0);

				m_list->SetItemText(i,1,lpwzDLLSize);
				m_list->SetItemText(i,2,lpwzDLLPath);
				m_list->SetItemText(i,3,lpwzSrvRun);
				m_list->SetItemText(i,4,lpwzTrue);

				if(PathEmpty)
					DllModuleImg.Add(imgApp->LoadIconW(IDI_WHITE));
				else
				{			
					hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzDLLPath,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
					DllModuleImg.Add(shfileinfo.hIcon);
				}
				m_list->SetImageList(&DllModuleImg);
				m_list->SetItemImageId(i,i);
				DestroyIcon(shfileinfo.hIcon);
				PathEmpty=true;
				bIsDllNormal = TRUE;
			}
			VirtualFree(PDll,(sizeof(DLLINFO)+sizeof(DLL_INFORMATION))*810,MEM_RESERVE | MEM_COMMIT);
		}else{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"�����ڴ���� ����������A��\r\n�������:%d\n",GetLastError());
			MessageBox(0,lpwzTextOut,0,0);
		}
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"����DLLģ��ɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);
}
//IntType:
//0 ֻд��
//1 ж�ز�ɾ��
VOID UnLoadDLL(HWND m_hWnd,ULONG ID,CMyList *m_list,int IntType)
{
	CString DllPath;
//	DWORD dwReadByte;
	BOOL bInit = FALSE;

	int ItemNum = m_list->GetItemCount();


	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	DllPath.Format(L"%s",m_list->GetItemText(Item,2));

	//MessageBoxW(0,DllPath,0);
	if (UnInjectDll(DllPath,ulPID))
	{
		EnumModule(m_hWnd,ID,m_list);

		if (IntType == 1)
		{
			//ɾ���ļ�
			DWORD dwReadByte;
			WCHAR lpwzDeletedFile[256];
			memset(lpwzDeletedFile,0,sizeof(lpwzDeletedFile));
			wsprintfW(lpwzDeletedFile,L"\\??\\%ws",DllPath);

			ReadFile((HANDLE)DELETE_FILE,lpwzDeletedFile,wcslen(lpwzDeletedFile),&dwReadByte,0);
		}
	}
}
void UnLoadDLLModule(HWND m_hWnd,CMyList *m_list)
{
	UnLoadDLL(m_hWnd,IDC_DllDebugStatus,m_list,0);
}
void UnLoadDLLModuleAndDelete(HWND m_hWnd,CMyList *m_list)
{
	UnLoadDLL(m_hWnd,IDC_DllDebugStatus,m_list,1);
}
void CopyDLLDataToClipboard(HWND m_hWnd,CMyList *m_list)
{
	CString DLLPath;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	DLLPath.Format(L"%s",m_list->GetItemText(Item,2));

	WCHAR lpwzDLLPath[260];

	memset(lpwzDLLPath,0,sizeof(lpwzDLLPath));
	wcscat_s(lpwzDLLPath,DLLPath);
	CHAR lpszDLLPath[1024];
	char *lpString = NULL;

	memset(lpwzDLLPath,0,sizeof(lpwzDLLPath));
	memset(lpszDLLPath,0,sizeof(lpszDLLPath));
	wcscat_s(lpwzDLLPath,DLLPath);
	WideCharToMultiByte( CP_ACP,
		0,
		lpwzDLLPath,
		-1,
		lpszDLLPath,
		wcslen(lpwzDLLPath)*2,
		NULL,
		NULL
		);
	lpString = setClipboardText(lpszDLLPath);
	if (lpString)
	{
		MessageBoxW(m_hWnd,L"�����ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
	}
}
void LookupDLLInServices(HWND m_hWnd,ULONG ID,CMyList *m_list,int Type)
{

	CString DLLPath;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	DLLPath.Format(L"%s",m_list->GetItemText(Item,2));

	WCHAR lpwzDLLPath[260];

	memset(lpwzDLLPath,0,sizeof(lpwzDLLPath));
	wcscat_s(lpwzDLLPath,DLLPath);
	if (!wcslen(lpwzDLLPath))
	{
		return;
	}
	//1Ϊ��֤����ǩ��
	if (Type == 1){
		if (VerifyEmbeddedSignature(lpwzDLLPath)){
			AfxMessageBox(L"ͨ������ǩ����֤");
		}else
			AfxMessageBox(L"û��ͨ������ǩ����֤");
		return;
	}
	SetDlgItemTextW(m_hWnd,ID,L"������֤��ѡDLLģ���Ƿ���svchost�������������Ժ�...");

	CHAR lpszDLLPathInServices1[1024] = {0};
	CHAR lpszDLLNameInServices1[256] = {0};
	memset(lpszDLLNameInServices1,0,sizeof(lpszDLLNameInServices1));
	memset(lpszDLLPathInServices1,0,sizeof(lpszDLLPathInServices1));
	WideCharToMultiByte( CP_ACP,
		0,
		lpwzDLLPath,
		-1,
		lpszDLLPathInServices1,
		wcslen(lpwzDLLPath)*2,
		NULL,
		NULL
		);

	DWORD dwReadByte;
	WCHAR lpwzForMat[256];
	BOOL bIsSvchostRun = FALSE;

	DLLServicesRegistry = NULL;
	DLLServicesRegistry = (PSERVICESREGISTRY)VirtualAlloc(0, sizeof(SERVICESREGISTRY)*1025,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (DLLServicesRegistry)
	{
		memset(DLLServicesRegistry,0,sizeof(SERVICESREGISTRY)*1025);
		ReadFile((HANDLE)LIST_SERVICES,DLLServicesRegistry,sizeof(SERVICESREGISTRY)*1025,&dwReadByte,0);

		CHAR lpszDLLPathInServices[1024] = {0};
		CHAR lpszDLLNameInServices[256] = {0};

		for (int x=0;x<(int)DLLServicesRegistry->ulCount;x++)
		{
			memset(lpszDLLPathInServices,0,sizeof(lpszDLLPathInServices));
			memset(lpszDLLNameInServices,0,sizeof(lpszDLLNameInServices));

			if (wcslen(DLLServicesRegistry->SrvReg[x].lpwzDLLPath) < 10 ||
				wcsstr(DLLServicesRegistry->SrvReg[x].lpwzDLLPath,L"\\") == 0)
			{
				continue;
			}
			WideCharToMultiByte(CP_ACP,
				0,
				DLLServicesRegistry->SrvReg[x].lpwzDLLPath,
				-1,
				lpszDLLPathInServices,
				wcslen(DLLServicesRegistry->SrvReg[x].lpwzDLLPath),
				NULL,
				NULL
				);
			if (strlen(lpszDLLPathInServices) < 10)
			{
				continue;
			}
			wsprintfA(lpszDLLNameInServices,"%s",ExtractFileName(lpszDLLPathInServices));
			wsprintfA(lpszDLLNameInServices1,"%s",ExtractFileName(lpszDLLPathInServices1));

			if (StrCmpIA(lpszDLLNameInServices,lpszDLLNameInServices1) == 0)
			{
				memset(lpwzForMat,0,sizeof(lpwzForMat));
				wsprintfW(lpwzForMat,L"��֤ͨ����\r\n\r\nģ��:%ws ��svchostϵͳ����(%ws)������\r\n",lpwzDLLPath,DLLServicesRegistry->SrvReg[x].lpwzSrvName);
				bIsSvchostRun = TRUE;
				break;
			}
		}
		if (!bIsSvchostRun)
		{
			memset(lpwzForMat,0,sizeof(lpwzForMat));
			wsprintfW(lpwzForMat,L"��֤ʧ�ܣ�\r\n\r\nģ��:%ws ��������ʽ������\r\n",lpwzDLLPath);
			MessageBoxW(m_hWnd,lpwzForMat,L"A�ܵ��Է���",MB_ICONWARNING);

		}else
		{
			MessageBoxW(m_hWnd,lpwzForMat,L"A�ܵ��Է���",MB_ICONWARNING);
		}
		VirtualFree(DLLServicesRegistry,sizeof(SERVICESREGISTRY)*1025,MEM_RESERVE | MEM_COMMIT);
		SetDlgItemTextW(m_hWnd,ID,L"��֤���...");
	}
}