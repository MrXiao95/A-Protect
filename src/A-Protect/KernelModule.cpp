#include "stdafx.h"
#include "A-ProtectView.h"
#include "KernelModule.h"
#include "A-Protect.h"
#include "DisplayDecvice.cpp"

#include "Windows7Home_CN.h"
#include "Windows2003SP1_CN.h"
#include "Windows2003SP2_CN.h"
#include "Windows7SP1_CN.h"
#include "WindowsXPSP2_CN.h"
#include "WindowsXPSP3_CN.h"

BOOL VerifyEmbeddedSignature( LPCWSTR lpFileName );
BOOL IsWindows7();
void RunAProcess(char *comline);
LPSTR ExtractFilePath(LPSTR lpcFullFileName);

extern BOOL TrustQuery;

extern unsigned char szQueryValue[256];

BOOL FileVerify(char *lpszFullPath,WCHAR *lpwzFileMd5,WCHAR *lpwzTrue)
{
	memset(lpwzTrue,0,sizeof(lpwzTrue));
	wcscat(lpwzTrue,L"�޷�ȷ���ļ���Դ");

	OSVERSIONINFOEX   osvi;   
	BOOL   bOsVersionInfoEx;   

	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));   
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);   
	if(!(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*)&osvi)))   
	{   
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);   
		if(!GetVersionEx((OSVERSIONINFO*)&osvi))     
			return FALSE;   
	}
	for (int x=0;x<2888;x++)
	{
		if (osvi.dwBuildNumber == 2600 &&
			osvi.wServicePackMajor == 3 &&
			GetSystemDefaultLCID() == 2052)  //xpSP3_cn
		{
			if (!wcslen(WindowsXPSP3_CN[x]))
			{
				break;
			}
			if (_wcsnicmp(WindowsXPSP3_CN[x],lpwzFileMd5,wcslen(lpwzFileMd5)) == NULL)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat(lpwzTrue,L"MD5(��)/ǩ��(-)");
				break;
			}
		}else if (osvi.dwBuildNumber == 2600 &&
			osvi.wServicePackMajor == 2 &&
			GetSystemDefaultLCID() == 2052)  //xpSP2_cn
		{
			if (!wcslen(WindowsXPSP2_CN[x]))
			{
				break;
			}
			if (_wcsnicmp(WindowsXPSP2_CN[x],lpwzFileMd5,wcslen(lpwzFileMd5)) == NULL)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat(lpwzTrue,L"MD5(��)/ǩ��(-)");
				break;
			}
		}
		else if (osvi.dwBuildNumber == 3790 &&
			osvi.wServicePackMajor == 1 &&
			GetSystemDefaultLCID() == 2052)  //2003SP1_cn
		{
			if (!wcslen(Windows2003SP1_CN[x]))
			{
				break;
			}
			if (_wcsnicmp(Windows2003SP1_CN[x],lpwzFileMd5,wcslen(lpwzFileMd5)) == NULL)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat(lpwzTrue,L"MD5(��)/ǩ��(-)");
				break;
			}
		}
		else if (osvi.dwBuildNumber == 3790 &&
			osvi.wServicePackMajor == 2 &&
			GetSystemDefaultLCID() == 2052)  //2003SP2_cn
		{
			if (!wcslen(Windows2003SP2_CN[x]))
			{
				break;
			}
			if (_wcsnicmp(Windows2003SP2_CN[x],lpwzFileMd5,wcslen(lpwzFileMd5)) == NULL)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat(lpwzTrue,L"MD5(��)/ǩ��(-)");
				break;
			}
		}
		else if (osvi.dwBuildNumber == 7600 &&
			osvi.wServicePackMajor == 0 &&
			GetSystemDefaultLCID() == 2052)  //win7 home
		{
			if (!wcslen(Windows7Home_CN[x]))
			{
				break;
			}
			if (_wcsnicmp(Windows7Home_CN[x],lpwzFileMd5,wcslen(lpwzFileMd5)) == NULL)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat(lpwzTrue,L"MD5(��)/ǩ��(-)");
				break;
			}
		}
		else if (osvi.dwBuildNumber == 7601 &&
			osvi.wServicePackMajor == 1 &&
			GetSystemDefaultLCID() == 2052)  //win7 �콢 SP1_CN
		{
			if (!wcslen(Windows7SP1_CN[x]))
			{
				break;
			}
			if (_wcsnicmp(Windows7SP1_CN[x],lpwzFileMd5,wcslen(lpwzFileMd5)) == NULL)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat(lpwzTrue,L"MD5(��)/ǩ��(-)");
				break;
			}
		}
		else
		{
			memset(lpwzTrue,0,sizeof(lpwzTrue));
			wcscat(lpwzTrue,L"��֧�ֵ�ǰϵͳ");
			break;
		}
	}
	if (_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0 ||
		_wcsnicmp(lpwzTrue,L"��֧�ֵ�ǰϵͳ",wcslen(L"��֧�ֵ�ǰϵͳ")) == 0)
	{
		if (TrustQuery)
	{
		CHAR lpszProcFullPath[260] = {0};
		WCHAR lpwzProcFullPath[260] = {0};
		memset(lpwzProcFullPath,0,sizeof(lpwzProcFullPath));
		memset(lpszProcFullPath,0,sizeof(lpszProcFullPath));

		strcat(lpszProcFullPath,lpszFullPath);
		MultiByteToWideChar(
			CP_ACP,
			0, 
			lpszProcFullPath,
			-1, 
			lpwzProcFullPath, 
			strlen(lpszProcFullPath)
			);
		if (VerifyEmbeddedSignature(lpwzProcFullPath))
		{
			memset(lpwzTrue,0,sizeof(lpwzTrue));
			wcscat(lpwzTrue,L"MD5(-)/ǩ��(��)");
		}
	}
	}
	return TRUE;
}

VOID QueryKernelModule(HWND m_hWnd,ULONG ID,CMyList *m_list,int IntLookType)
{
	DWORD dwReadByte;
	int ItemNum = m_list->GetItemCount();
	int x = 0;
	int i = 0;
	int FileNotExist=false;
	CMyAProtectApp *imgApp=(CMyAProtectApp*)AfxGetApp();

	SetDlgItemTextW(m_hWnd,ID,L"����ɨ������ģ�飬���Ժ�...");

	if (bIsPhysicalCheck){
		SaveToFile("\r\n\r\n[---����ģ��---]\r\n",PhysicalFile);
	}
	if (SysModuleInfo)
	{
		VirtualFree(SysModuleInfo,sizeof(SYSINFO)*264,MEM_RESERVE | MEM_COMMIT);
		SysModuleInfo = NULL;
	}
	SysModuleInfo = (PSYSINFO)VirtualAlloc(0, sizeof(SYSINFO)*264,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (SysModuleInfo)
	{
		//Ϊ����ͼ�����
		SHFILEINFO shfileinfo;
		KernalModuleImg.Create(16,16, ILC_COLOR32, 2, 100);
		HIMAGELIST hImageList = NULL;
/*
		//win7ϵͳ�½����Կ���ö�٣���Ȼ����ɼ�����ԭ����~������
		if (IsWindows7()){
			//û����������£��Ż���ʾ
			if (!bIsPhysicalCheck){
				MessageBox(0,L"win7��ö������ģ��ή����Ļ�ֱ��ʣ�ö����ɼ����Զ��ָ�����������������Ī�ţ�", L"������ʾ",MB_ICONWARNING);
			}
			char lpAptDir[260] = {0};
			char lpModule[260] = {0};
			char lpCommand[260] = {0};
			char lpDecviceKey[260] = {0};

			GetModuleFileNameA(NULL,lpModule,sizeof(lpModule));
			wsprintfA(lpAptDir,"%s",ExtractFilePath(lpModule)); //�õ�·����Ŀ¼

			QueryDisplayDecvicePath(lpDecviceKey);
			strcat(lpCommand,lpAptDir);
			strcat(lpCommand,"winspapi.exe");
			strcat(lpCommand," disable ");    //�����Կ�������������ɼ���
			strcat(lpCommand,lpDecviceKey);
			WinExec(lpCommand,SW_HIDE);
			Sleep(3000);
		}
*/
		ReadFile((HANDLE)LIST_SYS_MODULE,SysModuleInfo,sizeof(SYSINFO)*264,&dwReadByte,0);
/*
		//�����Կ�
		if (IsWindows7()){
			char lpAptDir[260] = {0};
			char lpModule[260] = {0};
			char lpCommand[260] = {0};
			char lpDecviceKey[260] = {0};

			GetModuleFileNameA(NULL,lpModule,sizeof(lpModule));
			wsprintfA(lpAptDir,"%s",ExtractFilePath(lpModule)); //�õ�·����Ŀ¼

			QueryDisplayDecvicePath(lpDecviceKey);
			strcat(lpCommand,lpAptDir);
			strcat(lpCommand,"winspapi.exe");   //�����Կ�����
			strcat(lpCommand," enable ");
			strcat(lpCommand,lpDecviceKey);
			WinExec(lpCommand,SW_HIDE);
		}
*/
		for (i=0;i< (int)SysModuleInfo->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",SysModuleInfo->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzSysBase[256] = {0};
			WCHAR lpwzSizeOfImage[256] = {0};

			WCHAR lpwzFullSysName[256] = {0};
			WCHAR lpwzBaseSysName[256] = {0};
			WCHAR lpwzServiceName[256] = {0};

			WCHAR lpwzDriverObject[256] = {0};

			WCHAR IntHideType[256] = {0};

			memset(lpwzSysBase,0,sizeof(lpwzSysBase));
			memset(lpwzSizeOfImage,0,sizeof(lpwzSizeOfImage));

			memset(lpwzFullSysName,0,sizeof(lpwzFullSysName));
			memset(lpwzBaseSysName,0,sizeof(lpwzBaseSysName));

			memset(lpwzServiceName,0,sizeof(lpwzServiceName));
			memset(lpwzDriverObject,0,sizeof(lpwzDriverObject));

			memset(IntHideType,0,sizeof(IntHideType));

			if (SysModuleInfo->SysInfo[i].ulSysBase)
				wsprintfW(lpwzSysBase,L"0x%08X",SysModuleInfo->SysInfo[i].ulSysBase);
			else
				wsprintfW(lpwzSysBase,L"%ws",L"-");

			if (SysModuleInfo->SysInfo[i].SizeOfImage)
				wsprintfW(lpwzSizeOfImage,L"0x%X",SysModuleInfo->SysInfo[i].SizeOfImage);
			else
				wsprintfW(lpwzSizeOfImage,L"%ws",L"-");

			wcscat(lpwzFullSysName,SysModuleInfo->SysInfo[i].lpwzFullSysName);
			wcscat(lpwzBaseSysName,SysModuleInfo->SysInfo[i].lpwzBaseSysName);

			if (wcsstr(SysModuleInfo->SysInfo[i].lpwzServiceName,L"\\Driver\\")){
				memcpy(lpwzServiceName,SysModuleInfo->SysInfo[i].lpwzServiceName+wcslen(L"\\Driver\\"),wcslen(SysModuleInfo->SysInfo[i].lpwzServiceName)*2-wcslen(L"\\Driver\\"));
			}
			if (wcsstr(SysModuleInfo->SysInfo[i].lpwzServiceName,L"\\FileSystem\\")){
				memcpy(lpwzServiceName,SysModuleInfo->SysInfo[i].lpwzServiceName+wcslen(L"\\FileSystem\\"),wcslen(SysModuleInfo->SysInfo[i].lpwzServiceName)*2-wcslen(L"\\FileSystem\\"));
			}
			if (!wcslen(SysModuleInfo->SysInfo[i].lpwzServiceName)){
				memcpy(lpwzServiceName,L"-",wcslen(L"-"));
			}
			if (SysModuleInfo->SysInfo[i].DriverObject)
				wsprintfW(lpwzDriverObject,L"0x%08X",SysModuleInfo->SysInfo[i].DriverObject);
			else
				wsprintfW(lpwzDriverObject,L"%ws",L"-");

			/////
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
			if (!wcslen(lpwzFullSysName) &&
				!wcslen(lpwzBaseSysName)){
					wcscat(lpwzDosFullPath,L"-");
					goto Next;
			}
			if (wcslen(lpwzFullSysName) == wcslen(lpwzBaseSysName) &&
				wcsncmp(lpwzFullSysName,L"-",wcslen(L"-")) != 0)
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat(lpwzDosFullPath,lpwzSysDisk);
				wcscat(lpwzDosFullPath,L"\\WINDOWS\\system32\\drivers\\");
				wcscat(lpwzDosFullPath,lpwzBaseSysName);
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
				wcscat(lpwzTrue,L"�ļ������ڣ��޷���֤");
			}
			//������һ���������ݣ�����Ҫ���������
			if (bIsPhysicalCheck){
				//���û��hook���ͷ���
				if (_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0 ||
					_wcsnicmp(lpwzTrue,L"�ļ������ڣ��޷���֤",wcslen(L"�ļ������ڣ��޷���֤")) == 0 ||
					SysModuleInfo->SysInfo[i].IntHideType == FALSE)
				{
					WCHAR lpwzSaveBuffer[1024] ={0};
					CHAR lpszSaveBuffer[2024] ={0};
					memset(lpwzSaveBuffer,0,sizeof(lpwzSaveBuffer));
					memset(lpszSaveBuffer,0,sizeof(lpszSaveBuffer));

					wsprintfW(lpwzSaveBuffer,L"          --> �����޷�ʶ���ں�ģ�飺DriverObject:%ws | ����ӳ��:%ws | ��������:%ws | ����·��:%ws\r\n",
						lpwzDriverObject,lpwzBaseSysName,lpwzServiceName,lpwzDosFullPath);

					m_list->InsertItem(0,L"����ģ��",RGB(77,77,77));
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
			if (SysModuleInfo->SysInfo[i].IntHideType == FALSE)
			{
				memset(lpwzTrue,0,sizeof(lpwzTrue));
				wcscat(lpwzTrue,L"�޷�ʶ�����������");
				m_list->InsertItem(i,lpwzSysBase,RGB(255,20,147));
				FileNotExist=true;
				goto InsertData;
			}
			if (_wcsnicmp(lpwzTrue,L"�޷�ȷ���ļ���Դ",wcslen(L"�޷�ȷ���ļ���Դ")) == 0 ||
				SysModuleInfo->SysInfo[i].IntHideType == FALSE)  //SysModuleInfo->SysInfo[i].IntHideType = FASLE Ϊ��������
			{
				m_list->InsertItem(i,lpwzSysBase,RGB(238,118,0));

			}else if (_wcsnicmp(lpwzTrue,L"�ļ������ڣ��޷���֤",wcslen(L"�ļ������ڣ��޷���֤")) == 0)
			{
				m_list->InsertItem(i,lpwzSysBase,RGB(255,20,147));
				FileNotExist=true;
			}else
			{
				m_list->InsertItem(i,lpwzSysBase,RGB(77,77,77));
			}
InsertData:
			m_list->SetItemText(i,1,lpwzSizeOfImage);
			m_list->SetItemText(i,2,lpwzDriverObject);

			m_list->SetItemText(i,3,lpwzBaseSysName);
			m_list->SetItemText(i,4,lpwzDosFullPath);
			m_list->SetItemText(i,5,lpwzServiceName);

			m_list->SetItemText(i,6,lpwzTrue);
		
			hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzDosFullPath,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
			if(SUCCEEDED(hImageList))
			{
				if(!FileNotExist)
					KernalModuleImg.Add(shfileinfo.hIcon);
				else
					KernalModuleImg.Add(imgApp->LoadIconW(IDI_WHITE));
				m_list->SetImageList(&KernalModuleImg);
				m_list->SetItemImageId(i,i);
				DestroyIcon(shfileinfo.hIcon);
			}
			FileNotExist=false;
		}
	}else{
		WCHAR lpwzTextOut[100];
		memset(lpwzTextOut,0,sizeof(lpwzTextOut));
		wsprintfW(lpwzTextOut,L"�����ڴ���� ����������A��\r\n�������:%d\n",GetLastError());
		MessageBox(0,lpwzTextOut,0,0);
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"�ں�ģ��ɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);
}
void CopyKernelModuleDataToClipboard(HWND m_hWnd,CMyList *m_list)
{
	CString KernelModule;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	KernelModule.Format(L"%s",m_list->GetItemText(Item,3));

	WCHAR lpwzKernelModule[260];

	memset(lpwzKernelModule,0,sizeof(lpwzKernelModule));
	wcscat(lpwzKernelModule,KernelModule);
	CHAR lpszKernelModule[1024];
	char *lpString = NULL;

	memset(lpwzKernelModule,0,sizeof(lpwzKernelModule));
	memset(lpszKernelModule,0,sizeof(lpszKernelModule));
	wcscat(lpwzKernelModule,KernelModule);
	WideCharToMultiByte( CP_ACP,
		0,
		lpwzKernelModule,
		-1,
		lpszKernelModule,
		wcslen(lpwzKernelModule)*2,
		NULL,
		NULL
		);
	lpString = setClipboardText(lpszKernelModule);
	if (lpString)
	{
		MessageBoxW(m_hWnd,L"�����ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
	}
}
BOOL SaveToFile(WCHAR *lpwzFilePath,PVOID Buffer,ULONG ulBufferSize)
{
	DWORD dwBytesWrite = 0;
	BOOL bRetOK = FALSE;

	HANDLE	hFile = CreateFileW(lpwzFilePath, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(hFile, 0, 0, FILE_END);
		WriteFile(hFile,Buffer,ulBufferSize, &dwBytesWrite, NULL);
		CloseHandle(hFile);
		bRetOK = TRUE;
	}
	return bRetOK;
}
void OnDumpmemorydatatofile(HWND hWnd,CMyList *m_list)
{
	// TODO: �ڴ���������������


	CString			m_path;

	CString KernelModuleBase;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	KernelModuleBase.Format(L"%s",m_list->GetItemText(Item,0));

	WCHAR lpwzKernelModuleBase[260];
	WCHAR lpwzSysBase[260];
	CHAR lpszSysSize[260];

	WCHAR lpwzFilePath[260];
	DWORD dwReadByte;
	WCHAR lpwzForMat[260];

	memset(lpwzForMat,0,sizeof(lpwzForMat));
	memset(lpwzFilePath,0,sizeof(lpwzFilePath));
	memset(lpwzSysBase,0,sizeof(lpwzSysBase));
	memset(lpwzKernelModuleBase,0,sizeof(lpwzKernelModuleBase));

	wcscat(lpwzKernelModuleBase,KernelModuleBase);
	if (!wcslen(lpwzKernelModuleBase))
	{
		return;
	}

	//��ͣ��Ȼ�޷���Ϊ������win7���޷��򿪶Ի���
	ReadFile((HANDLE)SUSPEND_PROTECT,0,0,&dwReadByte,0);

	CFileDialog dlg( FALSE,L"txt",0, OFN_OVERWRITEPROMPT|OFN_HIDEREADONLY,L"�����ļ�|*.*");
	dlg.m_ofn.lpstrTitle= L"����dump";
	if ( dlg.DoModal() == IDOK )
	{
		m_path = dlg.GetPathName();
		wsprintfW(lpwzFilePath,L"\\??\\%ws",m_path);

		ReadFile((HANDLE)RESUME_PROTECT,0,0,&dwReadByte,0);

		for (int i=0;i< (int)SysModuleInfo->ulCount;i++)
		{
			wsprintfW(lpwzSysBase,L"0x%08X",SysModuleInfo->SysInfo[i].ulSysBase);
			wsprintfA(lpszSysSize,"%d",SysModuleInfo->SysInfo[i].SizeOfImage);

			if (_wcsnicmp(lpwzKernelModuleBase,lpwzSysBase,wcslen(lpwzSysBase)) == 0)
			{
				ReadFile((HANDLE)INIT_DUMP_KERNEL_MODULE_MEMORY,0,SysModuleInfo->SysInfo[i].ulSysBase,&dwReadByte,0);
				ReadFile((HANDLE)INIT_DUMP_KERNEL_MODULE_MEMORY_1,0,SysModuleInfo->SysInfo[i].SizeOfImage,&dwReadByte,0);
				ReadFile((HANDLE)DUMP_KERNEL_MODULE_MEMORY,lpwzFilePath,wcslen(lpwzFilePath),&dwReadByte,0);

				wsprintfW(lpwzForMat,L"�����ɹ���dump�ļ�������:%ws",m_path);
				MessageBoxW(hWnd,lpwzForMat,L"A�ܵ��Է���",MB_ICONWARNING);
				break;
			}
		}
	}
	ReadFile((HANDLE)RESUME_PROTECT,0,0,&dwReadByte,0);
}
