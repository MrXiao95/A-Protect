// ProtectSetting.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-Protect.h"
#include "ProtectSetting.h"
#include "afxdialogex.h"
#include "uninstall360.h"

// CProtectSetting �Ի���

BOOL bDisLoadDriver = TRUE;
BOOL bDisCreateProcess = TRUE;
BOOL bDisWriteFile = TRUE;
BOOL bDisResetServices = TRUE;
BOOL bDisKernelThread = TRUE;
BOOL bDisSetWindowsHook = TRUE;
BOOL bDisDllFuck = TRUE;

IMPLEMENT_DYNAMIC(CProtectSetting, CDialogEx)

CProtectSetting::CProtectSetting(CWnd* pParent /*=NULL*/)
	: CDialogEx(CProtectSetting::IDD, pParent)
{
}

CProtectSetting::~CProtectSetting()
{
}

void CProtectSetting::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);

	if (bDisLoadDriver == FALSE){
		SetDlgItemText(IDC_DisLoadDriver,L"�����������");
	}
	if (bDisCreateProcess == FALSE){
		SetDlgItemText(IDC_DisCreateProcess,L"����������");
	}
	if (bDisWriteFile == FALSE){
		SetDlgItemText(IDC_DisCreateFile,L"�������ļ�");
	}
	if (bDisResetServices == FALSE){
		SetDlgItemText(IDC_DisSrvReset,L"��������д");
	}
	if (bDisKernelThread == FALSE){
		SetDlgItemText(IDC_DisKernelThread,L"�����ں��߳�");
	}
	if (bDisSetWindowsHook == FALSE){
		SetDlgItemText(IDC_DisUserHook,L"����ȫ�ֹ���");
	}
	if (bDisDllFuck == FALSE){
		SetDlgItemText(IDC_DisDllFuck,L"����DLLЮ�ַ���");
	}
}


BEGIN_MESSAGE_MAP(CProtectSetting, CDialogEx)
	ON_BN_CLICKED(IDC_DeleteFile, &CProtectSetting::OnBnClickedDeletefile)
	ON_BN_CLICKED(IDC_DisLoadDriver, &CProtectSetting::OnBnClickedDisloaddriver)
	ON_BN_CLICKED(IDC_DisCreateProcess, &CProtectSetting::OnBnClickedDiscreateprocess)
	ON_BN_CLICKED(IDC_DisCreateFile, &CProtectSetting::OnBnClickedDiscreatefile)
	ON_BN_CLICKED(IDC_DisSrvReset, &CProtectSetting::OnBnClickedDissrvreset)
	ON_BN_CLICKED(IDC_DisKernelThread, &CProtectSetting::OnBnClickedDiskernelthread)
	ON_BN_CLICKED(IDC_DisUserHook, &CProtectSetting::OnBnClickedDisSetWindowsHook)
	ON_BN_CLICKED(IDC_DisDllFuck, &CProtectSetting::OnBnClickedDisDllFuck)
	

	ON_BN_CLICKED(IDC_ShutdownSystem, &CProtectSetting::OnBnClickedShutdownsystem)
	ON_BN_CLICKED(IDC_Uninstall360, &CProtectSetting::OnBnClickedUninstall360)
END_MESSAGE_MAP()


// CProtectSetting ��Ϣ�������


void CProtectSetting::OnBnClickedDeletefile()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//AfxMessageBox(_T("������������"));
	DWORD dwReadByte;
	WCHAR lpwzDeletedFile[256];
	CString			m_path;

	//��ͣ��Ȼ�޷���Ϊ������win7���޷��򿪶Ի���
	ReadFile((HANDLE)SUSPEND_PROTECT,0,0,&dwReadByte,0);
	//Sleep(3000);

	//ǿ��ɾ���ļ���ʱ��Ҫ�л����ں˰�ȫģʽȥ
	ReadFile((HANDLE)KERNEL_SAFE_MODULE,0,0,&dwReadByte,0);

	CFileDialog dlg( TRUE,L"*.*",0, 0,L"�����ļ�|*.*");
	dlg.m_ofn.lpstrTitle= L"����ɾ���ļ�";
	if ( dlg.DoModal() == IDOK )
	{
		m_path = dlg.GetPathName();
		memset(lpwzDeletedFile,0,sizeof(lpwzDeletedFile));
		wsprintfW(lpwzDeletedFile,L"\\??\\%ws",m_path);
		ReadFile((HANDLE)RESUME_PROTECT,0,0,&dwReadByte,0);
		ReadFile((HANDLE)DELETE_FILE,lpwzDeletedFile,wcslen(lpwzDeletedFile),&dwReadByte,0);
		if (GetFileAttributesW(m_path) == INVALID_FILE_ATTRIBUTES)
		{
			MessageBoxW(L"�ļ�ɾ���ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
		}
	}
	//�ټ��������Լ��Ľ���
	ReadFile((HANDLE)RESUME_PROTECT,0,0,&dwReadByte,0);
}
void CProtectSetting::OnBnClickedDisloaddriver()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//AfxMessageBox(_T("������������"));
	DWORD dwReadByte;

	if (bDisLoadDriver == TRUE)
	{
		ReadFile((HANDLE)DIS_LOAD_DRIVER,0,0,&dwReadByte,0);
		bDisLoadDriver = FALSE;
		SetDlgItemText(IDC_DisLoadDriver,L"�����������");

	}else
	{
		ReadFile((HANDLE)LOAD_DRIVER,0,0,&dwReadByte,0);
		bDisLoadDriver = TRUE;
		SetDlgItemText(IDC_DisLoadDriver,L"��ֹ��������");
	}
}
void CProtectSetting::OnBnClickedDiscreateprocess()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//AfxMessageBox(_T("������������"));
	DWORD dwReadByte;

	if (bDisCreateProcess == TRUE)
	{
		ReadFile((HANDLE)DIS_CREATE_PROCESS,0,0,&dwReadByte,0);
		bDisCreateProcess = FALSE;
		SetDlgItemText(IDC_DisCreateProcess,L"����������");

	}else
	{
		ReadFile((HANDLE)CREATE_PROCESS,0,0,&dwReadByte,0);
		bDisCreateProcess = TRUE;
		SetDlgItemText(IDC_DisCreateProcess,L"��ֹ��������");
	}
}

void CProtectSetting::OnBnClickedDiscreatefile()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//AfxMessageBox(_T("������������"));
	DWORD dwReadByte;

	if (bDisWriteFile == TRUE)
	{
		ReadFile((HANDLE)DIS_WRITE_FILE,0,0,&dwReadByte,0);
		bDisWriteFile = FALSE;
		SetDlgItemText(IDC_DisCreateFile,L"�������ļ�");

	}else
	{
		ReadFile((HANDLE)WRITE_FILE,0,0,&dwReadByte,0);
		bDisWriteFile = TRUE;
		SetDlgItemText(IDC_DisCreateFile,L"��ֹ�����ļ�");
	}
}

void CProtectSetting::OnBnClickedDissrvreset()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//AfxMessageBox(_T("������������"));
	DWORD dwReadByte;

	if (bDisResetServices == TRUE)
	{
		ReadFile((HANDLE)DIS_RESET_SRV,0,0,&dwReadByte,0);
		bDisResetServices = FALSE;
		SetDlgItemText(IDC_DisSrvReset,L"��������д");

	}else
	{
		ReadFile((HANDLE)RESET_SRV,0,0,&dwReadByte,0);
		bDisResetServices = TRUE;
		SetDlgItemText(IDC_DisSrvReset,L"��ֹ�����д");
	}
}
void CProtectSetting::OnBnClickedDiskernelthread()
{
	DWORD dwReadByte;

	if (bDisKernelThread == TRUE)
	{
		ReadFile((HANDLE)DIS_KERNEL_THREAD,0,0,&dwReadByte,0);
		bDisKernelThread = FALSE;
		SetDlgItemText(IDC_DisKernelThread,L"�����ں��߳�");

	}else
	{
		ReadFile((HANDLE)KERNEL_THREAD,0,0,&dwReadByte,0);
		bDisKernelThread = TRUE;
		SetDlgItemText(IDC_DisKernelThread,L"��ֹ�ں��߳�");
	}
}
void CProtectSetting::OnBnClickedDisSetWindowsHook()
{
	DWORD dwReadByte;

	if (bDisSetWindowsHook == TRUE)
	{
		ReadFile((HANDLE)DIS_SET_WINDOWS_HOOK,0,0,&dwReadByte,0);
		bDisSetWindowsHook = FALSE;
		SetDlgItemText(IDC_DisUserHook,L"����ȫ�ֹ���");

	}else
	{
		ReadFile((HANDLE)SET_WINDOWS_HOOK,0,0,&dwReadByte,0);
		bDisSetWindowsHook = TRUE;
		SetDlgItemText(IDC_DisUserHook,L"��ֹȫ�ֹ���");
	}
}
void CProtectSetting::OnBnClickedDisDllFuck()
{
	DWORD dwReadByte;

	if (bDisDllFuck == TRUE)
	{
		ReadFile((HANDLE)DIS_DLL_FUCK,0,0,&dwReadByte,0);
		bDisDllFuck = FALSE;
		SetDlgItemText(IDC_DisDllFuck,L"����DLLЮ�ַ���");

	}else
	{
		ReadFile((HANDLE)DLL_FUCK,0,0,&dwReadByte,0);
		bDisDllFuck = TRUE;
		SetDlgItemText(IDC_DisDllFuck,L"�ر�DLLЮ�ַ���");
	}
}

void CProtectSetting::OnBnClickedShutdownsystem()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	DWORD dwReadByte;
	ReadFile((HANDLE)SHUT_DOWN_SYSTEM,0,0,&dwReadByte,0);
}

void ReadDeskPath(LPCSTR DaskPath)
{
	CHAR path[255];
	ZeroMemory(path,255);
	SHGetSpecialFolderPathA(0,path,CSIDL_DESKTOPDIRECTORY,0);
	lstrcatA((char *)DaskPath,path);
	return;
}

void CProtectSetting::OnBnClickedUninstall360()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	DWORD dwReadByte;

	HKEY hkRoot2 = HKEY_LOCAL_MACHINE;
	HKEY hkRoot3 = HKEY_LOCAL_MACHINE;
	BOOL bFound360 = FALSE;

	if(RegOpenKeyExW(hkRoot2,L"SYSTEM\\CurrentControlSet\\Services\\zhudongfangyu", 0, KEY_QUERY_VALUE, &hkRoot2) == ERROR_SUCCESS ||
		RegOpenKeyExW(hkRoot3,L"SYSTEM\\CurrentControlSet\\Services\\360rp", 0, KEY_QUERY_VALUE, &hkRoot3) == ERROR_SUCCESS)
	{
		bFound360 = TRUE;
	}
	if (!bFound360)
	{
		MessageBoxW(L"��ϲ����ϵͳ��û�з���360������Ҫһ��ж�أ�",L"A�ܵ��Է���",MB_ICONINFORMATION);
		return;
	}
	RegCloseKey(hkRoot2);
	RegCloseKey(hkRoot3);

	if (MessageBoxW(L"��A�ܵ��Է�������Ȼ�ṩһ��ж��360�Ĺ��ܣ�����������ж�ز��������û�������ʶȥ�����һ��ж��360�������ж�ء�\r\n\r\nAProtect�ٴ�ȷ���Ƿ�Ҫһ��ж��360��\r\n",L"A�ܵ��Է���",MB_ICONINFORMATION|MB_YESNO) == IDYES)
	{
		//��ʼж��360
		SetDlgItemText(IDC_Uninstall360,L"����ж��...");

		//ȥ������
		ReadFile((HANDLE)UNPROTECT_360SAFE,0,0,&dwReadByte,0);
		Uninstall360();

		//�����ݷ�ʽ
		char lpszDesk[260] = {0};
		char lpsz360lnk[260] = {0};

		memset(lpszDesk,0,260);
		memset(lpsz360lnk,0,260);
		ReadDeskPath(lpszDesk);

		wsprintfA(lpsz360lnk,"%s\\360��ȫ��ʿ.lnk",lpszDesk);
		DeleteFileA(lpsz360lnk);

		memset(lpsz360lnk,0,260);
		wsprintfA(lpsz360lnk,"%s\\360����ܼ�.lnk",lpszDesk);
		DeleteFileA(lpsz360lnk);

		memset(lpsz360lnk,0,260);
		wsprintfA(lpsz360lnk,"%s\\360ɱ��.lnk",lpszDesk);
		DeleteFileA(lpsz360lnk);

		char lpWinDir[260] = {0};
		char lpSysDisk[10] = {0};
		GetWindowsDirectoryA(lpWinDir,sizeof(lpWinDir));
		memcpy(lpSysDisk,lpWinDir,4);

		memset(lpsz360lnk,0,260);
		wsprintfA(lpsz360lnk,"%s\\Documents and Settings\\All Users\\����\\360ɱ��.lnk",lpSysDisk);
		DeleteFileA(lpsz360lnk);

		memset(lpsz360lnk,0,260);
		wsprintfA(lpsz360lnk,"%s\\Documents and Settings\\All Users\\Desktop\\360ɱ��.lnk",lpSysDisk);
		DeleteFileA(lpsz360lnk);

		SetDlgItemText(IDC_Uninstall360,L"һ��ж��360");
		if (MessageBoxW(L"һ��ж����ϣ������360�ļ������´�ϵͳ����ʱ�Զ�ɾ����\r\n\r\n�Ƿ�����������",L"A�ܵ��Է���",MB_ICONINFORMATION | MB_YESNO) == IDYES)
		{
			ReadFile((HANDLE)SHUT_DOWN_SYSTEM,0,0,&dwReadByte,0);
		}
	}
}
