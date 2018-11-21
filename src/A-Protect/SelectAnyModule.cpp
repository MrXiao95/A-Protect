// SelectAnyModule.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-Protect.h"
#include "A-ProtectView.h"

#include "SelectAnyModule.h"
#include "afxdialogex.h"

#define  SystemModuleInformation 11

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS        0x00000000 
#define STATUS_UNSUCCESSFUL (0xC0000001L)
typedef LONG NTSTATUS;

typedef struct _SYSTEM_MODULE_INFORMATION  // ϵͳģ����Ϣ
{
	ULONG  Reserved[2];  
	ULONG  Base;        
	ULONG  Size;         
	ULONG  Flags;        
	USHORT Index;       
	USHORT Unknown;     
	USHORT LoadCount;   
	USHORT ModuleNameOffset;
	CHAR   ImageName[256];   
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _tagSysModuleList {          //ģ�����ṹ
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION smi[1];
} MODULES, *PMODULES;

extern BOOL bIsStopHookScan;

extern "C" NTSTATUS __stdcall  ZwQuerySystemInformation(
	__in       ULONG SystemInformationClass,
	__inout    PVOID SystemInformation,
	__in       ULONG SystemInformationLength,
	__out_opt  PULONG ReturnLength
	);
VOID FixSelectModuleToKernel(ULONG ulModuleBase,WCHAR *ModulePath,char *lpszModulePath);
VOID QueryKernelHook(HWND m_hWnd,ULONG ID,CMyList *m_list);
//*********************************************
typedef struct _SELECT_MODULE_INFORMATION  // ��ѡ���ģ����Ϣ
{
	ULONG  Base;        
	CHAR   lpszImageFileName[256];
	WCHAR  lpwzImageName[256];

} SELECT_MODULE_INFORMATION, *PSELECT_MODULE_INFORMATION;

typedef struct _SELECTMODULE {          //ģ�����ṹ
	ULONG ulCount;
	SELECT_MODULE_INFORMATION Module[1];
} SELECTMODULE, *PSELECTMODULE;

PSELECTMODULE SelectModuleHook;

ULONG ulKernelSize;
DWORD StringToHex(char* strSource);
//*********************************************
#define	 MODULE_MAX_COLUMN	2

wchar_t	SelectModuleStr[MODULE_MAX_COLUMN][260]  = {_T("��ַ"),_T("ģ��·��")};										 
int		SelectModuleWidth[MODULE_MAX_COLUMN]= {90,300};

// CSelectAnyModule �Ի���

IMPLEMENT_DYNAMIC(CSelectAnyModule, CDialogEx)

CSelectAnyModule::CSelectAnyModule(CWnd* pParent /*=NULL*/)
	: CDialogEx(CSelectAnyModule::IDD, pParent)
{

}

CSelectAnyModule::~CSelectAnyModule()
{
}

void CSelectAnyModule::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_SELECTANYMODULE, m_SelectAnyModuleList);
}


BEGIN_MESSAGE_MAP(CSelectAnyModule, CDialogEx)
	ON_BN_CLICKED(IDC_BTN_SELECTALL, &CSelectAnyModule::OnBnClickedBtnSelectall)
	ON_BN_CLICKED(IDC_BTN_CANCELSELECT, &CSelectAnyModule::OnBnClickedBtnCancelSelectall)
	
	ON_BN_CLICKED(IDC_BTN_SCAN, &CSelectAnyModule::OnBnClickedBtnScan)

END_MESSAGE_MAP()


// CSelectAnyModule ��Ϣ�������

BOOL CSelectAnyModule::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��

	LONG lStyle;
    lStyle = GetWindowLong(m_SelectAnyModuleList.m_hWnd, GWL_STYLE);//��ȡ��ǰ����style
    lStyle &= ~LVS_TYPEMASK; //�����ʾ��ʽλ
    lStyle |= LVS_REPORT; //����style
    SetWindowLong(m_SelectAnyModuleList.m_hWnd, GWL_STYLE, lStyle);//����style

    DWORD dwStyle = m_SelectAnyModuleList.GetExtendedStyle();
	//ѡ��ĳ��ʹ���и�����ֻ������report����listctrl��LVS_EX_DOUBLEBUFFER˫�������������˸����
    dwStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER|LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT;
    m_SelectAnyModuleList.SetExtendedStyle(dwStyle); //������չ���
	m_SelectAnyModuleList.SetExtendedStyle(m_SelectAnyModuleList.GetExtendedStyle()|LVS_EX_SUBITEMIMAGES);

	//������������ݵĳ�ʼ�������룬�ҾͲ�д�ˣ�һ��û�ȥ�ˣ����Բο��ϴ��Ҽ�����Ǹ��࣬��������������
	for(int Index = 0; Index < MODULE_MAX_COLUMN; Index++)
	{
		m_SelectAnyModuleList.InsertColumn(Index,SelectModuleStr[Index] ,LVCFMT_LEFT, SelectModuleWidth[Index]);
	}
	//***********************************************************************
	DWORD	dwsize;
	DWORD	dwSizeReturn;
	PUCHAR	pBuffer	=	NULL;
	PMODULES	pSmi=NULL;
	NTSTATUS	ntStatus=STATUS_UNSUCCESSFUL;
	int x=0;

	ntStatus = ZwQuerySystemInformation(
		SystemModuleInformation,
		pSmi, 
		0, 
		&dwSizeReturn
		);
	if (ntStatus!=STATUS_INFO_LENGTH_MISMATCH)
	{
		return 0;
	}
	dwsize	=	dwSizeReturn*2;
	pSmi	=	(PMODULES)new char[dwsize];
	if (pSmi==NULL)
	{
		return 0;
	}

	ntStatus = ZwQuerySystemInformation(
		SystemModuleInformation, 
		pSmi,
		dwsize, 
		&dwSizeReturn
		);
	if (ntStatus!=STATUS_SUCCESS)
	{
		return 0;
	}
	for (int i=0;i<(int)pSmi->ulCount;i++)
	{
		//�õ��ں˴�С
		if (i == 0){
			ulKernelSize = pSmi->smi[i].Size;
		}
		WCHAR lpwzDosFullPath[256];
		WCHAR lpwzWinDir[256];
		WCHAR lpwzSysDisk[256];
		WCHAR lpwzFullSysName[1024] = {0};
		CHAR lpszPath[1024] = {0};

		memset(lpwzWinDir,0,sizeof(lpwzWinDir));
		memset(lpwzSysDisk,0,sizeof(lpwzSysDisk));
		memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
		memset(lpwzFullSysName,0,sizeof(lpwzFullSysName));
		memset(lpszPath,0,sizeof(lpszPath));

		MultiByteToWideChar(
			CP_ACP,
			0, 
			pSmi->smi[i].ImageName,
			-1, 
			lpwzFullSysName, 
			strlen(pSmi->smi[i].ImageName)
			);

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
		if (wcsstr(lpwzFullSysName,L"\\") == 0)
		{
			memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
			wcscat(lpwzDosFullPath,lpwzSysDisk);
			wcscat(lpwzDosFullPath,L"\\WINDOWS\\system32\\drivers\\");
			wcscat(lpwzDosFullPath,lpwzFullSysName);
		}
Next:
// 		CHAR ShartPath[50] = {0};
// 		WideCharToMultiByte( CP_ACP,
// 			0,
// 			lpwzDosFullPath,
// 			-1,
// 			lpszPath,
// 			wcslen(lpwzDosFullPath)*2,
// 			NULL,
// 			NULL
// 			);
		//�����������
		WCHAR lpwzBase[50] = {0};
		wsprintfW(lpwzBase,L"%08x",pSmi->smi[i].Base);
		m_SelectAnyModuleList.InsertItem(i,lpwzBase,RGB(255,20,147));
		m_SelectAnyModuleList.SetItemText(i,1,lpwzDosFullPath);
		//
	}
	//************************************************************************
	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣: OCX ����ҳӦ���� FALSE
}

//ȫѡ
void CSelectAnyModule::OnBnClickedBtnSelectall()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	for(int i=0;i<m_SelectAnyModuleList.GetItemCount();i++)
		ListView_SetCheckState(m_SelectAnyModuleList,i,TRUE);
}
//ȡ��ȫѡ
void CSelectAnyModule::OnBnClickedBtnCancelSelectall()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	for(int i=0;i<m_SelectAnyModuleList.GetItemCount();i++)
		ListView_SetCheckState(m_SelectAnyModuleList,i,FALSE);
}
void CSelectAnyModule::OnBnClickedBtnScan()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString str;
	CString BaseText;
	CString PathText;
	int x=0;
	WCHAR lpwzBaseText[50];
	 CHAR lpszBaseText[50];

	WCHAR lpwzPathText[260];

	if (!m_SelectAnyModuleList.GetItemCount())
	{
		return;
	}
	SelectModuleHook = (PSELECTMODULE)VirtualAlloc(0, ulKernelSize+1024,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!SelectModuleHook){
		return;
	}
	memset(SelectModuleHook,0,ulKernelSize+1024);
	
	for(int i=0;i<m_SelectAnyModuleList.GetItemCount();i++)
	{
		if(ListView_GetCheckState(m_SelectAnyModuleList,i)==TRUE)
		{
			BaseText = m_SelectAnyModuleList.GetItemText(i,0);
			PathText = m_SelectAnyModuleList.GetItemText(i,1);
			//str.Format(_T("%d"),i);
			//MessageBox(PathText,BaseText,0);
			memset(lpwzPathText,0,sizeof(lpwzPathText));
			memset(lpwzBaseText,0,sizeof(lpwzBaseText));
			wcscat(lpwzBaseText,BaseText);
			wcscat(lpwzPathText,PathText);

			CHAR lpszPath[260] = {0};
			WideCharToMultiByte( CP_ACP,
				0,
				lpwzPathText,
				-1,
				lpszPath,
				wcslen(lpwzPathText)*2,
				NULL,
				NULL
				);
			wcscat(SelectModuleHook->Module[x].lpwzImageName,lpwzPathText);
			strcat(SelectModuleHook->Module[x].lpszImageFileName,lpszPath);

			WideCharToMultiByte( CP_ACP,
				0,
				lpwzBaseText,
				-1,
				lpszBaseText,
				wcslen(lpwzBaseText)*2,
				NULL,
				NULL
				);
			SelectModuleHook->Module[x].Base = StringToHex(lpszBaseText);
			SelectModuleHook->ulCount = x;
			x++;
		}
	}
	EndDialog(0);
}
void SearchSelectModuleHook(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	if (!SelectModuleHook){
		SetDlgItemTextW(m_hWnd,ID,L"û��ѡ��Ҫɨ�����Ŀ...");
		return;
	}
	for (int i=0;i<=(int)SelectModuleHook->ulCount;i++)
	{
		if (bIsStopHookScan){
			break;
		}
		//MessageBoxW(0,SelectModuleHook->Module[i].lpwzImageName,0,0);
		WCHAR lpwzTextOut[100];
		memset(lpwzTextOut,0,sizeof(lpwzTextOut));
		wsprintfW(lpwzTextOut,L"[%d-%d]%ws",SelectModuleHook->ulCount,i,SelectModuleHook->Module[i].lpwzImageName);
		SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

		FixSelectModuleToKernel(SelectModuleHook->Module[i].Base,SelectModuleHook->Module[i].lpwzImageName,SelectModuleHook->Module[i].lpszImageFileName);
		QueryKernelHook(m_hWnd,ID,m_list);
	}
	SetDlgItemTextW(m_hWnd,ID,L"ɨ�����...");
}