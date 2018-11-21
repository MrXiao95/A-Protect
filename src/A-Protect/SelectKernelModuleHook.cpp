// SelectKernelModuleHook.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-Protect.h"
#include "SelectKernelModuleHook.h"
#include "afxdialogex.h"


// CSelectKernelModuleHook �Ի���

HWND skmhWnd;
#define   SKERNEL_HOOK_MAX_COLUMN 9

wchar_t	SHookStr[SKERNEL_HOOK_MAX_COLUMN][260]  = {_T("���ҹ���ַ"),_T("ԭʼ��ַ"),		_T("����"),	_T("hook��ת��ַ"),	_T("Hookģ��"),_T("ԭʼģ��"),		
	_T("ģ���ַ"),	_T("ģ���С"),	_T("Hook����")};										 
int		SHookWidth[SKERNEL_HOOK_MAX_COLUMN]= {80,80,  100, 90, 180,  160, 80, 80,80};


IMPLEMENT_DYNAMIC(CSelectKernelModuleHook, CDialogEx)

CSelectKernelModuleHook::CSelectKernelModuleHook(CWnd* pParent /*=NULL*/)
	: CDialogEx(CSelectKernelModuleHook::IDD, pParent)
{

}

CSelectKernelModuleHook::~CSelectKernelModuleHook()
{
}

void CSelectKernelModuleHook::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_SKMHOOKList);
}


BEGIN_MESSAGE_MAP(CSelectKernelModuleHook, CDialogEx)
END_MESSAGE_MAP()


// CSelectKernelModuleHook ��Ϣ�������
extern VOID QueryKernelHook(HWND m_hWnd,ULONG ID,CMyList *m_list);

DWORD WINAPI SQueryKernelHookFunction(CMyList *m_ListCtrl)
{
	QueryKernelHook(skmhWnd,IDC_DebugStatus,m_ListCtrl);
	return 0;
}

BOOL CSelectKernelModuleHook::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	LONG lStyle;
    lStyle = GetWindowLong(m_SKMHOOKList.m_hWnd, GWL_STYLE);//��ȡ��ǰ����style
    lStyle &= ~LVS_TYPEMASK; //�����ʾ��ʽλ
    lStyle |= LVS_REPORT; //����style
    SetWindowLong(m_SKMHOOKList.m_hWnd, GWL_STYLE, lStyle);//����style

    DWORD dwStyle = m_SKMHOOKList.GetExtendedStyle();
	//ѡ��ĳ��ʹ���и�����ֻ������report����listctrl��LVS_EX_DOUBLEBUFFER˫�������������˸����
    dwStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER;
    m_SKMHOOKList.SetExtendedStyle(dwStyle); //������չ���
	m_SKMHOOKList.SetExtendedStyle(m_SKMHOOKList.GetExtendedStyle()|LVS_EX_SUBITEMIMAGES);

	skmhWnd=m_hWnd;

	for(int Index = 0; Index < SKERNEL_HOOK_MAX_COLUMN; Index++)
	{
		m_SKMHOOKList.InsertColumn(Index, SHookStr[Index] ,LVCFMT_CENTER, SHookWidth[Index]);
	}

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SQueryKernelHookFunction,&m_SKMHOOKList, 0,NULL);

	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣: OCX ����ҳӦ���� FALSE
}
