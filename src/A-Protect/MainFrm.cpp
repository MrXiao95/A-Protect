// MainFrm.cpp : CMainFrame ���ʵ��
#include "stdafx.h"
#include "A-Protect.h"
#include "AboutDlg.h"
#include "A-ProtectView.h"
#include "C3600Splash.h"
#include "MainFrm.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
VOID Uinstall2();
VOID Unistall1();
// CMainFrame
HINSTANCE hDbgHelp;
IMPLEMENT_DYNCREATE(CMainFrame, CFrameWndEx)
BEGIN_MESSAGE_MAP(CMainFrame, CFrameWndEx)
	ON_WM_CREATE()
	ON_WM_CLOSE()
	//ON_COMMAND(ID_VIEW_CUSTOMIZE, &CMainFrame::OnViewCustomize)
	ON_REGISTERED_MESSAGE(AFX_WM_CREATETOOLBAR, &CMainFrame::OnToolbarCreateNew)
	//ON_COMMAND(ID_Exit, &CMainFrame::OnExit)
	//ON_COMMAND(ID_About, &CMainFrame::OnAbout)
	ON_MESSAGE(WM_SHOWTASK,OnShowTask)
	ON_WM_SYSCOMMAND()
	ON_COMMAND(ID_WindowsOverhead, &CMainFrame::OnWindowsoverhead)
	ON_COMMAND(ID_CancelTheOverhead, &CMainFrame::OnCanceltheoverhead)
END_MESSAGE_MAP()
static UINT indicators[] =
{
	ID_SEPARATOR,           // ״̬��ָʾ��
	ID_INDICATOR_CAPS,
	ID_INDICATOR_NUM,
	ID_INDICATOR_SCRL,
};
// CMainFrame ����/����
CMainFrame::CMainFrame()
{
}
CMainFrame::~CMainFrame()
{
}
int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CFrameWndEx::OnCreate(lpCreateStruct) == -1)
		return -1;
  /*  C3600Splash wndSplash;                 //���������������ʵ��  
	wndSplash.Create(IDB_SPLASH);  
	wndSplash.CenterWindow();  
	wndSplash.UpdateWindow();          //send WM_PAINT 
	Sleep(100);
	Install2();
	Sleep(1500);  
	wndSplash.DestroyWindow();//���ٳ�ʼ���洰��  */
	HICON m_hIcon;
	hDbgHelp=0;
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	SetIcon(m_hIcon,TRUE);
	SetWindowTextW(_T("A�ܵ��Է��� LE 2012-0.4.4"));
	return 0;
}
BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
	if( !CFrameWndEx::PreCreateWindow(cs) )
		return FALSE;
	// TODO: �ڴ˴�ͨ���޸�
	//  CREATESTRUCT cs ���޸Ĵ��������ʽ
	cs.style   &=   ~WS_MAXIMIZEBOX;
	cs.style&=~FWS_ADDTOTITLE;
	cs.style &= ~WS_THICKFRAME;//ʹ���ڲ��������ı��С

	//cs.x=500;
	//cs.y=200;
	cs.cx = 1900;
	cs.cy = 1700;
	return TRUE;
}
// CMainFrame ���
#ifdef _DEBUG
void CMainFrame::AssertValid() const
{
	CFrameWndEx::AssertValid();
}

void CMainFrame::Dump(CDumpContext& dc) const
{
	CFrameWndEx::Dump(dc);
}
#endif //_DEBUG
// CMainFrame ��Ϣ�������
void CMainFrame::OnViewCustomize()
{
	CMFCToolBarsCustomizeDialog* pDlgCust = new CMFCToolBarsCustomizeDialog(this, TRUE /* ɨ��˵�*/);
	pDlgCust->Create();
}
LRESULT CMainFrame::OnToolbarCreateNew(WPARAM wp,LPARAM lp)
{
	return 0;
}
void CMainFrame::OnClose()
{
	if (MessageBoxW(L"�˳�֮��A�ܵ��Է��� ���޷������ں˰�ȫ��ͬʱ�޷�����ľ���ϵͳ�Ĺ�����Ϊ��ȷ��Ҫ�˳���",L"A�ܵ��Է���", MB_ICONINFORMATION|MB_YESNO) == IDYES)
	{
		Uinstall2();
		Unistall1();
		exit(0);
	}
}
void CMainFrame::OnSysCommand(UINT nID, LPARAM lParam)
{
	if(nID==SC_MINIMIZE)
	{
		NOTIFYICONDATA nid;
		nid.cbSize=(DWORD)sizeof(NOTIFYICONDATA);
		nid.hWnd=this->m_hWnd;
		nid.uID=IDR_MAINFRAME;
		nid.uFlags=NIF_INFO|NIF_ICON|NIF_MESSAGE|NIF_TIP;
		nid.dwInfoFlags=NIIF_USER;
		nid.uCallbackMessage=WM_SHOWTASK;//�Զ������Ϣ����
		nid.hIcon = AfxGetApp()->LoadIconW(IDR_MAINFRAME);
		lstrcpy(nid.szTip,_T("A�ܵ��Է��� ���ڱ�������ϵͳ..."));
		lstrcpy(nid.szInfoTitle,_T("A�ܵ��Է��� "));
		lstrcpy(nid.szInfo,_T("A�ܵ��Է��� ���ڱ�������ϵͳ..."));
		Shell_NotifyIcon(NIM_ADD,&nid);
		ShowWindow(SW_HIDE);
	}
	else
		CFrameWndEx::OnSysCommand(nID, lParam);
}
LRESULT CMainFrame::OnShowTask(WPARAM wParam,LPARAM lParam)
{
	if((lParam == WM_RBUTTONUP) || (lParam == WM_LBUTTONUP))  
    {  
        ModifyStyleEx(0,WS_EX_TOPMOST);
		NOTIFYICONDATA nid;
		nid.cbSize=(DWORD)sizeof(NOTIFYICONDATA);
		nid.hWnd=this->m_hWnd;
		nid.uID=IDR_MAINFRAME;
		nid.uFlags=NIF_ICON|NIF_MESSAGE|NIF_TIP;
		nid.dwInfoFlags=NIIF_USER;
		nid.uCallbackMessage=WM_SHOWTASK;//�Զ������Ϣ����
		nid.hIcon = AfxGetApp()->LoadIconW(IDR_MAINFRAME);
		lstrcpy(nid.szTip,TEXT("A�ܵ��Է��� "));
		Shell_NotifyIcon(NIM_DELETE,&nid);
        ShowWindow(SW_SHOWDEFAULT);
    } 
	return 0;
}
void CMainFrame::OnWindowsoverhead()
{
	// TODO: �ڴ���������������
	::SetWindowPos(this->m_hWnd,HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
	AfxMessageBox(L"���ô��ڶ��óɹ�!");
}
void CMainFrame::OnCanceltheoverhead()
{
	// TODO: �ڴ���������������
	::SetWindowPos(this->m_hWnd,HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
	AfxMessageBox(L"ȡ�����ڶ��óɹ�!");
}
