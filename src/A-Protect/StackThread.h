#pragma once
#include "afxcmn.h"
#include "MyList.h"
// CStackThread �Ի���
class CStackThread : public CDialogEx
{
	DECLARE_DYNAMIC(CStackThread)
public:
	CStackThread(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CStackThread();
// �Ի�������
	enum { IDD = IDD_DLG_STACKTHREAD };
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	DECLARE_MESSAGE_MAP()
public:
	CString m_strStackThread;
	virtual BOOL OnInitDialog();
	afx_msg void OnBnThreadStackByPDB();
	CListCtrl	m_ListCtrl;
};
