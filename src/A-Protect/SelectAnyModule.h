#pragma once
#include "afxcmn.h"
// CSelectAnyModule �Ի���
class CSelectAnyModule : public CDialogEx
{
	DECLARE_DYNAMIC(CSelectAnyModule)
public:
	CSelectAnyModule(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CSelectAnyModule();
	enum { IDD = IDD_DLG_SELECTANYMODELE };
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_SelectAnyModuleList;
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedBtnSelectall();
	afx_msg void OnBnClickedBtnCancelSelectall();
	afx_msg void OnBnClickedBtnScan();
};
