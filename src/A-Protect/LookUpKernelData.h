#pragma once
#include "afxwin.h"
// CLookUpKernelData �Ի���
class CLookUpKernelData : public CDialogEx
{
	DECLARE_DYNAMIC(CLookUpKernelData)
public:
	CLookUpKernelData(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CLookUpKernelData();
// �Ի�������
	enum { IDD = IDD_DLG_KERNALDATA };
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	DECLARE_MESSAGE_MAP()
public:
	CString m_ccbKernelBase;
	CString m_strLookUpSize;
	CString m_strKernelData;
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedBtnok();
};
