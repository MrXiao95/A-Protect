#pragma once
#include "afxcmn.h"
#include "MyList.h"
// CSelectKernelModuleHook �Ի���
class CSelectKernelModuleHook : public CDialogEx
{
	DECLARE_DYNAMIC(CSelectKernelModuleHook)
public:
	CSelectKernelModuleHook(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CSelectKernelModuleHook();
// �Ի�������
	enum { IDD = IDD_DLG_SKMHOOK };
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	DECLARE_MESSAGE_MAP()
public:
	CMyList m_SKMHOOKList;
	virtual BOOL OnInitDialog();
};
