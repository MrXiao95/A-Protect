#pragma once
#include "afxcmn.h"
#include "MyList.h"


// CCProcessSearch �Ի���

class CCProcessSearch : public CDialogEx
{
	DECLARE_DYNAMIC(CCProcessSearch)

public:
	CCProcessSearch(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CCProcessSearch();

// �Ի�������
	enum { IDD = IDD_DLG_PROCESSSEARCH };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CString m_strFindInfo;
	CMyList m_listFindInfo;
	int idFrom;//��id���������Ǵ�������õĸöԻ��򣬶���������Ӧ�ĳ�ʼ��������
	virtual BOOL OnInitDialog();
	afx_msg void SearchDllModuleInfo(CMyList *m_listInfo,int Type);
	afx_msg void OnBnClickedBtnSearch();
	afx_msg void OnBnClickedStopSearch();
	//afx_msg void OnTimer(UINT_PTR nIDEvent);
};
