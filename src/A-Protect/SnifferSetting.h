#pragma once
// CSnifferSetting �Ի���
class CSnifferSetting : public CDialogEx
{
	DECLARE_DYNAMIC(CSnifferSetting)
public:
	CSnifferSetting(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CSnifferSetting();
// �Ի�������
	enum { IDD = IDD_DLG_SNIFFERSETTING };
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	DECLARE_MESSAGE_MAP()
public:
	CString m_strData;
	CString m_strDataDescription;
};
