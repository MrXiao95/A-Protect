///////////////////////////////////////////////////////////////////////////
//CListCtrl���һ��������
//����ļ��㹦�ܣ�
//1������ʹ�ö��߳�
//2�������ڵ�һ�в���ͼ��
//3�����Ըı�������ɫ
//˵�����ù�����CListCtrl��������
//��Щ�����ʹ�ö��̣߳����������ػ��ԭ��ʼ�ռӲ���ͼ��
//��Щ����Լ���ͼ�꣬������Windows��Ϣ��ԭ��ʹ�ö��߳̾ͳ���
//����������̫�࣬������Ҫ����ʱ��ȥ���㣬�ֲ���ʹ�û����ý��濨��ֻ���ö��߳�
//���Ǿ��ۺ���һ�£�д������࣬���ܼ򵥣�������⡣
//�����ǵ�һ��д�࣬��ϣ����Ҷ���Ὠ��
//by l0g1n-------2012��6��12��   17��44     QQ:519710391
///////////////////////////////////////////////////////////////////////////
#pragma once
// CMyList
class CMyList : public CListCtrl
{
	DECLARE_DYNAMIC(CMyList)
public:
	CMyList();
	virtual ~CMyList();
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnNMCustomdraw(NMHDR *pNMHDR, LRESULT *pResult);
	//����ͼ��ͼ�����
	CImageList* SetImageList(CImageList *pImageList);
	//����ͼ��id
	BOOL SetItemImageId(int nItem,int nImageId);
	//�������ݣ�������������ɫ
	int InsertItem(int nItem,LPCTSTR lpText,COLORREF fontcolor=RGB(0,0,0));
};
