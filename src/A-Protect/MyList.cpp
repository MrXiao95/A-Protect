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
#include "stdafx.h"
#include "MyList.h"

// CMyList

IMPLEMENT_DYNAMIC(CMyList, CListCtrl)

CMyList::CMyList()
{
}

CMyList::~CMyList()
{
}

BEGIN_MESSAGE_MAP(CMyList, CListCtrl)
	ON_NOTIFY_REFLECT(NM_CUSTOMDRAW, &CMyList::OnNMCustomdraw)
END_MESSAGE_MAP()

CMap<DWORD , DWORD& , COLORREF , COLORREF&> MapItemColor;

void CMyList::OnNMCustomdraw(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)pNMHDR;

	if (lplvcd->nmcd.dwDrawStage == CDDS_PREPAINT)
	{
	    *pResult = CDRF_NOTIFYITEMDRAW;
	}
    else if (lplvcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
	    *pResult = CDRF_NOTIFYSUBITEMDRAW;
	}
    else if (lplvcd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM))
    {
		COLORREF ItemColor;
		if(MapItemColor.Lookup((lplvcd->nmcd.dwItemSpec), ItemColor))
		{
                //lplvdr->clrText = RGB(0,0,0);//ItemColor;
				lplvcd->clrText = ItemColor;
                *pResult = CDRF_DODEFAULT;
        }
	}
}
// CMyList ��Ϣ�������

//����ͼ��ͼ�����
CImageList* CMyList::SetImageList(CImageList *pImageList)
{
	return CListCtrl::SetImageList(pImageList,LVSIL_SMALL);
}
//����ͼ��id
BOOL CMyList::SetItemImageId(int nItem,int nImageId)
{
	return CListCtrl::SetItem(nItem,0,LVIF_IMAGE,NULL,nImageId,0,0,0);
}
//�������ݣ�������������ɫ
int CMyList::InsertItem(int nItem,LPCTSTR lpText,COLORREF fontcolor)
{
	const int IDX = CListCtrl::InsertItem(nItem, lpText);
	//�ı���ɫ
	DWORD iItem=(DWORD)nItem;
	MapItemColor.SetAt(iItem, fontcolor);
	CListCtrl::RedrawItems(iItem,iItem);
	CListCtrl::Update(iItem);
	return IDX;
}