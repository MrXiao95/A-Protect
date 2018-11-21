// Mouclass.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-ProtectView.h"
#include "Mouclass.h"

void QueryMouclassHook(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	DWORD dwReadByte;
	int i=0;
	int ItemNum = m_list->GetItemCount();

	SHFILEINFO shfileinfo;
	MouclassImg.Create(16,16, ILC_COLOR32, 2, 100);
	HIMAGELIST hImageList = NULL;


	SetDlgItemTextW(m_hWnd,ID,L"����ɨ��Mouclass/Dispatch�����Ժ�...");

	if (bIsPhysicalCheck){
		SaveToFile("\r\n\r\n[---MOUCLASS.SYS---]\r\n",PhysicalFile);
	}
	if (MouclassDispatchBakUp)
	{
		VirtualFree(MouclassDispatchBakUp,sizeof(MOUCLASSDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2,MEM_RESERVE | MEM_COMMIT);
		MouclassDispatchBakUp = 0;
	}
	MouclassDispatchBakUp = (PMOUCLASSDISPATCHBAKUP)VirtualAlloc(0,sizeof(MOUCLASSDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (MouclassDispatchBakUp)
	{
		memset(MouclassDispatchBakUp,0,sizeof(MOUCLASSDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2);

		ReadFile((HANDLE)LIST_MOUCLASS_HOOK,MouclassDispatchBakUp,sizeof(MOUCLASSDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2,&dwReadByte,0);

		for (i=0;i< (int)MouclassDispatchBakUp->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",MouclassDispatchBakUp->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzNumber[256] = {0};
			WCHAR lpwzHookType[256] = {0};
			WCHAR lpwzFunction[256] = {0};
			WCHAR lpwzHookModuleImage[256] = {0};
			WCHAR lpwzCurrentMouclassDispatch[256] = {0};
			WCHAR lpwsMouclassDispatch[256] = {0};

			WCHAR lpwzHookModuleBase[256] = {0};
			WCHAR lpwzHookModuleSize[256] = {0};

			memset(lpwzNumber,0,sizeof(lpwzNumber));
			memset(lpwzHookType,0,sizeof(lpwzHookType));

			memset(lpwzFunction,0,sizeof(lpwzFunction));
			memset(lpwzHookModuleImage,0,sizeof(lpwzHookModuleImage));
			memset(lpwzCurrentMouclassDispatch,0,sizeof(lpwzCurrentMouclassDispatch));
			memset(lpwsMouclassDispatch,0,sizeof(lpwsMouclassDispatch));

			memset(lpwzHookModuleBase,0,sizeof(lpwzHookModuleBase));
			memset(lpwzHookModuleSize,0,sizeof(lpwzHookModuleSize));

			switch (MouclassDispatchBakUp->MouclassDispatch[i].Hooked)
			{
			case 0:
				StrCatW(lpwzHookType,L"-");
				break;
			case 1:
				StrCatW(lpwzHookType,L"mou hook");
				break;
			case 2:
				StrCatW(lpwzHookType,L"mou Inline hook");
				break;
			}

			wsprintfW(lpwzNumber,L"%d",MouclassDispatchBakUp->MouclassDispatch[i].ulNumber);

			//wsprintfW(lpwzHookModuleImage,L"%ws",MouclassDispatchBakUp->MouclassDispatch[i].lpszBaseModule);
			MultiByteToWideChar(
				CP_ACP,
				0, 
				MouclassDispatchBakUp->MouclassDispatch[i].lpszBaseModule,
				-1, 
				lpwzHookModuleImage, 
				strlen(MouclassDispatchBakUp->MouclassDispatch[i].lpszBaseModule)
				);
			wsprintfW(lpwzFunction,L"%ws",MouclassDispatchBakUp->MouclassDispatch[i].lpwzMouclassDispatchName);
			wsprintfW(lpwzCurrentMouclassDispatch,L"0x%08X",MouclassDispatchBakUp->MouclassDispatch[i].ulCurrentMouclassDispatch);
			wsprintfW(lpwsMouclassDispatch,L"0x%08X",MouclassDispatchBakUp->MouclassDispatch[i].ulMouclassDispatch);
			wsprintfW(lpwzHookModuleBase,L"0x%X",MouclassDispatchBakUp->MouclassDispatch[i].ulModuleBase);
			wsprintfW(lpwzHookModuleSize,L"0x%X",MouclassDispatchBakUp->MouclassDispatch[i].ulModuleSize);

			WCHAR lpwzDosFullPath[256];
			WCHAR lpwzWinDir[256];
			WCHAR lpwzSysDisk[256];

			memset(lpwzWinDir,0,sizeof(lpwzWinDir));
			memset(lpwzSysDisk,0,sizeof(lpwzSysDisk));
			memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));

			GetWindowsDirectoryW(lpwzWinDir,sizeof(lpwzWinDir));
			memcpy(lpwzSysDisk,lpwzWinDir,4);

			if (wcsstr(lpwzHookModuleImage,L"\\??\\"))
			{
				//��ʼ����·���Ĵ���
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcsncpy(lpwzDosFullPath,lpwzHookModuleImage+wcslen(L"\\??\\"),wcslen(lpwzHookModuleImage)-wcslen(L"\\??\\"));
				goto Next;
			}
			if (wcsstr(lpwzHookModuleImage,L"\\WINDOWS\\system32\\"))
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat(lpwzDosFullPath,lpwzSysDisk);
				wcscat(lpwzDosFullPath,lpwzHookModuleImage);
				//MessageBoxW(lpwzDosFullPath,lpwzFullSysName,0);
				goto Next;
			}
			if (wcsstr(lpwzHookModuleImage,L"\\SystemRoot\\"))
			{
				WCHAR lpwzTemp[256];
				memset(lpwzTemp,0,sizeof(lpwzTemp));
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat(lpwzTemp,lpwzSysDisk);
				wcscat(lpwzTemp,L"\\WINDOWS\\");
				wcscat(lpwzDosFullPath,lpwzTemp);
				wcsncpy(lpwzDosFullPath+wcslen(lpwzTemp),lpwzHookModuleImage+wcslen(L"\\SystemRoot\\"),wcslen(lpwzHookModuleImage) - wcslen(L"\\SystemRoot\\"));
				goto Next;
			}
			//if (wcslen(lpwzHookModuleImage) == wcslen(lpwzHookModuleImage))
			//{
			memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
			wcscat(lpwzDosFullPath,lpwzSysDisk);
			wcscat(lpwzDosFullPath,L"\\WINDOWS\\system32\\drivers\\");
			wcscat(lpwzDosFullPath,lpwzHookModuleImage);
			goto Next;
			//}
Next:
			//������һ���������ݣ�����Ҫ���������
			if (bIsPhysicalCheck){
				//���û��hook���ͷ���
				if (MouclassDispatchBakUp->MouclassDispatch[i].Hooked == 0){
					continue;
				}
				WCHAR lpwzSaveBuffer[1024] ={0};
				CHAR lpszSaveBuffer[2024] ={0};
				memset(lpwzSaveBuffer,0,sizeof(lpwzSaveBuffer));
				memset(lpszSaveBuffer,0,sizeof(lpszSaveBuffer));

				wsprintfW(lpwzSaveBuffer,L"          --> ����Hook:ID:%ws | ��ǰ��ַ:%ws | ԭʼ��ַ:%ws | ������:%ws | �ں�ģ��:%ws | Hook����:%ws\r\n",
					lpwzNumber,lpwzCurrentMouclassDispatch,lpwsMouclassDispatch,lpwzFunction,lpwzDosFullPath,lpwzHookType);

				m_list->InsertItem(0,L"MOUCLASEE.SYS",RGB(77,77,77));
				m_list->SetItemText(0,1,lpwzSaveBuffer);

				WideCharToMultiByte( CP_ACP,
					0,
					lpwzSaveBuffer,
					-1,
					lpszSaveBuffer,
					wcslen(lpwzSaveBuffer)*2,
					NULL,
					NULL
					);
				SaveToFile(lpszSaveBuffer,PhysicalFile);
				continue;
			}
			if (MouclassDispatchBakUp->MouclassDispatch[i].Hooked == 0)
			{
				m_list->InsertItem(i,lpwzNumber,RGB(77,77,77));

			}else
			{
				m_list->InsertItem(i,lpwzNumber,RGB(255,20,147));
			}
			m_list->SetItemText(i,1,lpwzFunction);
			m_list->SetItemText(i,2,lpwzCurrentMouclassDispatch);
			m_list->SetItemText(i,3,lpwsMouclassDispatch);
			m_list->SetItemText(i,4,lpwzDosFullPath);
			m_list->SetItemText(i,5,lpwzHookModuleBase);
			m_list->SetItemText(i,6,lpwzHookModuleSize);
			m_list->SetItemText(i,7,lpwzHookType);

			hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzDosFullPath,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
			MouclassImg.Add(shfileinfo.hIcon);
			m_list->SetImageList(&MouclassImg);
			m_list->SetItemImageId(i,i);
			DestroyIcon(shfileinfo.hIcon);
		}
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"Mouclass/Dispatch ɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

}
void MouclassHookResetOne(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	DWORD dwReadByte;
	CString str;
	CString Num;
	CString Address;

	CString FunctionStr;

	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	str.Format(L"%s",m_list->GetItemText(Item,7));

	if (!wcslen(str))
	{
		return;
	}
	if (wcsstr(str,L"-") != NULL)
	{
		AfxMessageBox(_T("�ú�������Ҫ�ָ���"));
		return;
	}
	WCHAR lpwzNum[10];
	char lpszNum[10];

	if (wcsstr(str,L"mou") != NULL)
	{
		//ȡ���
		Num.Format(L"%s",m_list->GetItemText(Item,0));

		memset(lpszNum,0,sizeof(lpszNum));
		memset(lpwzNum,0,sizeof(lpwzNum));
		wcscat_s(lpwzNum,Num);
		WideCharToMultiByte (CP_OEMCP,NULL,lpwzNum,-1,lpszNum,wcslen(lpwzNum),NULL,FALSE);
		ReadFile((HANDLE)INIT_SET_MOUCLASS_HOOK,0,atoi(lpszNum),&dwReadByte,0);

		for (int i = 0;i< (int)MouclassDispatchBakUp->ulCount;i++)
		{
			if (atoi(lpszNum) == MouclassDispatchBakUp->MouclassDispatch[i].ulNumber)
			{
				ReadFile((HANDLE)SET_MOUCLASS_HOOK,0,MouclassDispatchBakUp->MouclassDispatch[i].ulMouclassDispatch,&dwReadByte,0);
				break;
			}
		}

		//ɾ����ǰѡ���һ��
		m_list->DeleteAllItems();
		QueryMouclassHook(m_hWnd,ID,m_list);
	}
}
void CopyMouclassDataToClipboard(HWND m_hWnd,CMyList *m_list)
{
	CString FunctionName;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	FunctionName.Format(L"%s",m_list->GetItemText(Item,1));

	WCHAR lpwzFunctionName[260];

	memset(lpwzFunctionName,0,sizeof(lpwzFunctionName));
	wcscat_s(lpwzFunctionName,FunctionName);
	CHAR lpszFunctionName[1024];
	char *lpString = NULL;

	memset(lpwzFunctionName,0,sizeof(lpwzFunctionName));
	memset(lpszFunctionName,0,sizeof(lpszFunctionName));
	wcscat_s(lpwzFunctionName,FunctionName);
	WideCharToMultiByte( CP_ACP,
		0,
		lpwzFunctionName,
		-1,
		lpszFunctionName,
		wcslen(lpwzFunctionName)*2,
		NULL,
		NULL
		);
	lpString = setClipboardText(lpszFunctionName);
	if (lpString)
	{
		MessageBoxW(m_hWnd,L"�����ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
	}
}