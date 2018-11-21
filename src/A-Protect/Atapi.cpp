// Atapi.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "A-ProtectView.h"
#include "Atapi.h"

void QueryAtapiHook(HWND m_hWnd,ULONG ID,CMyList *m_list)
{
	DWORD dwReadByte;
	int ItemNum = m_list->GetItemCount();
	int i=0;

	SHFILEINFO shfileinfo;
	AtapiImg.Create(16,16, ILC_COLOR32, 2, 100);
	HIMAGELIST hImageList = NULL;

	SetDlgItemTextW(m_hWnd,ID,L"����ɨ��Atapi/Dispatch�����Ժ�...");

	if (bIsPhysicalCheck){
		SaveToFile("\r\n\r\n[---ATAPI.SYS---]\r\n",PhysicalFile);
	}
	if (AtapiDispatchBakUp)
	{
		VirtualFree(AtapiDispatchBakUp,sizeof(ATAPIDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2,MEM_RESERVE | MEM_COMMIT);
		AtapiDispatchBakUp = 0;
	}
	AtapiDispatchBakUp = (PATAPIDISPATCHBAKUP)VirtualAlloc(0,sizeof(ATAPIDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (AtapiDispatchBakUp)
	{
		memset(AtapiDispatchBakUp,0,sizeof(ATAPIDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2);

		ReadFile((HANDLE)LIST_ATAPI_HOOK,AtapiDispatchBakUp,sizeof(ATAPIDISPATCHBAKUP)*IRP_MJ_MAXIMUM_FUNCTION*2,&dwReadByte,0);

		for (i=0;i< (int)AtapiDispatchBakUp->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",AtapiDispatchBakUp->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzNumber[256] = {0};
			WCHAR lpwzHookType[256] = {0};
			WCHAR lpwzFunction[256] = {0};
			WCHAR lpwzHookModuleImage[256] = {0};
			WCHAR lpwzCurrentAtapiDispatch[256] = {0};
			WCHAR lpwsAtapiDispatch[256] = {0};

			WCHAR lpwzHookModuleBase[256] = {0};
			WCHAR lpwzHookModuleSize[256] = {0};

			memset(lpwzNumber,0,sizeof(lpwzNumber));
			memset(lpwzHookType,0,sizeof(lpwzHookType));

			memset(lpwzFunction,0,sizeof(lpwzFunction));
			memset(lpwzHookModuleImage,0,sizeof(lpwzHookModuleImage));
			memset(lpwzCurrentAtapiDispatch,0,sizeof(lpwzCurrentAtapiDispatch));
			memset(lpwsAtapiDispatch,0,sizeof(lpwsAtapiDispatch));

			memset(lpwzHookModuleBase,0,sizeof(lpwzHookModuleBase));
			memset(lpwzHookModuleSize,0,sizeof(lpwzHookModuleSize));

			switch (AtapiDispatchBakUp->AtapiDispatch[i].Hooked)
			{
			case 0:
				StrCatW(lpwzHookType,L"-");
				break;
			case 1:
				StrCatW(lpwzHookType,L"A-tapi hook");
				break;
			case 2:
				StrCatW(lpwzHookType,L"A-tapi Inline hook");
				break;
			}

			wsprintfW(lpwzNumber,L"%d",AtapiDispatchBakUp->AtapiDispatch[i].ulNumber);

			//wsprintfW(lpwzHookModuleImage,L"%ws",AtapiDispatchBakUp->AtapiDispatch[i].lpszBaseModule);
			MultiByteToWideChar(
				CP_ACP,
				0, 
				AtapiDispatchBakUp->AtapiDispatch[i].lpszBaseModule,
				-1, 
				lpwzHookModuleImage, 
				strlen(AtapiDispatchBakUp->AtapiDispatch[i].lpszBaseModule)
				);
			wsprintfW(lpwzFunction,L"%ws",AtapiDispatchBakUp->AtapiDispatch[i].lpwzAtapiDispatchName);
			wsprintfW(lpwzCurrentAtapiDispatch,L"0x%08X",AtapiDispatchBakUp->AtapiDispatch[i].ulCurrentAtapiDispatch);
			wsprintfW(lpwsAtapiDispatch,L"0x%08X",AtapiDispatchBakUp->AtapiDispatch[i].ulAtapiDispatch);
			wsprintfW(lpwzHookModuleBase,L"0x%X",AtapiDispatchBakUp->AtapiDispatch[i].ulModuleBase);
			wsprintfW(lpwzHookModuleSize,L"0x%X",AtapiDispatchBakUp->AtapiDispatch[i].ulModuleSize);

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
				memcpy(lpwzDosFullPath,lpwzHookModuleImage+wcslen(L"\\??\\"),wcslen(lpwzHookModuleImage)-wcslen(L"\\??\\"));
				goto Next;
			}
			if (wcsstr(lpwzHookModuleImage,L"\\WINDOWS\\system32\\"))
			{
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat_s(lpwzDosFullPath,lpwzSysDisk);
				wcscat_s(lpwzDosFullPath,lpwzHookModuleImage);
				//MessageBoxW(lpwzDosFullPath,lpwzFullSysName,0);
				goto Next;
			}
			if (wcsstr(lpwzHookModuleImage,L"\\SystemRoot\\"))
			{
				WCHAR lpwzTemp[256];
				memset(lpwzTemp,0,sizeof(lpwzTemp));
				memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
				wcscat_s(lpwzTemp,lpwzSysDisk);
				wcscat_s(lpwzTemp,L"\\WINDOWS\\");
				wcscat_s(lpwzDosFullPath,lpwzTemp);
				memcpy(lpwzDosFullPath+wcslen(lpwzTemp),lpwzHookModuleImage+wcslen(L"\\SystemRoot\\"),wcslen(lpwzHookModuleImage) - wcslen(L"\\SystemRoot\\"));
				goto Next;
			}
			//if (wcslen(lpwzHookModuleImage) == wcslen(lpwzHookModuleImage))
			//{
			memset(lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
			wcscat_s(lpwzDosFullPath,lpwzSysDisk);
			wcscat_s(lpwzDosFullPath,L"\\WINDOWS\\system32\\drivers\\");
			wcscat_s(lpwzDosFullPath,lpwzHookModuleImage);
			goto Next;
			//}
Next:
			//������һ���������ݣ�����Ҫ���������
			if (bIsPhysicalCheck){
				//���û��hook���ͷ���
				if (AtapiDispatchBakUp->AtapiDispatch[i].Hooked == 0){
					continue;
				}
				WCHAR lpwzSaveBuffer[1024] ={0};
				CHAR lpszSaveBuffer[2024] ={0};
				memset(lpwzSaveBuffer,0,sizeof(lpwzSaveBuffer));
				memset(lpszSaveBuffer,0,sizeof(lpszSaveBuffer));

				wsprintfW(lpwzSaveBuffer,L"          --> ����Hook:ID:%ws | ��ǰ��ַ:%ws | ԭʼ��ַ:%ws | ������:%ws | �ں�ģ��:%ws | Hook����:%ws\r\n",
					lpwzNumber,lpwzCurrentAtapiDispatch,lpwsAtapiDispatch,lpwzFunction,lpwzDosFullPath,lpwzHookType);

				m_list->InsertItem(0,L"ATAPI.SYS",RGB(77,77,77));
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
			if (AtapiDispatchBakUp->AtapiDispatch[i].Hooked == 0)
			{
				m_list->InsertItem(i,lpwzNumber,RGB(77,77,77));

			}else
			{
				m_list->InsertItem(i,lpwzNumber,RGB(255,20,147));
			}
			m_list->SetItemText(i,1,lpwzFunction);
			m_list->SetItemText(i,2,lpwzCurrentAtapiDispatch);
			m_list->SetItemText(i,3,lpwsAtapiDispatch);
			m_list->SetItemText(i,4,lpwzDosFullPath);
			m_list->SetItemText(i,5,lpwzHookModuleBase);
			m_list->SetItemText(i,6,lpwzHookModuleSize);
			m_list->SetItemText(i,7,lpwzHookType);

			hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzDosFullPath,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
			AtapiImg.Add(shfileinfo.hIcon);
			m_list->SetImageList(&AtapiImg);
			m_list->SetItemImageId(i,i);
			DestroyIcon(shfileinfo.hIcon);
		}
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"A-tapi/Dispatchɨ����ϣ����� %d ������",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);
}
void AtapiHookResetOne(HWND m_hWnd,ULONG ID,CMyList *m_list)
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

	if (wcsstr(str,L"A-tapi") != NULL)
	{
		//ȡ���
		Num.Format(L"%s",m_list->GetItemText(Item,0));

		memset(lpszNum,0,sizeof(lpszNum));
		memset(lpwzNum,0,sizeof(lpwzNum));
		wcscat_s(lpwzNum,Num);
		WideCharToMultiByte (CP_OEMCP,NULL,lpwzNum,-1,lpszNum,wcslen(lpwzNum),NULL,FALSE);
		ReadFile((HANDLE)INIT_SET_ATAPI_HOOK,0,atoi(lpszNum),&dwReadByte,0);

		for (int i = 0;i< (int)AtapiDispatchBakUp->ulCount;i++)
		{
			if (atoi(lpszNum) == AtapiDispatchBakUp->AtapiDispatch[i].ulNumber)
			{
				ReadFile((HANDLE)SET_ATAPI_HOOK,0,AtapiDispatchBakUp->AtapiDispatch[i].ulAtapiDispatch,&dwReadByte,0);
				break;
			}
		}

		//ɾ����ǰѡ���һ��
		m_list->DeleteAllItems();
		QueryAtapiHook(m_hWnd,ID,m_list);
	}
}
void CopyAtapiDataToClipboard(HWND m_hWnd,CMyList *m_list)
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