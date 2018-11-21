#include "stdafx.h"
#include "ShadowSSDT.h"
#include "A-ProtectView.h"
#include "A-Protect.h"

VOID QueryShadowSSDTHook(HWND m_hWnd,ULONG ID,int IntType,CMyList *m_list)
{
	DWORD dwReadByte;
	int i=0;
	int ItemNum = m_list->GetItemCount();

	SHFILEINFO shfileinfo;
	ShadowSSDTImg.Create(16,16, ILC_COLOR32, 2, 100);
	HIMAGELIST hImageList = NULL;
	CMyAProtectApp *imgApp=(CMyAProtectApp*)AfxGetApp();

	if (bIsPhysicalCheck){
		SaveToFile("\r\n\r\n[---ShadowSSDT---]\r\n",PhysicalFile);
	}
	SetDlgItemTextW(m_hWnd,ID,L"����ɨ��ShadowSSDT�����Ժ�...");

	ShadowSSDTInfo = (PSHADOWSSDTINFO)VirtualAlloc(0, sizeof(SHADOWSSDTINFO)*910,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (ShadowSSDTInfo)
	{
		memset(ShadowSSDTInfo,0,sizeof(SHADOWSSDTINFO)*910);
		if (IntType == 0)
		{
			ReadFile((HANDLE)LIST_SHADOWSSDT,ShadowSSDTInfo,sizeof(SHADOWSSDTINFO)*910,&dwReadByte,0);
		}else
			ReadFile((HANDLE)LIST_SHADOWSSDT_ALL,ShadowSSDTInfo,sizeof(SHADOWSSDTINFO)*910,&dwReadByte,0);

		for ( i=0;i< (int)ShadowSSDTInfo->ulCount;i++)
		{
			WCHAR lpwzTextOut[100];
			memset(lpwzTextOut,0,sizeof(lpwzTextOut));
			wsprintfW(lpwzTextOut,L"���� %d �����ݣ�����ɨ��� %d �������Ժ�...",ShadowSSDTInfo->ulCount,i);
			SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

			WCHAR lpwzNumber[256] = {0};
			WCHAR lpwzHookType[256] = {0};
			WCHAR lpwzFunction[256] = {0};
			WCHAR lpwzHookModuleImage[256] = {0};
			WCHAR lpwzMemoryFunctionBase[256] = {0};
			WCHAR lpwzRealFunctionBase[256] = {0};
			WCHAR lpwzHookModuleBase[256] = {0};
			WCHAR lpwzHookModuleSize[256] = {0};

			memset(lpwzNumber,0,sizeof(lpwzNumber));
			memset(lpwzHookType,0,sizeof(lpwzHookType));

			memset(lpwzFunction,0,sizeof(lpwzFunction));
			memset(lpwzHookModuleImage,0,sizeof(lpwzHookModuleImage));
			memset(lpwzMemoryFunctionBase,0,sizeof(lpwzMemoryFunctionBase));
			memset(lpwzRealFunctionBase,0,sizeof(lpwzRealFunctionBase));
			memset(lpwzHookModuleBase,0,sizeof(lpwzHookModuleBase));
			memset(lpwzHookModuleSize,0,sizeof(lpwzHookModuleSize));

			if (ShadowSSDTInfo->SSDT[i].ulNumber == 0xffffffff)
			{
				StrCatW(lpwzNumber,L"*");
			}
			else
				wsprintfW(lpwzNumber,L"%d",ShadowSSDTInfo->SSDT[i].ulNumber);

			MultiByteToWideChar(
				CP_ACP,
				0, 
				ShadowSSDTInfo->SSDT[i].lpszFunction,
				-1, 
				lpwzFunction, 
				strlen(ShadowSSDTInfo->SSDT[i].lpszFunction)
				);
			MultiByteToWideChar(
				CP_ACP,
				0, 
				ShadowSSDTInfo->SSDT[i].lpszHookModuleImage,
				-1, 
				lpwzHookModuleImage, 
				strlen(ShadowSSDTInfo->SSDT[i].lpszHookModuleImage)
				);
			//wsprintfW(lpwzFunction,L"%s",SSDTInfo->SSDT[i].lpszFunction);
			//wsprintfW(lpwzHookModuleImage,L"%s",SSDTInfo->SSDT[i].lpszHookModuleImage);

			wsprintfW(lpwzMemoryFunctionBase,L"0x%08X",ShadowSSDTInfo->SSDT[i].ulMemoryFunctionBase);
			wsprintfW(lpwzRealFunctionBase,L"0x%08X",ShadowSSDTInfo->SSDT[i].ulRealFunctionBase);
			wsprintfW(lpwzHookModuleBase,L"0x%08X",ShadowSSDTInfo->SSDT[i].ulHookModuleBase);
			wsprintfW(lpwzHookModuleSize,L"%d KB",ShadowSSDTInfo->SSDT[i].ulHookModuleSize/1024);

			switch (ShadowSSDTInfo->SSDT[i].IntHookType)
			{
			case 0:
				StrCatW(lpwzHookType,L"-");
				break;
			case 1:
				StrCatW(lpwzHookType,L"ShadowSSDT hook");
				break;
			case 2:
				StrCatW(lpwzHookType,L"ShadowSSDT Inline hook");
				break;
			case 3:
				StrCatW(lpwzHookType,L"Inline hook");
				break;
			}
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
Next:
			//������һ���������ݣ�����Ҫ���������
			if (bIsPhysicalCheck){
				//���û��hook���ͷ���
				if (ShadowSSDTInfo->SSDT[i].IntHookType == 0){
					continue;
				}
				WCHAR lpwzSaveBuffer[1024] ={0};
				CHAR lpszSaveBuffer[2024] ={0};
				memset(lpwzSaveBuffer,0,sizeof(lpwzSaveBuffer));
				memset(lpszSaveBuffer,0,sizeof(lpszSaveBuffer));

				wsprintfW(lpwzSaveBuffer,L"          --> ����Hook:ID:%ws | ��ǰ��ַ:%ws | ԭʼ��ַ:%ws | ������:%ws | �ں�ģ��:%ws | Hook����:%ws\r\n",
					lpwzNumber,lpwzMemoryFunctionBase,lpwzRealFunctionBase,lpwzFunction,lpwzDosFullPath,lpwzHookType);

				m_list->InsertItem(0,L"ShadowSSDT",RGB(77,77,77));
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
			if (ShadowSSDTInfo->SSDT[i].IntHookType == 0)
			{
				m_list->InsertItem(i,lpwzNumber,RGB(77,77,77));

			}else
			{
				m_list->InsertItem(i,lpwzNumber,RGB(255,20,147));
			}
			m_list->SetItemText(i,1,lpwzMemoryFunctionBase);
			m_list->SetItemText(i,2,lpwzRealFunctionBase);
			m_list->SetItemText(i,3,lpwzFunction);
			m_list->SetItemText(i,4,lpwzDosFullPath);
			m_list->SetItemText(i,5,lpwzHookModuleBase);
			m_list->SetItemText(i,6,lpwzHookModuleSize);
			m_list->SetItemText(i,7,lpwzHookType);

			if(GetFileAttributes(lpwzDosFullPath)!=INVALID_FILE_ATTRIBUTES)
			{
				hImageList=(HIMAGELIST)::SHGetFileInfo(lpwzDosFullPath,0,&shfileinfo,sizeof(shfileinfo),SHGFI_ICON);
				ShadowSSDTImg.Add(shfileinfo.hIcon);
			}else
				ShadowSSDTImg.Add(imgApp->LoadIconW(IDI_WHITE));
			m_list->SetImageList(&ShadowSSDTImg);
			m_list->SetItemImageId(i,i);
			DestroyIcon(shfileinfo.hIcon);
		}
		VirtualFree(ShadowSSDTInfo,sizeof(SHADOWSSDTINFO)*910,MEM_RESERVE | MEM_COMMIT);
	}
	WCHAR lpwzTextOut[100];
	memset(lpwzTextOut,0,sizeof(lpwzTextOut));
	wsprintfW(lpwzTextOut,L"ShadowSSDTɨ����ϣ����� %d ������.",i);
	SetDlgItemTextW(m_hWnd,ID,lpwzTextOut);

}
VOID UnHookShadowSSDT(HWND m_hWnd,CMyList *m_list)
{
	DWORD dwReadByte;
	CString str;
	CString Num;

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

	if (wcsstr(str,L"Inline") != NULL)
	{
		//ȡ�����
		Num.Format(L"%s",m_list->GetItemText(Item,0));

		memset(lpszNum,0,sizeof(lpszNum));
		memset(lpwzNum,0,sizeof(lpwzNum));
		wcscat_s(lpwzNum,Num);

		WideCharToMultiByte (CP_OEMCP,NULL,lpwzNum,-1,lpszNum,wcslen(lpwzNum),NULL,FALSE);

		ReadFile((HANDLE)SET_SHADOWSSDT_INLINE_HOOK,0,atoi(lpszNum),&dwReadByte,0);

		//ɾ����ǰѡ���һ��
		m_list->DeleteAllItems();
		QueryShadowSSDTHook(m_hWnd,IDC_DebugStatus,0,m_list);
	}
	if (wcsstr(str,L"SSDT") != NULL)
	{
		//ȡ�����
		Num.Format(L"%s",m_list->GetItemText(Item,0));

		memset(lpszNum,0,sizeof(lpszNum));
		memset(lpwzNum,0,sizeof(lpwzNum));
		wcscat_s(lpwzNum,Num);

		WideCharToMultiByte (CP_OEMCP,NULL,lpwzNum,-1,lpszNum,wcslen(lpwzNum),NULL,FALSE);

		//MessageBoxA(0,lpszNum,0,0);
		ReadFile((HANDLE)SET_ONE_SHADOWSSDT,0,atoi(lpszNum),&dwReadByte,0);

		//ɾ����ǰѡ���һ��
		m_list->DeleteAllItems();
		QueryShadowSSDTHook(m_hWnd,IDC_DebugStatus,0,m_list);
	}

}
VOID UnHookShadowSSDTAll(HWND m_hWnd,CMyList *m_list)
{
	DWORD dwReadByte;

	m_list->DeleteAllItems();

	ReadFile((HANDLE)SET_ALL_SHADOWSSDT,0,0,&dwReadByte,0);

	QueryShadowSSDTHook(m_hWnd,IDC_DebugStatus,0,m_list);
}
void CopyShadowSSDTDataToClipboard(HWND hWnd,CMyList *m_list)
{
	CString FunctionName;
	int ItemNum = m_list->GetItemCount();
	POSITION pos = m_list->GetFirstSelectedItemPosition(); //�ж��б�����Ƿ���ѡ����
	int Item = m_list->GetNextSelectedItem(pos); //���б��б�ѡ�����һ������ֵ���浽������

	FunctionName.Format(L"%s",m_list->GetItemText(Item,3));

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
		MessageBoxW(hWnd,L"�����ɹ���",L"A�ܵ��Է���",MB_ICONWARNING);
	}
}