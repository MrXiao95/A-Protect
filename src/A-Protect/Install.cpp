#include "stdafx.h"
#include "Install.h"
#include "Md5.h"

///-------------------------------------------------
extern unsigned int conv(unsigned int a);
extern VOID Uinstall2();
extern VOID Unistall1();
BOOL UnloadNTDriver(char * szSvrName)  ;
VOID GetFileMd5Hash(char *lpszDLLPath,char *lpszMd5)
{
	FILE * fp=fopen(lpszDLLPath,"rb");
	if(fp)
	{
		MD5VAL val;
		val = md5File(fp);
		wsprintfA(lpszMd5,"%08x%08x%08x%08x",conv(val.a),conv(val.b),conv(val.c),conv(val.d));
		fclose(fp);
	}
	return;
}
void RunAProcess(char *comline)
{
	STARTUPINFOA   si;   
	memset(&si,0 ,sizeof(LPSTARTUPINFOA));   
	si.cb   =   sizeof(   LPSTARTUPINFOA   );   
	si.dwFlags   =   STARTF_USESHOWWINDOW;   
	si.wShowWindow   =   SW_SHOW;   
	PROCESS_INFORMATION   pi;   
	CreateProcessA(NULL,comline,   NULL,   NULL,   FALSE,   CREATE_NO_WINDOW,   NULL,   NULL,   &si,   &pi);
	//WaitForSingleObject(pi.hProcess, 5*1000);  //�ȴ��ź�ִ�н���
	Sleep(3000);
	return;
}
BOOL VerifyEmbeddedSignature( LPCWSTR lpFileName )
{
	BOOL bRet = FALSE;
	WINTRUST_DATA wd = { 0 };
	WINTRUST_FILE_INFO wfi = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };
	CATALOG_INFO ci = { 0 };
	HCATADMIN hCatAdmin = NULL;
	if ( !CryptCATAdminAcquireContext( &hCatAdmin, NULL, 0 ) )
	{
		return FALSE;
	}

	HANDLE hFile = CreateFileW( lpFileName, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL );
	if ( INVALID_HANDLE_VALUE == hFile )
	{
		CryptCATAdminReleaseContext( hCatAdmin, 0 );
		return FALSE;
	}

	DWORD dwCnt = 100;
	BYTE byHash[100];
	CryptCATAdminCalcHashFromFileHandle( hFile, &dwCnt, byHash, 0 );
	CloseHandle( hFile );

	//LPWSTR pszMemberTag = new WCHAR[dwCnt * 2 + 1];
	//LPWSTR pszMemberTag = (WCHAR *)VirtualAlloc(0, dwCnt * 2 + 1,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	//�þ�̬�ڴ�~��
	WCHAR pszMemberTag[260] = {0};
	for ( DWORD dw = 0; dw < dwCnt; ++dw )
	{
		wsprintfW( &pszMemberTag[dw * 2], L"%02X", byHash[dw] );
	}

	HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash( hCatAdmin,
		byHash, dwCnt, 0, NULL );
	if ( NULL == hCatInfo )
	{
		wfi.cbStruct       = sizeof( WINTRUST_FILE_INFO );
		wfi.pcwszFilePath  = lpFileName;
		wfi.hFile          = NULL;
		wfi.pgKnownSubject = NULL;

		wd.cbStruct            = sizeof( WINTRUST_DATA );
		wd.dwUnionChoice       = WTD_CHOICE_FILE;
		wd.pFile               = &wfi;
		wd.dwUIChoice          = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wd.dwStateAction       = WTD_STATEACTION_IGNORE;
		wd.dwProvFlags         = WTD_SAFER_FLAG;
		wd.hWVTStateData       = NULL;
		wd.pwszURLReference    = NULL;
	}
	else
	{
		CryptCATCatalogInfoFromContext( hCatInfo, &ci, 0 );
		wci.cbStruct             = sizeof( WINTRUST_CATALOG_INFO );
		wci.pcwszCatalogFilePath = ci.wszCatalogFile;
		wci.pcwszMemberFilePath  = lpFileName;
		wci.pcwszMemberTag       = pszMemberTag;

		wd.cbStruct            = sizeof( WINTRUST_DATA );
		wd.dwUnionChoice       = WTD_CHOICE_CATALOG;
		wd.pCatalog            = &wci;
		wd.dwUIChoice          = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
		wd.dwProvFlags         = 0;
		wd.hWVTStateData       = NULL;
		wd.pwszURLReference    = NULL;
	}
	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	HRESULT hr  = WinVerifyTrust( NULL, &action, &wd );
	bRet        = SUCCEEDED( hr );

	//�ǵ�Ҫ�ͷŰ�������Ĳ�Ȼ�ڴ�쮵��ϸ���~��������
	if (hCatAdmin && hCatInfo)
		 CryptCATAdminReleaseCatalogContext(hCatAdmin,hCatInfo,0);

	if (hCatAdmin)
		CryptCATAdminReleaseContext( hCatAdmin, 0 );

	//delete[] pszMemberTag;
	//VirtualFree(pszMemberTag,dwCnt * 2 + 1,MEM_RESERVE | MEM_COMMIT);

	return bRet;
}
LPSTR ExtractFilePath(LPSTR lpcFullFileName)
{
	int iLen;
	char szBuffer[MAX_PATH];

	iLen = strlen(lpcFullFileName);
	if (iLen > MAX_PATH) return NULL;

	ZeroMemory(szBuffer, MAX_PATH);
	strcpy(szBuffer, lpcFullFileName);
	lpcFullFileName = szBuffer;
	*(char *)((int)strrchr(lpcFullFileName, '\\') + 1) = 0x00;
	return lpcFullFileName;
}
BOOL QueryUserAgent(HKEY HKey,char *lpSubKey,char *lpValueName,char *OutBuffer)
{
	HKEY hKey1;
	DWORD dwBufSize = 256;
	DWORD dwDataType = REG_EXPAND_SZ;
	unsigned char szQueryKey[256];

	if (RegOpenKeyExA(HKey,lpSubKey,NULL,KEY_QUERY_VALUE,&hKey1) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegQueryValueExA(hKey1,lpValueName,NULL,&dwDataType,szQueryKey,&dwBufSize);
	RegCloseKey(hKey1);
	wsprintfA(OutBuffer,"%s",(char *)szQueryKey);

	return TRUE;
}
BOOL PrintfDosPath(__in LPCTSTR lpwzNtFullPath,__out LPCTSTR lpwzDosFullPath)
{
	char cDrive = 'A';

	for (int i=0;i<26;i++)  
	{
		memset((WCHAR *)lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
		swprintf(
			(WCHAR*)lpwzDosFullPath,
			L"%c:%s",
			cDrive+i,
			lpwzNtFullPath
			);
		if (GetFileAttributesW((WCHAR *)lpwzDosFullPath) != INVALID_FILE_ATTRIBUTES)
		{
			return TRUE;
		}
	}
	memset((WCHAR *)lpwzDosFullPath,0,sizeof(lpwzDosFullPath));
	wcsncat((WCHAR *)lpwzDosFullPath,lpwzNtFullPath,wcslen(lpwzNtFullPath));
	return FALSE;
}
BOOL NtFilePathToDosFilePath(__in LPCTSTR lpwzNtFilePath,__out LPCTSTR lpwzDosFilePath)
{
	WCHAR lpwzDisk[10] = {0};
	WCHAR lpwzTemp[260] = {0};
	WCHAR lpwzNTDevice[260] = {0};
	char cDrive = 'A';

	//L"\\Device\\Harddisk\\WINDOWS\\system32\\drivers\\AProtect.sys"

	wcsncat(lpwzNTDevice,lpwzNtFilePath+wcslen(L"\\Device\\"),wcslen(lpwzNtFilePath)-wcslen(L"\\Device\\"));
	WCHAR *p = wcsstr(lpwzNTDevice,L"\\");
	if (!p)
	{
		wcsncat((WCHAR *)lpwzDosFilePath,lpwzNtFilePath,wcslen(lpwzNtFilePath));
		return FALSE;
	}
	swprintf_s(lpwzTemp,L"%ws",p);
	return PrintfDosPath(lpwzTemp,lpwzDosFilePath);
}
void SaveToFile(CHAR *lpszBuffer,WCHAR *lpwzFilePath)
{
	HANDLE	hFile = CreateFileW(lpwzFilePath, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwBytesWrite = 0;
	SetFilePointer(hFile, 0, 0, FILE_END);
	WriteFile(hFile,lpszBuffer,strlen(lpszBuffer), &dwBytesWrite, NULL);
	CloseHandle(hFile);
}
void SaveTitleFile(CHAR *lpszBuffer,WCHAR *lpwzFilePath)
{
	SaveToFile(lpszBuffer,lpwzFilePath);
}
BOOL IsWindows7()   
{   
	BOOL   bOsVersionInfoEx;   
	OSVERSIONINFOEX   osvi;   

	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));   
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);   
	if(!(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*)&osvi)))   
	{   
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);   
		if(!GetVersionEx((OSVERSIONINFO*)&osvi))     
			return   FALSE;   
	}
	if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1)
	{
		if (osvi.dwBuildNumber == 7000 ||osvi.dwBuildNumber >= 7600)
		{
			return TRUE;
		}
	}
	return FALSE;
}
CHAR* setClipboardText(CHAR* str)
{
	if(OpenClipboard(NULL)==FALSE)
		return NULL;
	if(EmptyClipboard()==FALSE)
	{
		CloseClipboard();
		return NULL;
	}
	int sz=strlen(str)+1;
	HANDLE hMem=GlobalAlloc(GMEM_MOVEABLE, sz);
	if(hMem==NULL)
	{
		CloseClipboard();
		return NULL;
	}
	CHAR *pMem=(CHAR*)GlobalLock(hMem);
	if(pMem==NULL)
	{
		GlobalFree(hMem);
		CloseClipboard();
		return NULL;
	}
	memcpy(pMem,str,sz);
	GlobalUnlock(hMem);
	if(SetClipboardData(CF_TEXT,hMem)==FALSE)
	{
		GlobalFree(hMem);
		CloseClipboard();
		return NULL;
	}
	CloseClipboard();
	return str;
}
BOOL WINAPI EnableDebugPriv(LPCTSTR name)//��Ȩ����
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	//�򿪽������ƻ�
	if(!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
		&hToken
		))
	{
		//  OpenProcessToken Error
		return FALSE;
	}
	//��ý��̱���ΨһID
	if(!LookupPrivilegeValue(NULL, name, &luid))
	{
		//  LookupPrivivlegeValue Error;
		return FALSE;
	}

	tp.PrivilegeCount=1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid=luid;

	//����Ȩ��  
	if(!AdjustTokenPrivileges(
		hToken, 
		0,
		&tp, 
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL
		))
	{
		// AdjustTokenPrivileges Error
		return FALSE;
	}

	return TRUE;
}
ULONG GetDLLFileSize(char *lpszDLLPath)
{
	ULONG ulFileSize = NULL;

	HANDLE hFile = CreateFileA(lpszDLLPath,     //�����ļ������ơ�
		GENERIC_READ,          // д�Ͷ��ļ���
		0,                      // �������д��
		NULL,                   // ȱʡ��ȫ���ԡ�
		OPEN_EXISTING,          // 
		FILE_ATTRIBUTE_NORMAL, // һ����ļ���       
		NULL);                 // ģ���ļ�Ϊ�ա�

	if (hFile != INVALID_HANDLE_VALUE) 
	{
		ulFileSize = GetFileSize(hFile,NULL);
		ulFileSize = ulFileSize/1024;
		CloseHandle(hFile);
	}
	return ulFileSize;
}
void ShutdownWindows( DWORD dwReason )
{
	EnableDebugPriv(SE_SHUTDOWN_NAME);
	ExitWindowsEx(dwReason, 0);
	EnableDebugPriv(SE_SHUTDOWN_NAME);	
}
DWORD InstallByZwLoadDriver(LPSTR Path,LPSTR lpszServiceName)
{
	DWORD Status, Ret=1, Value=SERVICE_KERNEL_DRIVER;
	UNICODE_STRING usKey;
	HKEY hk;
	char lpszSrvForMat[MAX_PATH] = {0};
	WCHAR lpwzServiceName[MAX_PATH] = {0};
	WCHAR lpwzLoadDriverForMat[MAX_PATH] = {0};

	sprintf(lpszSrvForMat,
		"SYSTEM\\CurrentControlSet\\Services\\%s",
		lpszServiceName);

	if(RegCreateKeyExA(HKEY_LOCAL_MACHINE, 
		lpszSrvForMat, 
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&hk,
		NULL)!=ERROR_SUCCESS)
	{
		printf("Error with RegCreateKeyEx : %d\n", GetLastError());
		Ret=0;
		goto cleanup;
	}

	if(RegSetValueExA(
		hk, 
		"Type", 
		0, 
		REG_DWORD, 
		(LPBYTE)&Value,
		sizeof(DWORD))!=ERROR_SUCCESS)
	{
		printf("Error with RegSetValueEx : %d\n", GetLastError());
		Ret=0;
		goto cleanup;
	}		

	/*
	If dwType is the REG_SZ, REG_MULTI_SZ, or REG_EXPAND_SZ type and the ANSI version of this function is used 
	(either by explicitly calling RegSetValueExA or by not defining UNICODE before including the Windows.h file),
	the data pointed to by the lpData parameter must be an ANSI character string. 
	The string is converted to Unicode before it is stored in the registry
	*/

	if(RegSetValueExA(hk, "ImagePath", 0, REG_EXPAND_SZ, (const PBYTE)Path, lstrlenA(Path))!=ERROR_SUCCESS)
	{
		printf("Error with RegSetValueEx : %d\n", GetLastError());
		Ret=0;
		goto cleanup;
	}

	Value=SERVICE_DEMAND_START;

	if(RegSetValueExA(hk, "Start", 0, REG_DWORD, (LPBYTE)&Value, sizeof(DWORD))!=ERROR_SUCCESS)
	{
		printf("Error with RegSetValueEx : %d\n", GetLastError());
		Ret=0;
		goto cleanup;
	}
	MultiByteToWideChar (CP_ACP,
		0, 
		lpszServiceName, 
		-1, 
		lpwzServiceName, 
		strlen(lpszServiceName)
		);
	wcscat(lpwzLoadDriverForMat,L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	wcscat(lpwzLoadDriverForMat,lpwzServiceName);

	RtlInitUnicodeString(&usKey,lpwzLoadDriverForMat);

	Status=NtLoadDriver(&usKey);
	if(Status!=STATUS_SUCCESS)
	{	
		//printf("Error with NtLoadDriver : 0x%x : %d \n", Status, RtlNtStatusToDosError(Status));
		Ret=0;
	}

cleanup:

	RegCloseKey(hk); 

	return Ret; 
}
BOOL BFS_WriteFile(char *targetPath,unsigned char *lpszCode,ULONG ulSize)
{
	DWORD dwBytesWrite1;
	HANDLE	hFile = CreateFileA(targetPath, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	SetFilePointer(hFile, 0, 0, FILE_END);
	WriteFile(hFile,lpszCode,ulSize, &dwBytesWrite1, NULL);  //д��β
	CloseHandle(hFile);
	return TRUE;
}
BOOL Install(HWND hwndDlg)
{
	DWORD dwReadByte;
	int i=0;
	char lpszInit[8] = {0};
	char lpszWindowsPath[256] = {0};
	char lpszNumber[256] = {0};
	char lpszLoadDriverPath[256] = {0};
	memset(lpszInit,0,sizeof(lpszInit));
	strcat(lpszInit,"Safe");
	ReadFile((HANDLE)SAFE_SYSTEM,lpszInit,8,&dwReadByte,0);
	if (StrCmpIA("hehe",lpszInit) == NULL)
	{
		goto InitSuccess;
	}
	if (StrCmpIA("call",lpszInit) == NULL)
	{
		if (MessageBoxA(hwndDlg,"�ܾ�����\r\n\r\nԭ���޷���֤��ǰA���ļ��������ԡ��ļ��п��ܱ��޸ġ���Ⱦ������������������\r\n\r\n�Ƿ�ǰ���ٷ��������°棿","��A�ܵ��Է�����",MB_ICONERROR | MB_YESNO) == IDYES)
		{
			ShellExecuteW(0,0,L"http://www.3600safe.com/",0,0,SW_SHOW);
		}
		Uinstall2();
		Unistall1();
		ExitProcess(0);
	}
	char lpszAProtectRunKey[100] = {0};
	memset(lpszAProtectRunKey,0,sizeof(lpszAProtectRunKey));
	QueryUserAgent(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","A-Protect",lpszAProtectRunKey);
	if (strstr(lpszAProtectRunKey,"\\") != 0)
	{
		MessageBoxA(hwndDlg,"��A�ܵ��Է�������ʼ��ʧ�ܣ�\r\n\r\n1:������ֹ�ˡ�A�ܵ��Է�����������\r\n2:ĳЩ��ȫ����ָ�����ֹ��A�ܵ��Է������Ĺ���\r\n3:��ĳЩɱ�����߰�ȫ��������ݵ��¡�A�ܵ��Է������ĳ�ʼ��ʧ��\r\n4:��ȷ�������ȷ���ɨ��ʧ�ܣ��������������Լ��ɡ�","��A�ܵ��Է�����",MB_ICONERROR);
		Unistall1();
		Uinstall2();
		ExitProcess(0);
	}
	GetWindowsDirectoryA(lpszWindowsPath,sizeof(lpszWindowsPath));
	sprintf(lpszNumber,"%s","A-Protect");
	char lpszSrvices[256] = {0};
	sprintf(lpszSrvices,"SYSTEM\\CurrentControlSet\\Services\\%s",lpszNumber);
	SHDeleteKeyA(HKEY_LOCAL_MACHINE,lpszSrvices);
	strcat(lpszWindowsPath,"\\");
	strcat(lpszWindowsPath,lpszNumber);
	strcat(lpszWindowsPath,".sys");
	BFS_WriteFile(lpszWindowsPath,lpszKernelModule,sizeof(lpszKernelModule));
	if (GetFileAttributesA(lpszWindowsPath) == INVALID_FILE_ATTRIBUTES)
	{
		if (IsWindows7())
			MessageBoxA(hwndDlg,"�ͷ������ļ�ʧ�ܣ�win7ϵͳ���Ҽ����Թ���Ա������С�","��A�ܵ��Է�����",MB_ICONERROR);
		else
			MessageBoxA(hwndDlg,"�ͷ������ļ�ʧ��","��A�ܵ��Է�����",MB_ICONERROR);
		Uinstall2();
		Unistall1();
		ExitProcess(0);
	}
	wsprintfA(lpszLoadDriverPath,"\\??\\%s",lpszWindowsPath);
	if(!EnableDebugPriv(SE_LOAD_DRIVER_NAME))
	{
		DeleteFileA(lpszWindowsPath);
		MessageBoxA(hwndDlg,"û���㹻��Ȩ�޼���������","��A�ܵ��Է�����",MB_ICONERROR);
		Unistall1();
		Uinstall2();
		ExitProcess(0);
	}
	if (!LoadNTDriver(lpszNumber,lpszWindowsPath))
	{
		DeleteFileA(lpszWindowsPath);
		SHDeleteKeyA(HKEY_LOCAL_MACHINE,lpszSrvices);
		MessageBoxA(hwndDlg,"��������ʧ�ܣ�","��A�ܵ��Է�����",MB_ICONERROR);
		Unistall1();
		Uinstall2();
		ExitProcess(0);
	}
	DeleteFileA(lpszWindowsPath);
	SHDeleteKeyA(HKEY_LOCAL_MACHINE,lpszSrvices);
	i = 0;
Last:
	Sleep(3000);
	memset(lpszInit,0,sizeof(lpszInit));
	strcat(lpszInit,"Safe");
	ReadFile((HANDLE)SAFE_SYSTEM,lpszInit,8,&dwReadByte,0);
	if (StrCmpIA("hehe",lpszInit) != NULL)
	{
		if (StrCmpIA("call",lpszInit) == NULL)
		{
			if (MessageBoxA(hwndDlg,"�ܾ�����\r\n\r\nԭ���޷���֤��ǰA���ļ��������ԡ��ļ��п��ܱ��޸ġ���Ⱦ������������������\r\n\r\n�Ƿ�ǰ���ٷ��������°棿","��A�ܵ��Է�����",MB_ICONERROR | MB_YESNO) == IDYES)
			{
				ShellExecuteW(0,0,L"http://www.3600safe.com/",0,0,SW_SHOW);
			}
			Unistall1();
			Uinstall2();
			ExitProcess(0);
		}
		i++;
		if (i>5)
		{
			MessageBoxA(hwndDlg,"��A�ܵ��Է�������ʼ��ʧ�ܣ��п�������ԭ���£�\r\n\r\n1:������ֹ�ˡ�A�ܵ��Է�����������\r\n2:ĳЩ��ȫ����ָ�����ֹ��A�ܵ��Է������Ĺ���\r\n3:��ĳЩɱ�����߰�ȫ��������ݵ��¡�A�ܵ��Է������ĳ�ʼ��ʧ��\r\n4:��ȷ�������ȷ���ɨ��ʧ�ܣ��������������Լ��ɡ�","��A�ܵ��Է�����",MB_ICONERROR);
			SHDeleteKeyA(HKEY_LOCAL_MACHINE,lpszSrvices);
			DeleteFileA(lpszWindowsPath);
			Unistall1();
			Uinstall2();
			ExitProcess(0);
		}
		goto Last;
	}
InitSuccess:
	return TRUE;
}
VOID Unistall1()
{
	char pBuf1[MAX_PATH];
	char pBuf2[MAX_PATH]; 
	char pBuf3[MAX_PATH]; 
	memset(pBuf1,0,sizeof(pBuf1));
	memset(pBuf2,0,sizeof(pBuf2));
	memset(pBuf3,0,sizeof(pBuf3));
	GetCurrentDirectoryA(MAX_PATH,(LPSTR)pBuf1); 
	GetCurrentDirectoryA(MAX_PATH,(LPSTR)pBuf2);
	GetCurrentDirectoryA(MAX_PATH,(LPSTR)pBuf3);
	strcat(pBuf1,"\\dbghelp.dll");
	strcat(pBuf2,"\\symsrv.dll");
	strcat(pBuf3,"\\symsrv.yes");
	DeleteFileA(pBuf1);
	DeleteFileA(pBuf2);
	DeleteFileA(pBuf3);
}
VOID Uinstall2()
{
	DWORD dwReadByte;
	WCHAR pBuf1[MAX_PATH];
	WCHAR pBuf2[MAX_PATH]; 
	WCHAR pBuf3[MAX_PATH];
	WCHAR pBuf4[MAX_PATH];
	WCHAR lpwzDeletedFile1[MAX_PATH];
	WCHAR lpwzDeletedFile2[MAX_PATH];
	WCHAR lpwzDeletedFile3[MAX_PATH];
	WCHAR lpwzDeletedFile4[MAX_PATH];
	memset(pBuf1,0,sizeof(pBuf1));
	memset(pBuf2,0,sizeof(pBuf2));
	memset(pBuf3,0,sizeof(pBuf3));
	memset(pBuf4,0,sizeof(pBuf4));
	GetCurrentDirectoryW(MAX_PATH,pBuf1); 
	GetCurrentDirectoryW(MAX_PATH,pBuf2);
	GetCurrentDirectoryW(MAX_PATH,pBuf3);
	GetCurrentDirectoryW(MAX_PATH,pBuf4);
	wcscat(pBuf1,L"\\dbghelp.dll");
	wcscat(pBuf2,L"\\symsrv.dll");
	wcscat(pBuf3,L"\\symsrv.yes");
	wcscat(pBuf4,L"\\A-Protect.apt");
	memset(lpwzDeletedFile1,0,sizeof(lpwzDeletedFile1));
	memset(lpwzDeletedFile2,0,sizeof(lpwzDeletedFile2));
	memset(lpwzDeletedFile3,0,sizeof(lpwzDeletedFile3));
	memset(lpwzDeletedFile4,0,sizeof(lpwzDeletedFile4));
	wsprintfW(lpwzDeletedFile1,L"\\??\\%ws",pBuf1);
	wsprintfW(lpwzDeletedFile2,L"\\??\\%ws",pBuf2);
	wsprintfW(lpwzDeletedFile3,L"\\??\\%ws",pBuf3);
	wsprintfW(lpwzDeletedFile4,L"\\??\\%ws",pBuf4);
//	MessageBoxW(0,(LPCWSTR)lpwzDeletedFile4,(LPCWSTR)(L""),0);
	ReadFile((HANDLE)KERNEL_SAFE_MODULE,0,0,&dwReadByte,0);//�����ں˰�ȫģʽ����ֹ�ļ�hook
	ReadFile((HANDLE)DELETE_FILE,lpwzDeletedFile1,wcslen(lpwzDeletedFile1),&dwReadByte,0); //ɾ���ļ�
	ReadFile((HANDLE)DELETE_FILE,lpwzDeletedFile2,wcslen(lpwzDeletedFile2),&dwReadByte,0); //ɾ���ļ�
	ReadFile((HANDLE)DELETE_FILE,lpwzDeletedFile3,wcslen(lpwzDeletedFile3),&dwReadByte,0); //ɾ���ļ�
	ReadFile((HANDLE)DELETE_FILE,lpwzDeletedFile4,wcslen(lpwzDeletedFile4),&dwReadByte,0); //ɾ���ļ�
	ReadFile((HANDLE)NO_KERNEL_SAFE_MODULE,0,0,&dwReadByte,0); //�ر��ں˰�ȫģʽ
	ReadFile((HANDLE)EXIT_PROCESS,0,0,&dwReadByte,0); //�˳�����ǰ�����ں�
	//UnloadNTDriver("A-Protect"); //ж������
}
VOID Install2()
{
	char pBuf[MAX_PATH];
	memset(pBuf,0,sizeof(pBuf));
	GetCurrentDirectoryA(MAX_PATH,(LPSTR)pBuf); 
	strcat(pBuf,"\\dbghelp.dll");
	BFS_WriteFile(pBuf,lpszdbghelp,sizeof(lpszdbghelp));
	memset(pBuf,0,sizeof(pBuf));
	GetCurrentDirectoryA(MAX_PATH,(LPSTR)pBuf);
	strcat(pBuf,"\\symsrv.dll");
	BFS_WriteFile(pBuf,lpszsymsrv,sizeof(lpszsymsrv));
	memset(pBuf,0,sizeof(pBuf));
	GetCurrentDirectoryA(MAX_PATH,(LPSTR)pBuf);
	strcat(pBuf,"\\symsrv.yes");
	HANDLE hfile = CreateFileA (pBuf,FILE_ALL_ACCESS,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	CloseHandle (hfile);
}
/////////////////////////////////////////////
VOID CreateDepthSuccessKey(CHAR *KeyPath,CHAR *KeyName)
{
	HKEY regKey;
	LONG result;
	result =RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		KeyPath,
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		HKEY	subKey;
		if (SUCCEEDED(RegCreateKeyA(regKey,KeyName, &subKey)))
		{
			RegCloseKey(subKey);
		}
		RegCloseKey(regKey);
	}
}
BOOL InstallDepthServicesScan(CHAR * serviceName)
{
	BOOL	ret = FALSE;
	LONG	result;
	CHAR	sysDirPath[MAX_PATH];
	CHAR	targetPath[MAX_PATH];
	DWORD   dwBytesWrite;
	dwBytesWrite=0;
	GetSystemDirectoryA(sysDirPath, sizeof(sysDirPath));
	wsprintfA(targetPath, "%s\\Drivers\\%s.sys", sysDirPath, serviceName);
	if (GetFileAttributesA(targetPath) != INVALID_FILE_ATTRIBUTES)
	{
		return TRUE;
	}
	if (BFS_WriteFile(targetPath,lpszKernelModule,sizeof(lpszKernelModule)) == FALSE)
	{
		printf("create file failed\r\n");
		return FALSE;
	}
	if (GetFileAttributesA(targetPath) == INVALID_FILE_ATTRIBUTES)
	{
		MessageBoxW(0,L"�ͷ��ļ�ʧ�ܣ���ر�ɱ�����������ɾ\r\n",L"A�ܵ��Է���",MB_ICONWARNING);
		return FALSE;
	}
	HKEY regKey;
	result =RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Services",
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		HKEY	subKey;
		if (SUCCEEDED(RegCreateKeyA(regKey, serviceName, &subKey)))
		{
			DWORD	data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueExA(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, "ErrorControl", SERVICE_ERROR_NORMAL);
			SET_DWORD(subKey, "Start", SERVICE_BOOT_START);
			SET_DWORD(subKey, "Type", SERVICE_KERNEL_DRIVER);
			SET_DWORD(subKey, "Tag", 10);
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		RegCloseKey(regKey);
	}

	result =RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}",
		0,
		KEY_READ|KEY_WRITE,
		&regKey);

	if (SUCCEEDED(result))
	{
		CHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;

		memset( buff, 0, sizeof(buff));

		RegQueryValueExA( regKey,
			"UpperFilters",
			0,
			&type,
			(LPBYTE)buff, 
			&retLen);

		BOOL	alreadyExists = FALSE;
		CHAR * ptr = NULL;
		for (ptr = buff; *ptr; ptr += lstrlenA(ptr) + 1)
		{
			if(lstrcmpiA(ptr, serviceName) == 0)
			{
				alreadyExists = TRUE;
				break;
			}
		}
		if (!alreadyExists)
		{
			DWORD	added = lstrlenA(serviceName);
			memcpy(ptr, serviceName, added * sizeof(CHAR));

			ptr += added;

			*ptr = '\0';
			*(ptr+1) = '\0';

			result = RegSetValueExA(regKey, "UpperFilters", 0, REG_MULTI_SZ, (LPBYTE)buff, retLen + ((added + 1) * sizeof(CHAR)));
		}

		ret = TRUE;

		RegCloseKey(regKey);
	}

	return ret;
}
BOOL UninstallDepthServicesScan(CHAR * serviceName)
{
	BOOL	ret = FALSE;

	CHAR	sysDirPath[MAX_PATH];
	CHAR	targetPath[MAX_PATH];

	GetSystemDirectoryA(sysDirPath, sizeof(sysDirPath));
	wsprintfA(targetPath, "%s\\Drivers\\%s.sys", sysDirPath, serviceName);

	DeleteFileA(targetPath);

	HKEY regKey;
	LONG result;
	result =RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Services",
		0,
		KEY_READ|KEY_WRITE,
		&regKey);
	if( ERROR_SUCCESS == result )
	{
		SHDeleteKeyA(regKey, serviceName);
		// һ��Ҫflush,���򲻱���
		RegFlushKey(regKey);
	}

	result =RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}",
		0,
		KEY_READ|KEY_WRITE,
		&regKey);

	if( ERROR_SUCCESS == result )
	{
		CHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;

		memset( buff, 0, sizeof(buff));

		RegQueryValueExA( regKey,
			"UpperFilters",
			0,
			&type,
			(LPBYTE)buff, 
			&retLen);

		BOOL	alreadyExists = FALSE;
		for (CHAR * ptr = buff; *ptr; ptr += lstrlenA(ptr) + 1)
		{
			if(lstrcmpiA(ptr, serviceName) == 0)
			{
				DWORD	removeLength = (lstrlenA(ptr) + 1) * sizeof(CHAR);
				memmove(ptr, (char *)ptr + removeLength, ((char *)ptr + removeLength - (char *)buff) *  sizeof(CHAR));

				result = RegSetValueExA(regKey,"UpperFilters", 0, REG_MULTI_SZ, (LPBYTE)buff, retLen - removeLength);
				break;
			}
		}

		ret = TRUE;
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}
	return ret;
}
BOOL LoadNTDriver(char* lpszDriverName,char* lpszDriverPath)
{
	char szDriverImagePath[256];
	//�õ�����������·��
	GetFullPathNameA(lpszDriverPath, 256, szDriverImagePath, NULL);

	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr=NULL;//SCM�������ľ��
	SC_HANDLE hServiceDDK=NULL;//NT��������ķ�����

	//�򿪷�����ƹ�����
	hServiceMgr = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );

	if( hServiceMgr == NULL )  
	{
		//OpenSCManagerʧ��
		printf( "OpenSCManager() Faild %d ! \n", GetLastError() );
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager�ɹ�
		printf( "OpenSCManager() ok ! \n" );  
	}

	//������������Ӧ�ķ���
	hServiceDDK = CreateServiceA( hServiceMgr,
		lpszDriverName, //�����������ע����е�����  
		lpszDriverName, // ע������������ DisplayName ֵ  
		SERVICE_ALL_ACCESS, // ������������ķ���Ȩ��  
		SERVICE_KERNEL_DRIVER,// ��ʾ���صķ�������������  
		SERVICE_DEMAND_START, // ע������������ Start ֵ  
		SERVICE_ERROR_IGNORE, // ע������������ ErrorControl ֵ  
		szDriverImagePath, // ע������������ ImagePath ֵ  
		NULL,  
		NULL,  
		NULL,  
		NULL,  
		NULL);  

	DWORD dwRtn;
	//�жϷ����Ƿ�ʧ��
	if( hServiceDDK == NULL )  
	{  
		dwRtn = GetLastError();
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS )  
		{  
			//��������ԭ�򴴽�����ʧ��
			printf( "CrateService() Faild %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{
			//���񴴽�ʧ�ܣ������ڷ����Ѿ�������
			printf( "CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n" );  
		}

		// ���������Ѿ����أ�ֻ��Ҫ��  
		hServiceDDK = OpenServiceA( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );  
		if( hServiceDDK == NULL )  
		{
			//����򿪷���Ҳʧ�ܣ�����ζ����
			dwRtn = GetLastError();  
			printf( "OpenService() Faild %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else
		{
			printf( "OpenService() ok ! \n" );
		}
	}  
	else  
	{
		printf( "CrateService() ok ! \n" );
	}

	//�����������
	bRet= StartServiceA( hServiceDDK, NULL, NULL );  
	if( !bRet )  
	{  
		DWORD dwRtn = GetLastError();  
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING )  
		{  
			printf( "StartService() Faild %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{  
			if( dwRtn == ERROR_IO_PENDING )  
			{  
				//�豸����ס
				printf( "StartService() Faild ERROR_IO_PENDING ! \n");
				bRet = FALSE;
				goto BeforeLeave;
			}  
			else  
			{  
				//�����Ѿ�����
				printf( "StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
				bRet = TRUE;
				goto BeforeLeave;
			}  
		}  
	}
	bRet = TRUE;
	//�뿪ǰ�رվ��
BeforeLeave:
	if(hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if(hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	//ɾ��ע����ֵ
	char lpszSrvices[256] = {0};
	sprintf(lpszSrvices,"SYSTEM\\CurrentControlSet\\Services\\%s",lpszDriverName);
	SHDeleteKeyA(HKEY_LOCAL_MACHINE,lpszSrvices);

	return bRet;
}
//ж����������     
BOOL UnloadNTDriver(char * szSvrName)     
{   
	BOOL bRet = FALSE;   
	SC_HANDLE hServiceMgr=NULL;//SCM�������ľ��   
	SC_HANDLE hServiceDDK=NULL;//NT��������ķ�����   
	SERVICE_STATUS SvrSta;   
	//��SCM������   
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );     
	if( hServiceMgr == NULL )     
	{   
		//����SCM������ʧ��   
		printf( "OpenSCManager() Faild %d ! \n", GetLastError() );     
		bRet = FALSE;   
		goto BeforeLeave;   
	}     
	else     
	{   
		//����SCM������ʧ�ܳɹ�   
		printf( "OpenSCManager() ok ! \n" );     
	}   
	//����������Ӧ�ķ���   
	hServiceDDK = OpenServiceA( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );     

	if( hServiceDDK == NULL )     
	{   
		//����������Ӧ�ķ���ʧ��   
		printf( "OpenService() Faild %d ! \n", GetLastError() );     
		bRet = FALSE;   
		goto BeforeLeave;   
	}     
	else     
	{     
		printf( "OpenService() ok ! \n" );     
	}     
	//ֹͣ�����������ֹͣʧ�ܣ�ֻ�������������ܣ��ٶ�̬���ء�     
	if( !ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) )     
	{     
		printf( "ControlService() Faild %d !\n", GetLastError() );     
	}     
	else     
	{   
		//����������Ӧ��ʧ��   
		printf( "ControlService() ok !\n" );     
	}     
	//��̬ж����������     
	if( !DeleteService( hServiceDDK ) )     
	{   
		//ж��ʧ��   
		printf( "DeleteSrevice() Faild %d !\n", GetLastError() );     
	}     
	else     
	{     
		//ж�سɹ�   
		printf( "DelServer:eleteSrevice() ok !\n" );     
	}     
	bRet = TRUE;   
BeforeLeave:   
	//�뿪ǰ�رմ򿪵ľ��   
	if(hServiceDDK)   
	{   
		CloseServiceHandle(hServiceDDK);   
	}   
	if(hServiceMgr)   
	{   
		CloseServiceHandle(hServiceMgr);   
	}   
	return bRet;       
}    