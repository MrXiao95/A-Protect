#include "InitWindowsVersion.h"

 WIN_VER_DETAIL GetWindowsVersion()
{
	RTL_OSVERSIONINFOEXW	osverinfo;

	if (g_WinVersion)
		return g_WinVersion;

	
	memset(&osverinfo,0,sizeof(RTL_OSVERSIONINFOEXW));
	osverinfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW); 
	if (RtlGetVersion((RTL_OSVERSIONINFOW*)&osverinfo) != STATUS_SUCCESS){
		return WINDOWS_VERSION_NONE;
	}

// 	KdPrint(("[xxxxxxxx] OSVersion NT %d.%d:%d sp%d.%d\n", 
// 		osverinfo.dwMajorVersion, osverinfo.dwMinorVersion, osverinfo.dwBuildNumber, 
// 		osverinfo.wServicePackMajor, osverinfo.wServicePackMinor));

	if (osverinfo.dwMajorVersion == 5 && osverinfo.dwMinorVersion == 0){
		g_WinVersion = WINDOWS_VERSION_2K;
	} 
	else if (osverinfo.dwMajorVersion == 5 && osverinfo.dwMinorVersion == 1){
		g_WinVersion = WINDOWS_VERSION_XP;
	} 
	else if (osverinfo.dwMajorVersion == 5 && osverinfo.dwMinorVersion == 2){
		if (osverinfo.wServicePackMajor==0){ 
			g_WinVersion = WINDOWS_VERSION_2K3;
		} 
		else{
			g_WinVersion = WINDOWS_VERSION_2K3_SP1_SP2;
		}
	} 
	else if (osverinfo.dwMajorVersion == 6 && osverinfo.dwMinorVersion == 0){
		g_WinVersion = WINDOWS_VERSION_2K3_SP1_SP2;
	}
	else if (osverinfo.dwMajorVersion == 6 && osverinfo.dwMinorVersion == 1 && osverinfo.dwBuildNumber == 7000){
		g_WinVersion = WINDOWS_VERSION_7_7000;
	}
	else if (osverinfo.dwMajorVersion == 6 && osverinfo.dwMinorVersion == 1 && osverinfo.dwBuildNumber >= 7600){
		g_WinVersion = WINDOWS_VERSION_7_7600_UP;
	}
	return g_WinVersion;
}
