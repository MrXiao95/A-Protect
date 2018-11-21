//	dbghelp_supp.h : supplement header file for dbghelp.dll
//	Author: DLL to Lib version 3.00
//	Date: Saturday, March 09, 2013
//	Description: The declaration of the dbghelp.dll's entry-point function.
//	Prototype: BOOL WINAPI xxx_DllMain(HINSTANCE hinstance, DWORD fdwReason, LPVOID lpvReserved);
//	Parameters: 
//		hinstance
//		  Handle to current instance of the application. Use AfxGetInstanceHandle()
//		  to get the instance handle if your project has MFC support.
//		fdwReason
//		  Specifies a flag indicating why the entry-point function is being called.
//		lpvReserved 
//		  Specifies further aspects of DLL initialization and cleanup. Should always
//		  be set to NULL;
//	Comment: Please see the help document for detail information about the entry-point 
//		 function
//	Homepage: http://www.binary-soft.com
//	Technical Support: support@binary-soft.com
/////////////////////////////////////////////////////////////////////

#if !defined(D2L_DBGHELP_SUPP_H__654D0CA2_7E7E_12AB_7F61_398115A71AFE__INCLUDED_)
#define D2L_DBGHELP_SUPP_H__654D0CA2_7E7E_12AB_7F61_398115A71AFE__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef __cplusplus
extern "C" {
#endif


#include <windows.h>

#include <objbase.h>

/* 这是 dbghelp.dll'入口点函数 它是必须的
 初始化和定稿. */

BOOL WINAPI __imp_DBGHELP_DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);


#ifdef __cplusplus
}
#endif

#endif // !defined(D2L_DBGHELP_SUPP_H__654D0CA2_7E7E_12AB_7F61_398115A71AFE__INCLUDED_)