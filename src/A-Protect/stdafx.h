// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
#pragma once
#ifndef _SECURE_ATL
#define _SECURE_ATL 1
#endif
#define NOHOOK 0;
#define SSDTHOOK 1
#define SSDTINLINEHOOK 2
#define INLINEHOOK 3
#define WM_SHOWTASK (WM_USER +1)
/*
* ӥ�۷���
*/
#define EYEOPEN 1
#define EYECLOSE 2
#define EYEUPDATE 3
#define EYEUNKNOWN 0
/*
 * ��ʼ��
 */
#define SAFE_SYSTEM 0x18881111
#define LIST_SSDT   0x18881112                                //�оٱ��ҹ���SSDT����
#define LIST_SSDT_ALL    0x18881113                           //�о�����SSDT����  
#define SET_ALL_SSDT 0x18881114                               //�ָ�����SSDT����HOOK
#define SET_ONE_SSDT 0x18881115                               //�ָ�����SSDT����hook
#define SET_INLINE_HOOK 0x18881116                            //�ָ�����SSDT inline hook
#define LIST_TCPUDP 0x18881117                                //�о�������������
#define KILL_PROCESS_BY_PID 0x18881118                        //�ӽ���pid����һ������
#define LIST_PROCESS 0x18881119                               //�о����н���
#define DELETE_FILE 0x18881120                                //ɾ��һ���ļ�
#define LIST_PROCESS_MODULE 0x18881121                        //�оٽ���DLLģ��
#define INIT_PROCESS_LIST_PROCESS_MODULE 0x18881122           //���оٽ���DLLģ���ʱ�򣬱���Ҫ��ʼ��ĳЩ����
#define LIST_INLINEHOOK 0x18881123                            //ö��ntos*��hook������inline hook��eat hook
#define ANTI_INLINEHOOK 0x18881124                            //�ƹ�ntos* inline hook
#define KERNEL_SAFE_MODULE 0x18881125                         //�����ں˰�ȫģʽ
#define NO_KERNEL_SAFE_MODULE 0x18881126                      //�ر��ں˰�ȫģʽ
#define LIST_SYS_MODULE 0x18881127                           //�о��ں�ģ��
#define EXIT_PROCESS 0x18881128                              //�˳�AProtect��ʱ�򣬱���Ҫ���ں������������
#define LIST_SERVICES 0x18881129                             //�о�ϵͳ����
#define CHANG_SERVICES_TYPE_1 0x18881130                     //�����ֶ�
#define CHANG_SERVICES_TYPE_2 0x18881131                     //�����Զ�
#define CHANG_SERVICES_TYPE_3 0x18881132                     //�������
#define LIST_DEPTH_SERVICES 0x18881133                       //��ȷ���ɨ��
#define LIST_LOG 0x18881134                                  //�оٷ�����־
#define INIT_DUMP_KERNEL_MODULE_MEMORY 0x18881135            //��ʼ��dump�ں�ģ��
#define DUMP_KERNEL_MODULE_MEMORY 0x18881136                 //dump�ں�ģ���ڴ浽�ļ�
#define DIS_CREATE_PROCESS      0x18881137                   //��ֹ��������
#define CREATE_PROCESS          0x18881138                   //����������
#define DIS_WRITE_FILE      0x18881139                       //��ֹ�����ļ�
#define WRITE_FILE      0x18881140                           //�������ļ� 
#define DIS_LOAD_DRIVER      0x18881141                      //��ֹ��������
#define LOAD_DRIVER      0x18881142                          //�����������
#define SHUT_DOWN_SYSTEM      0x18881143                     //ǿ�ƻ�������ϵͳ
#define LIST_SHADOWSSDT       0x18881144                     //�оٱ��ҹ���shadowSSDT����
#define LIST_SHADOWSSDT_ALL       0x18881145                 //�о�����shadowSSDT����
#define SET_ALL_SHADOWSSDT 0x18881146                        //�ָ�����shadowSSDT hook
#define SET_ONE_SHADOWSSDT  0x18881147                       //�ָ�����shadowSSDT hook  
#define SET_SHADOWSSDT_INLINE_HOOK 0x18881148                //�ָ�����shadowSSDT inline hook
#define LIST_OBJECT_HOOK     0x18881149                      //���object hook
#define PROTECT_360SAFE 0x18881150                           //�Ƿ񱣻�360  ����ȥ���˹��ܣ�
#define UNPROTECT_360SAFE 0x18881151                         //
#define LIST_FSD_HOOK     0x18881152                         //�о�����NTFS FSD HOOK
#define SET_FSD_HOOK      0x18881153                         //�ָ�NTFS FSD hook
#define INIT_SET_FSD_HOOK  0x18881154                        //�ָ�NTFS FSD inline hook֮ǰ�ĳ�ʼ������
#define CLEAR_LIST_LOG  0x18881155                           //��շ�����־
#define LIST_KERNEL_FILTER_DRIVER   0x18881156               //�оٹ�������
#define DELETE_KERNEL_FILTER_DRIVER   0x18881157             //ժ����������
#define INIT_KERNEL_FILTER_DRIVER     0x18881158             //ժ����������֮ǰ�ĳ�ʼ������
#define ONLY_DELETE_FILE  0x18881159                         //ֱ��ɾ���ļ�����Reload
#define LIST_TCPIP_HOOK         0x18881160                   //�о�����Tcpip.sysģ��hook
#define SET_TCPIP_HOOK      0x18881161                       //�ָ�Tcpip.sysģ�� hook
#define INIT_SET_TCPIP_HOOK  0x18881162                      //�ָ�Tcpip.sysģ�� inline hook֮ǰ�ĳ�ʼ������
#define LIST_NSIPROXY_HOOK         0x18881163                //�о�����Nsiproxy.sysģ��hook
#define SET_NSIPROXY_HOOK      0x18881164                    //�ָ�Nsiproxy.sysģ�� hook
#define INIT_SET_NSIPROXY_HOOK  0x18881165                   //�ָ�Nsiproxy.sysģ�� inline hook֮ǰ�ĳ�ʼ������
#define LIST_SYSTEM_THREAD   0x18881166                      //�о�ϵͳ�߳�
#define KILL_SYSTEM_THREAD   0x18881167                      //����ϵͳ�߳�
#define PROTECT_DRIVER_FILE  0x18881168                      //���������ļ�(��ȥ��)
#define UNPROTECT_DRIVER_FILE  0x18881169
#define LIST_KERNEL_THREAD   0x18881170                      //�о��ں��߳�
#define CLEAR_KERNEL_THREAD   0x18881171                     //����ں��߳���־
#define SET_EAT_HOOK          0x18881172                     //�ָ�eat hook
#define PROTECT_PROCESS       0x18881173                     //����AProtect�������
#define UNPROTECT_PROCESS       0x18881174                   //������
#define DIS_RESET_SRV 0x18881175                             //��ֹ�����д
#define RESET_SRV 0x18881176                                 //��������д
#define KERNEL_THREAD 0x18881177                             //�������ں��߳�
#define DIS_KERNEL_THREAD 0x18881178                         //��ֹ�����ں��߳� 
#define RESUME_THREAD    0x18881179                          //�ָ��߳�����
#define SUSPEND_THREAD    0x18881180                         //��ͣ�߳�����
#define LIST_KBDCLASS_HOOK         0x18881181                //�о�����kbdclass.sysģ��hook
#define SET_KBDCLASS_HOOK      0x18881182                    //�ָ�kbdclass.sysģ�� hook
#define INIT_SET_KBDCLASS_HOOK  0x18881183                   //�ָ�kbdclass.sysģ�� inline hook֮ǰ�ĳ�ʼ������
#define LIST_MOUCLASS_HOOK         0x18881184                //�о�����Mouclass.sysģ��hook
#define SET_MOUCLASS_HOOK      0x18881185                    //�ָ�Mouclass.sysģ�� hook
#define INIT_SET_MOUCLASS_HOOK  0x18881186                   //�ָ�Mouclass.sysģ�� inline hook֮ǰ�ĳ�ʼ������
#define LIST_ATAPI_HOOK         0x18881187                   //�о�����Atapi.sysģ��hook
#define SET_ATAPI_HOOK      0x18881188                       //�ָ�Atapi.sysģ�� hook
#define INIT_SET_ATAPI_HOOK  0x18881189                      //�ָ�Atapi.sysģ�� inline hook֮ǰ�ĳ�ʼ������
#define LIST_DPC_TIMER    0x18881190                         //ö��DPC��ʱ��
#define KILL_DPC_TIMER    0x18881191                         //ժ��DPC��ʱ��
#define LIST_SYSTEM_NOTIFY    0x18881192                     //ö��ϵͳ�ص�
#define KILL_SYSTEM_NOTIFY    0x18881193                     //ժ��ϵͳ�ص�
#define INIT_KILL_SYSTEM_NOTIFY 0x18881194                   //��ʼ��ժ��
#define INIT_PROCESS_THREAD   0x18881195                     //��ʼ������EPROCESS
#define LIST_PROCESS_THREAD   0x18881196                     //��ȡ�����߳�
#define LIST_START_UP         0x18881197                     //������
#define LIST_WORKQUEUE        0x18881198                     //���������߳�
#define INIT_PDB_KERNEL_INFO  0x18881199                     //��pdb��������������ں˺���������
#define SUSPEND_PROCESS       0x18881200                     //��ͣ����
#define RESUME_PROCESS        0x18881201                     //�ָ���������
#define INIT_THREAD_STACK     0x18881202                     //��ʼ���̶߳�ջ
#define LIST_THREAD_STACK     0x18881203                     //��ȡ�̶߳�ջ
#define INIT_KERNEL_DATA_BASE     0x18881204                     //��ʼҪ�鿴����ʼ��ַ
#define INIT_KERNEL_DATA_SIZE     0x18881205                     //��ʼ��Ҫ�鿴�Ĵ�С
#define LIST_KERNEL_DATA          0x18881206                     //��ʼ�鿴��
#define SUSPEND_PROTECT        0x18881207                    //��ͣ����   
#define RESUME_PROTECT         0x18881208                    //�ָ����� 
#define KERNEL_BSOD            0x18881209                   //�ֶ�����  
#define INIT_SELECT_MODULE_INLINE_HOOK  0x18881210          //��ʼ����ѡģ���inlinehookɨ�� 
#define LIST_SELECT_MODULE_INLINE_HOOK  0x18881211          //ɨ����ѡģ���inlinehookɨ�� 
#define INIT_SET_SELECT_INLINE_HOOK 0x18881212              //��ʼ���ָ�inlinehook (ԭʼ��ַ)
#define INIT_SET_SELECT_INLINE_HOOK_1 0x18881213            //��ʼ���ָ�inlinehook (ԭʼģ���ַ)
#define SET_SELECT_INLINE_HOOK      0x18881214              //��ʼ�ָ�inlinehook
#define ANTI_SELECT_INLINE_HOOK     0x18881215              //�ƹ���ѡ��inlinehook
#define SET_WINDOWS_HOOK            0x18881216             //����ȫ�ֹ���
#define DIS_SET_WINDOWS_HOOK        0x18881217             //�ܾ�ȫ�ֹ���
#define INIT_DUMP_KERNEL_MODULE_MEMORY_1   0x18881218      //��ʼ��dump��С
#define LIST_IO_TIMER               0x18881219             //ö��IO��ʱ��
#define START_IO_TIMER               0x18881220            //����IO��ʱ��
#define STOP_IO_TIMER               0x18881221             //ֹͣIO��ʱ��
#define INIT_EAT_NUMBER          0x18881222                //��ʼ��EAT�ĵ��뺯��λ��
#define INIT_EAT_REAL_ADDRESS          0x18881223          //��ʼ��EAT��ԭʼ��ַ
#define DIS_DLL_FUCK                0x18881224             //�ر�DLLЮ�ַ���
#define DLL_FUCK                    0x18881225             //����DLLЮ�ַ���
#define LIST_MESSAGE_HOOK            0x18881226            //��Ϣ����
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // �� Windows ͷ���ų�����ʹ�õ�����
#endif
#include "targetver.h"
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // ĳЩ CString ���캯��������ʽ��
// �ر� MFC ��ĳЩ�����������ɷ��ĺ��Եľ�����Ϣ������
#define _AFX_ALL_WARNINGS
#include <afxwin.h>         // MFC ��������ͱ�׼���
#include <afxext.h>         // MFC ��չ
#include <afxdisp.h>        // MFC �Զ�����
#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // MFC �� Internet Explorer 4 �����ؼ���֧��
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>             // MFC �� Windows �����ؼ���֧��
#endif // _AFX_NO_AFXCMN_SUPPORT
#include <afxcontrolbars.h>     // �������Ϳؼ����� MFC ֧��
#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif


