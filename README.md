# ARK

一个开源的ark源码



VS2010+WDK7.1


先编译驱动 编译win7的free版，然后执行./src下面的Bin2c.exe



其他具体功能请看代码~ A-Protect是R3的  SafeSystem是R0的驱动

 .
│  A-Protect.sln
├─bin
│      A-Protect.exe
│      
└─src
    │  A-Protect.sln
    │  A-Protect.suo
    │  Bin2c.bat
    │  Bin2c.exe
    │  
    ├─A-Protect
    │  │  A-Protect.cpp
    │  │  A-Protect.h
    │  │  A-Protect.rc
    │  │  A-Protect.vcxproj
    │  │  A-Protect.vcxproj.filters
    │  │  A-Protect.vcxproj.user
    │  │  A-ProtectDoc.cpp
    │  │  A-ProtectDoc.h
    │  │  A-ProtectView.cpp
    │  │  A-ProtectView.h
    │  │  AboutDlg.cpp
    │  │  AboutDlg.h
    │  │  Atapi.cpp
    │  │  Atapi.h
    │  │  bugcodes.h
    │  │  C3600Splash.cpp
    │  │  C3600Splash.h
    │  │  CProcessSearch.cpp
    │  │  CProcessSearch.h
    │  │  DisplayDecvice.cpp
    │  │  DLLModule.cpp
    │  │  DLLModule.h
    │  │  DpcTimer.cpp
    │  │  DpcTimer.h
    │  │  EnumSymbols.cpp
    │  │  EnumSymbols.h
    │  │  FilterDriver.cpp
    │  │  FilterDriver.h
    │  │  FsdHook.cpp
    │  │  FsdHook.h
    │  │  HipsLog.cpp
    │  │  HipsLog.h
    │  │  Install.cpp
    │  │  Install.h
    │  │  IoTimer.cpp
    │  │  IoTimer.h
    │  │  Kbdclass.cpp
    │  │  Kbdclass.h
    │  │  KernelHook.cpp
    │  │  KernelHook.h
    │  │  KernelModule.cpp
    │  │  KernelModule.h
    │  │  KernelThread.cpp
    │  │  KernelThread.h
    │  │  LookUpKernelData.cpp
    │  │  LookUpKernelData.h
    │  │  MainFrm.cpp
    │  │  MainFrm.h
    │  │  Md5.cpp
    │  │  Md5.h
    │  │  MessageHook.cpp
    │  │  MessageHook.h
    │  │  Mouclass.cpp
    │  │  Mouclass.h
    │  │  ms.cpp
    │  │  MyList.cpp
    │  │  MyList.h
    │  │  ndis5hlp.cpp
    │  │  ndis5hlp.h
    │  │  Nsiproxy.cpp
    │  │  Nsiproxy.h
    │  │  ntdef.h
    │  │  ntdll.lib
    │  │  ntifs.h
    │  │  ntiologc.h
    │  │  ntnls.h
    │  │  ObjectHook.cpp
    │  │  ObjectHook.h
    │  │  Process.cpp
    │  │  Process.h
    │  │  ProcessHandle.cpp
    │  │  ProcessHandle.h
    │  │  ProcessThread.cpp
    │  │  ProcessThread.h
    │  │  ProtectSetting.cpp
    │  │  ProtectSetting.h
    │  │  ReadMe.txt
    │  │  ReportCtrl.cpp
    │  │  ReportCtrl.h
    │  │  resource.h
    │  │  SelectAnyModule.cpp
    │  │  SelectAnyModule.h
    │  │  SelectKernelModuleHook.cpp
    │  │  SelectKernelModuleHook.h
    │  │  Services.cpp
    │  │  Services.h
    │  │  ShadowSSDT.cpp
    │  │  ShadowSSDT.h
    │  │  SnifferSetting.cpp
    │  │  SnifferSetting.h
    │  │  SSDT.cpp
    │  │  SSDT.h
    │  │  StackThread.cpp
    │  │  StackThread.h
    │  │  Startup.cpp
    │  │  Startup.h
    │  │  stdafx.cpp
    │  │  stdafx.h
    │  │  SubModule.cpp
    │  │  SubModule.h
    │  │  SystemNotify.cpp
    │  │  SystemNotify.h
    │  │  SystemThread.cpp
    │  │  SystemThread.h
    │  │  targetver.h
    │  │  tcpdump.cpp
    │  │  tcpdump.h
    │  │  Tcpip.cpp
    │  │  Tcpip.h
    │  │  TcpView.cpp
    │  │  TcpView.h
    │  │  uninstall360.cpp
    │  │  uninstall360.h
    │  │  UnloadDllModule.h
    │  │  UserImages.bmp
    │  │  Windows2003SP1_CN.h
    │  │  Windows2003SP2_CN.h
    │  │  Windows7Home_CN.h
    │  │  Windows7SP1_CN.h
    │  │  WindowsXPSP2_CN.h
    │  │  WindowsXPSP3_CN.h
    │  │  WorkQueue.cpp
    │  │  WorkQueue.h
    │  │  
    │  └─res
    │          A-Protect.bmp
    │          A-Protect.ico
    │          A-Protect1.ico
    │          A-ProtectDoc.ico
    │          AProteaaact.rc2
    │          atapi.ico
    │          Dispatch.ico
    │          DPC定时器.ico
    │          Eye.ico
    │          GDriver.ico
    │          Hips.ico
    │          IO定时器.ico
    │          KernelHook.ico
    │          KernelModule.ico
    │          KernelThread.ico
    │          MyAProtect.rc2
    │          new.ico
    │          Nsiproxy.ico
    │          ntfs-Fsd.ico
    │          null.ico
    │          ObjectHook.ico
    │          Other.ico
    │          Process.ico
    │          ProtectSetting.ico
    │          Services.ico
    │          ShadowSSDT.ico
    │          Ssdt.ico
    │          tcpip.ico
    │          TcpSniffer.ico
    │          Tcpview.ico
    │          Toolbar.bmp
    │          Toolbar256.bmp
    │          内核钩子.ico
    │          启动项.ico
    │          工作队列线程.ico
    │          开启监控-刷新.ico
    │          本机所有数据.ico
    │          监控设置.ico
    │          系统回调.ico
    │          系统线程.ico
    │          线程创建.ico
    │          键盘.ico
    │          鼠标.ico
    │          
    ├─Dll_Resource
    │      dbghelp.dll
    │      dbghelp.dll_src.h
    │      dbghelp_supp.h
    │      symsrv.dll
    │      symsrv.dll_src.h
    │      
    ├─ndis5pkt
    │      BUILD
    │      buildinc.cmd
    │      buildnumber.h
    │      ddkbldenv.cmd
    │      ddkpostbld.cmd
    │      ddkprebld.cmd
    │      drvcommon.h
    │      drvversion.h
    │      drvversion.rc
    │      makefile
    │      ndis5pkt.c
    │      ndis5pkt.h
    │      ndis5pkt.vsprops
    │      ndis5pkt.W7.vcproj
    │      openclos.c
    │      packet.h
    │      read.c
    │      readfast.c
    │      sources
    │      write.c
    │      
    ├─SafeSystem
    │      AntiInlineHook.c
    │      AntiInlineHook.h
    │      Atapi.c
    │      Atapi.h
    │      buildchk_win7_x86.log
    │      buildfre_win7_x86.log
    │      buildnumber.h
    │      Common.h
    │      Control.c
    │      Control.h
    │      DeleteFile.c
    │      DeleteFile.h
    │      DpcTimer.c
    │      DpcTimer.h
    │      DriverHips.c
    │      DriverHips.h
    │      drvcommon.h
    │      drvversion.h
    │      drvversion.rc
    │      dump.c
    │      dump.h
    │      file.c
    │      file.h
    │      FileSystem.c
    │      FileSystem.h
    │      Fixrelocation.c
    │      Fixrelocation.h
    │      FuncAddrValid.c
    │      FuncAddrValid.h
    │      Function.c
    │      Function.h
    │      InitWindowsVersion.c
    │      InitWindowsVersion.h
    │      InlineHook.c
    │      InlineHook.h
    │      IoTimer.c
    │      IoTimer.h
    │      kbdclass.c
    │      kbdclass.h
    │      KernelFilterDriver.c
    │      KernelFilterDriver.h
    │      KernelHookCheck.c
    │      KernelHookCheck.h
    │      KernelReload.c
    │      KernelReload.h
    │      KernelThread.c
    │      KernelThread.h
    │      KillProcess.c
    │      KillProcess.h
    │      ldasm.c
    │      ldasm.h
    │      libdasm.c
    │      libdasm.h
    │      LookupKernelData.c
    │      LookupKernelData.h
    │      makefile
    │      Mouclass.c
    │      Mouclass.h
    │      msghook.c
    │      msghook.h
    │      NetworkDefense.c
    │      NetworkDefense.h
    │      nsiproxy.c
    │      nsiproxy.h
    │      Ntfs.c
    │      Ntfs.h
    │      ntifs.h
    │      ntos.c
    │      ntos.h
    │      ObjectHookCheck.c
    │      ObjectHookCheck.h
    │      Port.c
    │      Port.h
    │      Process.c
    │      Process.h
    │      ProcessModule.c
    │      ProcessModule.h
    │      Protect.c
    │      Protect.h
    │      ReLoadShadowSSDTTableHook.c
    │      ReLoadShadowSSDTTableHook.h
    │      ReLoadSSDTTableHook.c
    │      ReLoadSSDTTableHook.h
    │      SafeSystem.c
    │      SafeSystem.h
    │      SafeSystem.props
    │      SafeSystem.vcxproj.filters
    │      SafeSystem.vsprops
    │      SafeSystem.W7.log
    │      SafeSystem.W7.vcproj
    │      SafeSystem.W7.vcxproj
    │      SafeSystem.W7.vcxproj.filters
    │      SafeSystem.W7.vcxproj.user
    │      SDTShadowRestore.h
    │      SelectModuleHook.c
    │      Services.c
    │      Services.h
    │      ShadowSSDT.c
    │      ShadowSSDT.h
    │      sources
    │      SSDT.c
    │      SSDT.h
    │      Startup.c
    │      Startup.h
    │      SysModule.c
    │      SysModule.h
    │      SystemNotify.c
    │      SystemNotify.h
    │      SystemThread.c
    │      SystemThread.h
    │      tables.h
    │      Tcpip.c
    │      Tcpip.h
    │      win32k.c
    │      win32k.h
    │      WorkQueue.c
    │      WorkQueue.h
    │      
    └─share
            adapter.h
            assert.h
            netdef.h
            netstd.h
