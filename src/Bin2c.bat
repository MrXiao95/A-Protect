@echo off
title Bin2c
color 0B
echo.
echo �ֽڼ�ת��...
echo.


:      dll�ļ�

Bin2c.exe Dll_Resource\dbghelp.dll Dll_Resource\dbghelp.dll_src.h lpszdbghelp
Bin2c.exe Dll_Resource\symsrv.dll Dll_Resource\symsrv.dll_src.h lpszsymsrv





:     sys �ļ�

Bin2c.exe SafeSystem\objfre_win7_x86\i386\A-Protect.sys SafeSystem\objfre_win7_x86\i386\KernelModule.h lpszKernelModule
Bin2c.exe ndis5pkt\objfre_win7_x86\i386\ndis5pkt.sys ndis5pkt\objfre_win7_x86\i386\tcpsniffer.h lpszTcpsniffer


echo.
echo ת�����...
echo.
echo.
pause
