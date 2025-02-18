FOR %%G in (
"%SYS32%\bfe.dll"
"%SYS32%\cryptsvc.dll"
"%SYS32%\dnsapi.dll"
"%SYS32%\dnsrslvr.dll"
"%SYS32%\dosvc.dll"
"%SYS32%\Drivers\afd.sys"
"%SYS32%\Drivers\mpsdrv.sys"
"%SYS32%\Drivers\netbt.sys"
"%SYS32%\Drivers\nsiproxy.sys"
"%SYS32%\Drivers\tcpip.sys"
"%SYS32%\Drivers\tdx.sys"
"%SYS32%\es.dll"
"%SYS32%\iphlpsvc.dll"
"%SYS32%\ipnathlp.dll"
"%SYS32%\mpssvc.dll"
"%SYS32%\nsisvc.dll"
"%SYS32%\qmgr.dll"
"%SYS32%\rpcss.dll"
"%SYS32%\SDRSVC.dll"
"%SYS32%\SecurityHealthService.exe"
"%SYS32%\svchost.exe"
"%SYS32%\tasklist.exe"
"%SYS32%\taskmgr.exe"
"%SYS32%\usosvc.dll"
"%SYS32%\vssvc.exe"
"%SYS32%\WaaSMedicSvc.dll"
"%SYS32%\wevtutil.exe"
"%SYS32%\wscsvc.dll"
"%SYS32%\wuaueng.dll"
) DO @(
  IF NOT EXIST %%G (
    ECHO.%%G %Scan_IsMissing%!>>"%TEMP%\m1ss1ng00"
    )
)

:eof
EXIT /B