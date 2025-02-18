@ECHO OFF
@SETLOCAL
@CD /D "%~dp0"
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
COLOR 71
TITLE Furtivex
CHCP 65001>NUL
IF NOT EXIST "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh" MD "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh" >NUL 2>&1
IF NOT EXIST "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies" MD "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies" >NUL 2>&1
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
FOR %%G in (
grep.exe
libiconv2.dll
libintl3.dll
MessageBoxW.exe
pcre3.dll
pevFind.exe
regex2.dll
sed.exe
sort_.exe
) DO @(
  IF NOT EXIST "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies\%%G" COPY /Y "%CD%\dependencies\%%G" "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies" >NUL 2>&1 )
)
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
FOR %%G in (
I4ng.bat
jm.bat
NULL
pol.bat
R3570R3.bat
w1tchav.bat
regbad.cfg
tskwht.cfg
Urunkey.cfg
runblk.cfg
svcblk.cfg
helpdefend.reg
) DO @(
  IF NOT EXIST "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\%%G" COPY /Y "%CD%\%%G" "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh" >NUL 2>&1
)
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
IF EXIST %WINDIR%\SysWOW64 (SET ARCH=x64) else (SET ARCH=x86)
IF EXIST %WINDIR%\Sysnative\cmd.exe (SET "SYS32=%WINDIR%\Sysnative") else (SET "SYS32=%WINDIR%\System32")
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
SET "ALLUSERSPROFILE=%SYSTEMDRIVE%\ProgramData"
SET "APPDATA=%USERPROFILE%\AppData\Roaming"
SET "COMMON32=%SYSTEMDRIVE%\Program Files\Common Files"
SET "COMMON64=%SYSTEMDRIVE%\Program Files (x86)\Common Files"
SET "CUCDM=HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
SET "LOCALA=%USERPROFILE%\AppData\Local"
SET "LOCALLOW=%USERPROFILE%\AppData\LocalLow"
SET "PROGFILES32=%SYSTEMDRIVE%\Program Files"
SET "PROGFILES64=%SYSTEMDRIVE%\Program Files (x86)"
SET "PROGRAMSAUP=%SYSTEMDRIVE%\ProgramData\Microsoft\Windows\Start Menu\Programs"
SET "PROGRAMSCU=%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
SET "PROGRAMS1ALL=%SYSTEMDRIVE%\ProgramData\Start Menu\Programs"
SET "PROGRAMS2ALL=%USERPROFILE%\Start Menu\Programs"
SET "PUBDESKTOP=%SYSTEMDRIVE%\Users\Public\Desktop"
SET "PUBLIC=%SYSTEMDRIVE%\Users\Public"
SET "QUICKLAUNCHSM=%USERPROFILE%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\StartMenu"
SET "QUICKLAUNCHTB=%USERPROFILE%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
SET "QUICKLAUNCH=%USERPROFILE%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"
SET "STARTMENUAUP=%SYSTEMDRIVE%\ProgramData\Microsoft\windows\Start Menu"
SET "STARTMENUCU=%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu"
SET "STARTUP=%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
SET "STASKS=%SYSTEMDRIVE%\WINDOWS\System32\Tasks"
SET "URun=HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
SET "MRun=HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
SET "URunOnce=HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
SET "MRunOnce=HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
SET "S1518RunOnce=HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\RunOnce"
SET "S1519RunOnce=HKEY_USERS\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\RunOnce"
SET "S1520RunOnce=HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\RunOnce"
SET "WTASKS=%SYSTEMDRIVE%\WINDOWS\Tasks"
SET "GREP=%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies\grep.exe"
SET "SED=%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies\sed.exe"
SET "SORT=%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies\sort_.exe"
SET "MESSAGEBOXW=%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies\MessageBoxW.exe"
SET "PEVFIND=%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies\pevFind.exe"
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
REM Powershell does not like CHCP 65001. It changes the cmd.exe font to Raster, non TrueType font which breaks language support. Solution by Dragokas -- Toggle to English (437) before each powershell command
IF EXIST %SYS32%\chcp.com CHCP 437>NUL
POWERSHELL -command "(Get-CimInstance -ClassName CIM_OperatingSystem).Caption">temp00
IF EXIST %SYS32%\chcp.com CHCP 65001>NUL
"%SED%" -r "s/^.*\s+(Windows\s+.*)/\1/" <temp00 >temp01
FOR /F "TOKENS=*" %%G IN ( temp01 ) DO SET OS=%%G
"%GREP%" -Esi "Windows 1[0|1]" <temp01 >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :Abort
FOR /F "tokens=2*" %%A IN ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion 2^>NUL') DO SET DisplayVersion=%%B
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
@CALL I4ng.bat

"%MESSAGEBOXW%" QBOXCOMTOP "%Disclaimer%"
IF ERRORLEVEL 1 GOTO :Abort

REM ~~~~~~~~~~~~~~~~~~~~~~~~>
@CALL R3570R3.bat
@CALL Pol.bat
whoami /user>temp00
"%GREP%" -Es "S-1-5-21-[0-9]{10}-[0-9]{10}-[0-9]{10}-[0-9]{3,4}$" <temp00 >temp01
IF ERRORLEVEL 1 ( GOTO :AdminChk )
"%SED%" -r "s/^.*(S-1-5-21-[0-9]{10}-[0-9]{10}-[0-9]{10}-[0-9]{3,4})$/\1/" <temp01 >temp02
FOR /F %%G in (temp02) DO SET SID=%%G
DEL /F/Q temp0? >NUL 2>&1
REM ~~~~~~~~~~~~~~~~~~~~~~~~>
:AdminChk

FOR %%G in (
grep.exe
libiconv2.dll
libintl3.dll
pcre3.dll
MessageBoxW.exe
pevFind.exe
regex2.dll
sed.exe
sort_.exe
) DO ( IF NOT EXIST "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies\%%G" GOTO :Abort )

FOR %%G in (
I4ng.bat
jm.bat
NULL
pol.bat
R3570R3.bat
w1tchav.bat
regbad.cfg
tskwht.cfg
Urunkey.cfg
runblk.cfg
svcblk.cfg
helpdefend.reg
) DO ( IF NOT EXIST "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\%%G" GOTO :Abort )

IF EXIST %SYS32%\chcp.com CHCP 437>NUL
for /f %%a in ('powershell -Command "Get-Date -format yyyy_MM_dd__HH_mm_ss"') do set datetime=%%a
:: Create System Restore Point
POWERSHELL -command "Checkpoint-Computer -Description 'Furtivex Malware Removal Script' -RestorePointType 'MODIFY_SETTINGS'" >NUL 2>&1
IF ERRORLEVEL 1 (SET RestorePoint=%Log_RPFailed%) ELSE (SET RestorePoint=%Log_RPCreated%)
IF EXIST %SYS32%\chcp.com CHCP 65001>NUL
cls
ECHO.%Scan_ThereWillBeLog%
ECHO.%Scan_ShowHelper%
ECHO.
ECHO.
:License

:: PROCESSES ::
:Processes
cls
ECHO.%Scan_ThereWillBeLog%
ECHO.%Scan_ShowHelper%
ECHO.
ECHO.
ECHO.[^|    ]
:: Making video? obs-ffmpeg-mux|obs64
TASKLIST /FO CSV /NH 2>NUL|"%GREP%" -Es "\.exe" >temp00
"%SED%" -r "s/^\x22(.*\.exe)\x22.*/\1/" <temp00 >temp01
"%SORT%" -f -u <temp01 >temp02
"%GREP%" -Eivs "^(audiodg|cmd|conhost|csrss|ctfmon|dllhost|dwm|ekrn|explorer|fontdrvhost|LsaIso|lsass|MBAMService|MpCmdRun|MpDefenderCoreService|MsSense|MsMpEng|NisSrv|OpenConsole|RuntimeBroker|Search(host|Indexer)|services|SecHealthUI|SecurityHealthService|ShellExperienceHost|sihost|(CHX)?smartscreen|smss|spoolsv|StartMenuExperienceHost|svchost|task(kill|hostw)|TextInputHost|WindowsTerminal|VSSVC|wininit|winlogon|WmiPrvSE|WUDFHost)\.exe$" <temp02 >temp03
@FOR /F "TOKENS=*" %%G IN ( temp03 ) DO @TASKKILL /F /IM "%%G" >NUL 2>&1
DEL /F/Q temp0? >NUL 2>&1

:: Use WMI PROCESSES for the items in my taskkill whitelist since malware likes to impersonate those too! 
FOR %%G in (
audiodg
CHXsmartscreen
cmd
conhost
csrss
ctfmon
dllhost
dmw
ekrn
explorer
fontdrvhost
LsaIso
lsass
MBAMService
MpCmdRun
MpDefenderCoreService
MsSense
NisSrv
OpenConsole
RuntimeBroker
Searchhost
SearchIndexer
SecHealthUI
SecurityHealthService
services
ShellExperienceHost
sihost
smartscreen
smss
spoolsv
StartMenuExperienceHost
svchost
taskhostw
taskkill
TextInputHost
VSSVC
WindowsTerminal
wininit
winlogon
WmiPrvSE
WUDFHost
) DO @(
  IF EXIST %SYS32%\wbem\WMIC.exe @wmic process where name="%%G.exe" list full 2>NUL|"%GREP%" -Eis "^ExecutablePath">>WMICproc00
)

REM ~~~~~~~~~~~~~~~~~~~~~~~~>
:WMICCheck
IF NOT EXIST %SYS32%\wbem\WMIC.exe GOTO :PSCheck
"%GREP%" -Eivs "^ExecutablePath=$" <WMICproc00 >WMICproc01
"%GREP%" -Eivs "^ExecutablePath=C:\\Program Files\\WindowsApps\\Microsoft\.WindowsTerminal_[0-9].*[0-9]{1,}_x(64|86)__8wekyb3d8bbwe\\(WindowsTerminal|OpenConsole)\.exe$" <WMICproc01 >WMICproc02
"%GREP%" -Eivs "^ExecutablePath=C:\\Windows\\SystemApps\\MicrosoftWindows\.Client\.CBS_cw5n1h2txyewy\\(TextInputHost|Searchhost)\.exe$" <WMICproc02 >WMICproc03
"%GREP%" -Eivs "^ExecutablePath=C:\\Windows\\SystemApps\\Microsoft\.Windows\.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost\.exe$" <WMICproc03 >WMICproc04
"%GREP%" -Eivs "^ExecutablePath=C:\\WINDOWS\\(system32|SysWOW64)\\wbem\\wmiprvse\.exe$" <WMICproc04 >WMICproc05
"%GREP%" -Eivs "^ExecutablePath=C:\\Windows\\(system32|SysWOW64)\\(audiodg|cmd|conhost|ctfmon|DllHost|fontdrvhost|lsass|RuntimeBroker|SearchIndexer|sihost|smartscreen|spoolsv|svchost|task(kill|hostw)|SecurityHealthService|VSSVC|wininit|winlogon|WUDFHost)\.exe$" <WMICproc05 >WMICproc06
"%GREP%" -Eivs "^ExecutablePath=C:\\Windows\\SystemApps\\Microsoft\.Windows\.AppRep\.ChxApp_cw5n1h2txyewy\\CHXSmartScreen\.exe$" <WMICproc06 >WMICproc07
"%GREP%" -Eivs "^ExecutablePath=C:\\Program Files\\WindowsApps\\Microsoft\.SecHealthUI_[0-9].*[0-9]{1,}_x(64|86)__8wekyb3d8bbwe\\SecHealthUI\.exe$" <WMICproc07 >WMICproc08
"%GREP%" -Eivs "^ExecutablePath=C:\\WINDOWS\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost\.exe$" <WMICproc08 >WMICproc09
"%GREP%" -Eivs "^ExecutablePath=C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\[0-9].*[0-9]{1,}\\(MsMpEng|MpCmdRun|MpDefenderCoreService|NisSrv)\.exe$" <WMICproc09 >WMICproc10
"%GREP%" -Eivs "^ExecutablePath=C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense\.exe$" <WMICproc10 >WMICproc11
"%GREP%" -Eivs "^ExecutablePath=C:\\Windows\\SysWOW64\\cmd\.exe$" <WMICproc11 >WMICproc12
"%GREP%" -Eivs "^ExecutablePath=C:\\Windows\\SystemApps\\Microsoft\.Windows\.SecHealthUI_cw5n1h2txyewy\\SecHealthUI\.exe$" <WMICproc12 >WMICproc13
"%GREP%" -Eivs "^ExecutablePath=C:\\Program Files\\ESET\\ESET Security\\ekrn\.exe$" <WMICproc13 >WMICproc14
"%GREP%" -Eivs "^ExecutablePath=C:\\Program Files\\Malwarebytes\\Anti-Malware\\MBAMService\.exe$" <WMICproc14 >WMICproc15
"%GREP%" -Eivs "^ExecutablePath=C:\\WINDOWS\\explorer\.exe$" <WMICproc15 >WMICproc16

IF EXIST WMICproc16 "%SED%" -r "s/^ExecutablePath=//; s/\\/\\\\/g" <WMICproc16 >WMICproc17
IF EXIST WMICproc17 (
  @FOR /F "TOKENS=*" %%G IN ( WMICproc17 ) DO @(
    wmic process where "ExecutablePath='%%G'" Terminate >NUL 2>&1
    ECHO.%%G ^(WMIC^)>>"%TEMP%\005"
  )
)
DEL /F/Q WMICproc?? >NUL 2>&1
GOTO :WitchAV
REM ~~~~~~~~~~~~~~~~~~~~~~~~> some of these add whitespace at end of path. e.g. audiodg.exe
:PSCheck
IF NOT EXIST %SYS32%\WindowsPowerShell\v1.0\powershell.exe GOTO :JM
IF EXIST %SYS32%\chcp.com CHCP 437>NUL
FOR %%G in (
audiodg
CHXsmartscreen
cmd
conhost
csrss
ctfmon
dllhost
dmw
ekrn
fontdrvhost
LsaIso
lsass
MBAMService
MpCmdRun
MpDefenderCoreService
MsSense
NisSrv
OpenConsole
RuntimeBroker
Searchhost
SearchIndexer
SecHealthUI
SecurityHealthService
services
ShellExperienceHost
sihost
smartscreen
smss
spoolsv
StartMenuExperienceHost
svchost
taskhostw
taskkill
TextInputHost
VSSVC
WindowsTerminal
wininit
winlogon
WmiPrvSE
WUDFHost
) DO @(
  IF EXIST %SYS32%\WindowsPowerShell\v1.0\powershell.exe @POWERSHELL -command "Get-Process %%G | Select-Object Path"|"%GREP%" -Eis "\.exe">>PSproc00
)
IF EXIST %SYS32%\chcp.com CHCP 65001>NUL
"%GREP%" -Eivs "^C:\\Program Files\\WindowsApps\\Microsoft\.WindowsTerminal_[0-9].*[0-9]{1,}_x(64|86)__8wekyb3d8bbwe\\(WindowsTerminal|OpenConsole)\.exe" <PSproc00 >PSproc01
"%GREP%" -Eivs "^C:\\Windows\\SystemApps\\MicrosoftWindows\.Client\.CBS_cw5n1h2txyewy\\(TextInputHost|Searchhost)\.exe" <PSproc01 >PSproc02
"%GREP%" -Eivs "^C:\\Windows\\SystemApps\\Microsoft\.Windows\.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost\.exe" <PSproc02 >PSproc03
"%GREP%" -Eivs "^C:\\WINDOWS\\(system32|SysWOW64)\\wbem\\wmiprvse\.exe" <PSproc03 >PSproc04
"%GREP%" -Eivs "^C:\\Windows\\(system32|SysWOW64)\\(audiodg|cmd|conhost|ctfmon|DllHost|fontdrvhost|lsass|RuntimeBroker|SearchIndexer|sihost|smartscreen|spoolsv|svchost|task(kill|hostw)|SecurityHealthService|VSSVC|wininit|winlogon|WUDFHost)\.exe" <PSproc04 >PSproc05
"%GREP%" -Eivs "^C:\\Windows\\SystemApps\\Microsoft\.Windows\.AppRep\.ChxApp_cw5n1h2txyewy\\CHXSmartScreen\.exe" <PSproc05 >PSproc06
"%GREP%" -Eivs "^C:\\Program Files\\WindowsApps\\microsoft\.SecHealthUI_[0-9].*[0-9]{1,}_x(64|86)__8wekyb3d8bbwe\\SecHealthUI\.exe" <PSproc06 >PSproc07
"%GREP%" -Eivs "^C:\\WINDOWS\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost\.exe" <PSproc07 >PSproc08
"%GREP%" -Eivs "^C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\[0-9].*[0-9]{1,}\\(MsMpEng|MpCmdRun|MpDefenderCoreService|NisSrv)\.exe" <PSproc08 >PSproc09
"%GREP%" -Eivs "^C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense\.exe" <PSproc09 >PSproc10
"%GREP%" -Eivs "^C:\\Windows\\SysWOW64\\cmd\.exe" <PSproc10 >PSproc11
"%GREP%" -Eivs "^C:\\Windows\\SystemApps\\Microsoft\.Windows\.SecHealthUI_cw5n1h2txyewy\\SecHealthUI\.exe" <PSproc11 >PSproc12
"%GREP%" -Eivs "^C:\\Program Files\\ESET\\ESET Security\\ekrn\.exe" <PSproc12 >PSproc13
"%GREP%" -Eivs "^C:\\Program Files\\Malwarebytes\\Anti-Malware\\MBAMService\.exe" <PSproc13 >PSproc14
"%GREP%" -Eivs "^C:\\WINDOWS\\explorer\.exe" <PSproc14 >PSproc15

IF EXIST PSproc15 "%SED%" -r "s/\s+$//" <PSproc15 >PSproc16
IF EXIST %SYS32%\chcp.com CHCP 437>NUL
IF EXIST PSproc16 (
  @FOR /F "TOKENS=*" %%G IN ( PSproc16 ) DO @(
    POWERSHELL -command "Get-Process | ? { $_.Path -eq '%%G' } | Stop-Process" >NUL 2>&1
    ECHO.%%G ^(PS^)>>"%TEMP%\005"
  )
)
IF EXIST %SYS32%\chcp.com CHCP 65001>NUL
DEL /F/Q PSproc?? >NUL 2>&1

:WitchAV
@CALL w1tchav.bat
DEL /F/Q temp0? >NUL 2>&1
:: REGISTRY ::
:Registry
cls
ECHO.%Scan_ThereWillBeLog%
ECHO.%Scan_ShowHelper%
ECHO.
ECHO.
ECHO.[^|^|   ]
:RunOnce
REG QUERY %URunOnce% 2>NUL|"%GREP%" -Es "REG_SZ">runonce00
IF ERRORLEVEL 1 GOTO :RunOnce1
"%SED%" -r "s/^\s{4}(.*)\s{4}REG_SZ.*/\1/" <runonce00 >runonce01
FOR /F "TOKENS=*" %%G IN ( runonce01 ) DO @(
  ECHO.%URunOnce%\\"%%G">>"%TEMP%\004"
  REG DELETE %URunOnce% /V "%%G" /F >NUL 2>&1
)
:RunOnce1
REG QUERY %MRunOnce% 2>NUL|"%GREP%" -Es "REG_SZ">runonce00
IF ERRORLEVEL 1 GOTO :RunOnce2
"%SED%" -r "s/^\s{4}(.*)\s{4}REG_SZ.*/\1/" <runonce00 >runonce01
FOR /F "TOKENS=*" %%G IN ( runonce01 ) DO @(
  ECHO.%MRunOnce%\\"%%G">>"%TEMP%\004"
  REG DELETE %MRunOnce% /V "%%G" /F >NUL 2>&1
)
:RunOnce2
REG QUERY %S1518RunOnce% 2>NUL|"%GREP%" -Es "REG_SZ">runonce00
IF ERRORLEVEL 1 GOTO :RunOnce3
"%SED%" -r "s/^\s{4}(.*)\s{4}REG_SZ.*/\1/" <runonce00 >runonce01
FOR /F "TOKENS=*" %%G IN ( runonce01 ) DO @(
  ECHO.%S1518RunOnce%\\%%G>>"%TEMP%\004"
  REG DELETE %S1518RunOnce% /V "%%G" /F >NUL 2>&1
)
:RunOnce3
REG QUERY %S1519RunOnce% 2>NUL|"%GREP%" -Es "REG_SZ">runonce00
IF ERRORLEVEL 1 GOTO :RunOnce4
"%SED%" -r "s/^\s{4}(.*)\s{4}REG_SZ.*/\1/" <runonce00 >runonce01
FOR /F "TOKENS=*" %%G IN ( runonce01 ) DO @(
  ECHO.%S1519RunOnce%\\%%G>>"%TEMP%\004"
  REG DELETE %S1519RunOnce% /V "%%G" /F >NUL 2>&1
)
:RunOnce4
REG QUERY %S1520RunOnce% 2>NUL|"%GREP%" -Es "REG_SZ">runonce00
IF ERRORLEVEL 1 GOTO :Urunkey
"%SED%" -r "s/^\s{4}(.*)\s{4}REG_SZ.*/\1/" <runonce00 >runonce01
FOR /F "TOKENS=*" %%G IN ( runonce01 ) DO @(
  ECHO.%S1520RunOnce%\\%%G>>"%TEMP%\004"
  REG DELETE %S1520RunOnce% /V "%%G" /F >NUL 2>&1
)
:Urunkey
IF %ARCH%==x64 (
  FOR /F "TOKENS=*" %%G IN ( Urunkey.cfg ) DO @(
  REG DELETE %URun% /V "%%G" /REG:64 /F >NUL 2>&1
  IF NOT ERRORLEVEL 1 ( ECHO.%URun%\\%%G>>"%TEMP%\004" )
  REG DELETE %MRun% /V "%%G" /REG:64 /F >NUL 2>&1
  IF NOT ERRORLEVEL 1 ( ECHO.%MRun%\\%%G>>"%TEMP%\004" )
  )
)

IF %ARCH%==x86 (
  FOR /F "TOKENS=*" %%G IN ( Urunkey.cfg ) DO @(
  REG DELETE %URun% /V "%%G" /REG:32 /F >NUL 2>&1
  IF NOT ERRORLEVEL 1 ( ECHO.%URun%\\%%G>>"%TEMP%\004" )
  REG DELETE %MRun% /V "%%G" /REG:32 /F >NUL 2>&1
  IF NOT ERRORLEVEL 1 ( ECHO.%MRun%\\%%G>>"%TEMP%\004" )
  )
)

:URun2
REG QUERY %URun% 2>NUL|"%GREP%" -Es "REG_SZ">runonce00
IF ERRORLEVEL 1 GOTO :MRun
"%SED%" -r "s/^\s{4}(.*)\s{4}REG_SZ.*/\1/" <runonce00 >runonce01
"%GREP%" -Eixf runblk.cfg <runonce01 >runonce02
"%SORT%" -f -u <runonce02 >runonce03
FOR /F "TOKENS=*" %%G IN ( runonce03 ) DO @(
  ECHO.%URun%\\%%G>>"%TEMP%\004"
  REG DELETE %URun% /V "%%G" /F >NUL 2>&1
)

:MRun
REG QUERY %MRun% 2>NUL|"%GREP%" -Es "REG_SZ">runonce00
IF ERRORLEVEL 1 GOTO :FakeSteam
"%SED%" -r "s/^\s{4}(.*)\s{4}REG_SZ.*/\1/" <runonce00 >runonce01
"%GREP%" -Eixf runblk.cfg <runonce01 >runonce02
"%SORT%" -f -u <runonce02 >runonce03
FOR /F "TOKENS=*" %%G IN ( runonce03 ) DO @(
  ECHO.%MRun%\\%%G>>"%TEMP%\004"
  REG DELETE %MRun% /V "%%G" /F >NUL 2>&1
)
:FakeSteam
REG QUERY %URun% /V Steam 2>NUL|"%GREP%" -Pis "^\s{4,}Steam\s+REG_SZ\s+\x22C:\\(Steam\\steam|ProgramData\\Steam\\Launcher\\Steam)\.exe\x22">"%TEMP%\%random%"
IF ERRORLEVEL 1 ( GOTO :EdgeAutoLaunch )
ECHO.%URun%\\Steam>>"%TEMP%\004"
REG DELETE %URun% /V Steam /F >NUL 2>&1

:EdgeAutoLaunch
REG QUERY %URun% 2>NUL|"%GREP%" -Eis "(MicrosoftEdge|YandexBrowser|AvastBrowser|GoogleChrome)AutoLaunch_[A-F0-9]{32}|Mozilla-Firefox-[A-F0-9]{16}">"%TEMP%\FMRSlogh.txt"
IF ERRORLEVEL 1 ( GOTO :SubscribedContent )
"%SED%" -r "s/^\s{4}((MicrosoftEdge|YandexBrowser|AvastBrowser|GoogleChrome)AutoLaunch_[A-F0-9]{32}|Mozilla-Firefox-[A-F0-9]{16})\s+REG_SZ\s+.*/\1/" <"%TEMP%\FMRSlogh.txt" >"%TEMP%\FMRSlogh2.txt"
FOR /F %%G in (%TEMP%\FMRSlogh2.txt) DO (
    ECHO(%URun%\\%%G>>"%TEMP%\004"
    REG DELETE %URun% /V "%%G" /F >NUL 2>&1
)

:SubscribedContent
REG QUERY %CUCDM% 2>NUL|"%GREP%" -Eis "SubscribedContent-[0-9]{5,}Enabled">"%TEMP%\FMRSlogh.txt"
IF ERRORLEVEL 1 ( GOTO :CertUtil )
"%SED%" -r "s/^\s{4}(SubscribedContent-[0-9]{5,}Enabled)\s+REG_DWORD\s+.*/\1/" <"%TEMP%\FMRSlogh.txt" >"%TEMP%\FMRSlogh2.txt"
FOR /F %%G in (%TEMP%\FMRSlogh2.txt) DO (
    ECHO(%CUCDM%\\%%G>>"%TEMP%\004"
    REG DELETE %CUCDM% /V "%%G" /F >NUL 2>&1
)

:CertUtil
IF EXIST %SYS32%\CertUtil.exe %SYS32%\CertUtil.exe -urlcache * delete>NUL
IF NOT EXIST %SYS32%\wevtutil.exe GOTO :BlackLotus
%SYS32%\wevtutil.exe EL|"%GREP%" -Es "^(Application|Security|Setup|System|ForwardedEvents)$">"%TEMP%\FMRSlogcl.txt"
FOR /F %%G in (%TEMP%\FMRSlogcl.txt) DO ( %SYS32%\wevtutil.exe cl %%G>NUL )
REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity /v Enabled 2>nul>"%TEMP%\bl00"
REG QUERY "HKLM\Software\Microsoft\Windows Defender\Exclusions" /REG:64 /S 2>NUL>>"%TEMP%\bl00"
%sys32%\wevtutil.exe QE "Microsoft-Windows-Windows Defender/Operational" /q:"Event/System/EventID=3002" /c:10 /f:text>>"%TEMP%\bl00"


:BlackLotus

:: TASKS ::
:Tasks
cls
ECHO.%Scan_ThereWillBeLog%
ECHO.%Scan_ShowHelper%
ECHO.
ECHO.
ECHO.[^|^|^|  ]
SCHTASKS /QUERY /FO LIST /V 2>NUL|"%GREP%" -Eis "^TaskName:">tasks00
"%SED%" -r "s/^TaskName:\s+\\(.*)$/\1/" <tasks00 >tasks01
"%GREP%" -Eivxf tskwht.cfg <tasks01 >tasks02
"%SORT%" -f -u <tasks02 >tasks03
FOR /F "TOKENS=*" %%G IN ( tasks03 ) DO @(
  SCHTASKS /DELETE /TN "%%G" /F >NUL 2>&1
  IF NOT ERRORLEVEL 1 (
    ECHO."%%G">>"%TEMP%\002"
    )
)

:Services
cls
ECHO.%Scan_ThereWillBeLog%
ECHO.%Scan_ShowHelper%
ECHO.
ECHO.
ECHO.[^|^|^|^| ]
REG QUERY "HKLM\SYSTEM\CurrentControlSet\services" 2>NUL|"%GREP%" -Pis "\\CurrentControlSet\\services\\\w+">svc00
IF ERRORLEVEL 1 GOTO :DiscordCache
"%GREP%" -Eixf svcblk.cfg <svc00 >svc01
IF ERRORLEVEL 1 GOTO :DiscordCache
"%SORT%" -f -u <svc01 >svc02
DEL /F/Q svc00 svc01 >NUL 2>&1
FOR /F "TOKENS=*" %%G IN ( svc02 ) DO @(
  ECHO.%%G>>"%TEMP%\000b"
  REG DELETE "%%G" /F >NUL 2>&1
)

:DiscordCache
cls
ECHO.%Scan_ThereWillBeLog%
ECHO.%Scan_ShowHelper%
ECHO.
ECHO.
ECHO.[^|^|^|^|^|]
IF EXIST "%APPDATA%\discord\Cache\Cache_Data" DIR /B/S/A:-D "%APPDATA%\discord\Cache\Cache_Data" 2>NUL>appdata00
IF EXIST "%APPDATA%\discord\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\discord\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:DiscordCodeCache
IF EXIST "%APPDATA%\discord\Code Cache\js" DIR /B/S/A:-D "%APPDATA%\discord\Code Cache\js" 2>NUL>appdata00
IF EXIST "%APPDATA%\discord\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\discord\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:D3DSCache
IF EXIST "%LOCALA%\D3DSCache" DIR /B/S/A:D "%LOCALA%\D3DSCache" 2>NUL>locala00
IF EXIST "%LOCALA%\D3DSCache" (
  "%GREP%" -Esi "\\[a-f0-9]{10,}$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  RD /S/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\D3DSCache ^(%%H^)>>"%TEMP%\001b"
      )
  )
)
:D3DSCache2
IF EXIST "%WINDIR%\ServiceProfiles\LocalService\AppData\Local\D3DSCache" DIR /B/S/A:D "%WINDIR%\ServiceProfiles\LocalService\AppData\Local\D3DSCache" 2>NUL>sys32appdata00
IF EXIST "%WINDIR%\ServiceProfiles\LocalService\AppData\Local\D3DSCache" (
  "%GREP%" -Esi "\\[a-f0-9]{10,}$" <sys32appdata00 >sys32appdata01
  "%SORT%" -f -u <sys32appdata01 >sys32appdata02
  FOR /F "TOKENS=*" %%G IN ( sys32appdata02 ) DO @(
  RD /S/Q "%%G" >NUL 2>&1
    )
  IF EXIST sys32appdata02 (
    "%GREP%" -c "." <sys32appdata02 >sys32appdata09
    FOR /F "TOKENS=*" %%H IN ( sys32appdata09 ) DO @(
      ECHO.%WINDIR%\ServiceProfiles\LocalService\AppData\Local\D3DSCache ^(%%H^)>>"%TEMP%\001b"
      )
  )
)
:D3DSCache3
IF EXIST "%SYS32%\config\systemprofile\AppData\Local\D3DSCache" DIR /B/S/A:D "%SYS32%\config\systemprofile\AppData\Local\D3DSCache" 2>NUL>sys32appdata00
IF EXIST "%SYS32%\config\systemprofile\AppData\Local\D3DSCache" (
  "%GREP%" -Esi "\\[a-f0-9]{10,}$" <sys32appdata00 >sys32appdata01
  "%SORT%" -f -u <sys32appdata01 >sys32appdata02
  FOR /F "TOKENS=*" %%G IN ( sys32appdata02 ) DO @(
  RD /S/Q "%%G" >NUL 2>&1
    )
  IF EXIST sys32appdata02 (
    "%GREP%" -c "." <sys32appdata02 >sys32appdata09
    FOR /F "TOKENS=*" %%H IN ( sys32appdata09 ) DO @(
      ECHO.%SYS32%\config\systemprofile\AppData\Local\D3DSCache ^(%%H^)>>"%TEMP%\001b"
      )
  )
)
:Slobs
IF EXIST "%APPDATA%\slobs-client\partitions" DIR /B/S/A:-D "%APPDATA%\slobs-client\partitions" 2>NUL>appdata00
IF EXIST "%APPDATA%\slobs-client\partitions" (
"%GREP%" -Esi "\\[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\\Cache\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <appdata00 >appdata01
"%SORT%" -f -u <appdata01 >appdata02
FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  ECHO.%%G>>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  )
)
:Twtmp
IF EXIST "%SYS32%\config\systemprofile\AppData\Local" DIR /B/S/A:D "%SYS32%\config\systemprofile\AppData\Local" 2>NUL>sys32appdata00
IF EXIST "%SYS32%\config\systemprofile\AppData\Local" (
  "%GREP%" -Esi "\\tw-[a-f0-9]{2,}-[a-f0-9]{2,}-[a-f0-9]{2,}\.tmp$" <sys32appdata00 >sys32appdata01
  "%SORT%" -f -u <sys32appdata01 >sys32appdata02
  FOR /F "TOKENS=*" %%G IN ( sys32appdata02 ) DO @(
  RD /S/Q "%%G" >NUL 2>&1
    )
  IF EXIST sys32appdata02 (
    "%GREP%" -c "." <sys32appdata02 >sys32appdata09
    FOR /F "TOKENS=*" %%H IN ( sys32appdata09 ) DO @(
      ECHO.%SYS32%\config\systemprofile\AppData\Local ^(%%H^)>>"%TEMP%\001b"
      )
  )
)
:JavaCache
IF EXIST "%LOCALLOW%\Sun\Java\Deployment\cache" DIR /B/S/A:-D "%LOCALLOW%\Sun\Java\Deployment\cache" 2>NUL>locallow00
IF EXIST "%LOCALLOW%\Sun\Java\Deployment\cache" (
  "%GREP%" -Esi "\\cache\\[0-9]\.[0-9]\\[0-9]{2,}\\[a-f0-9]{8,}-[a-f0-9]{8,}$" <locallow00 >locallow01
  "%SORT%" -f -u <locallow01 >locallow02
  FOR /F "TOKENS=*" %%G IN ( locallow02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locallow02 (
    "%GREP%" -c "." <locallow02 >locallow09
    FOR /F "TOKENS=*" %%H IN ( locallow09 ) DO @(
      ECHO.%LOCALLOW%\Sun\Java\Deployment\cache ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:INetCache
IF EXIST "%LOCALA%\Microsoft\Windows\INetCache\IE" DIR /B/S/A:D "%LOCALA%\Microsoft\Windows\INetCache\IE" 2>NUL>locala00
IF EXIST "%LOCALA%\Microsoft\Windows\INetCache\IE" (
  "%GREP%" -Es "\\[A-Z0-9]{8}$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  RD /S/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Microsoft\Windows\INetCache\IE ^(%%H^)>>"%TEMP%\001b"
      )
  )
)
:ChromeCache
IF EXIST "%LOCALA%\Google\Chrome\User Data\Default\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Google\Chrome\User Data\Default\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Google\Chrome\User Data\Default\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Google\Chrome\User Data\Default\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ChromeCache2
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 1\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Google\Chrome\User Data\Profile 1\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 1\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Google\Chrome\User Data\Profile 1\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ChromeCache3
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 2\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Google\Chrome\User Data\Profile 2\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 2\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Google\Chrome\User Data\Profile 2\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ChromeCacheCode
IF EXIST "%LOCALA%\Google\Chrome\User Data\Default\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Google\Chrome\User Data\Default\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Google\Chrome\User Data\Default\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Google\Chrome\User Data\Default\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ChromeCacheCode2
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 1\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Google\Chrome\User Data\Profile 1\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 1\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Google\Chrome\User Data\Profile 1\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ChromeCacheCode3
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 2\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Google\Chrome\User Data\Profile 2\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Google\Chrome\User Data\Profile 2\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Google\Chrome\User Data\Profile 2\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:EdgeCache
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Default\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Microsoft\Edge\User Data\Default\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Default\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Microsoft\Edge\User Data\Default\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:EdgeCache2
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Microsoft\Edge\User Data\Profile 1\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:EdgeCache3
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Microsoft\Edge\User Data\Profile 2\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:EdgeCacheCode
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Default\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Microsoft\Edge\User Data\Default\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Default\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Microsoft\Edge\User Data\Default\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:EdgeCacheCode2
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Microsoft\Edge\User Data\Profile 1\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:EdgeCacheCode3
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Microsoft\Edge\User Data\Profile 2\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:BraveCache
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:BraveCache2
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:BraveCache3
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:BraveCacheCode
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:BraveCacheCode2
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:BraveCacheCode3
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:YandexCache
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Yandex\YandexBrowser\User Data\Default\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:YandexCache2
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:YandexCache3
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:YandexCacheCode
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Yandex\YandexBrowser\User Data\Default\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:YandexCacheCode2
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:YandexCacheCode3
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:VivaldiCache
IF EXIST "%LOCALA%\Vivaldi\User Data\Default\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Vivaldi\User Data\Default\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Vivaldi\User Data\Default\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Vivaldi\User Data\Default\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:VivaldiCache2
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 1\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Vivaldi\User Data\Profile 1\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 1\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Vivaldi\User Data\Profile 1\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:VivaldiCache3
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 2\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Vivaldi\User Data\Profile 2\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 2\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Vivaldi\User Data\Profile 2\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:VivaldiCacheCode
IF EXIST "%LOCALA%\Vivaldi\User Data\Default\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Vivaldi\User Data\Default\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Vivaldi\User Data\Default\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Vivaldi\User Data\Default\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:VivaldiCacheCode2
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 1\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Vivaldi\User Data\Profile 1\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 1\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Vivaldi\User Data\Profile 1\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:VivaldiCacheCode3
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 2\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Vivaldi\User Data\Profile 2\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Vivaldi\User Data\Profile 2\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Vivaldi\User Data\Profile 2\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ComodoCache
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Default\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Comodo\Dragon\User Data\Default\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Default\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Comodo\Dragon\User Data\Default\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ComodoCache2
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Comodo\Dragon\User Data\Profile 1\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ComodoCache3
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Cache\Cache_Data" DIR /B/S/A:-D "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Cache\Cache_Data" 2>NUL>locala00
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Comodo\Dragon\User Data\Profile 2\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ComodoCacheCode
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Default\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Comodo\Dragon\User Data\Default\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Default\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Comodo\Dragon\User Data\Default\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ComodoCacheCode2
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Comodo\Dragon\User Data\Profile 1\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:ComodoCacheCode3
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Code Cache\js" DIR /B/S/A:-D "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Code Cache\js" 2>NUL>locala00
IF EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Comodo\Dragon\User Data\Profile 2\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
REM Opera browser doesn't seem to have the Cache\Cache_Data folder
:OperaCacheCode
IF EXIST "%APPDATA%\Opera Software\Opera Stable\Default\Code Cache\js" DIR /B/S/A:-D "%APPDATA%\Opera Software\Opera Stable\Default\Code Cache\js" 2>NUL>appdata00
IF EXIST "%APPDATA%\Opera Software\Opera Stable\Default\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\Opera Software\Opera Stable\Default\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:OperaCacheCode2
IF EXIST "%APPDATA%\Opera Software\Opera Stable\Profile 1\Code Cache\js" DIR /B/S/A:-D "%APPDATA%\Opera Software\Opera Stable\Profile 1\Code Cache\js" 2>NUL>appdata00
IF EXIST "%APPDATA%\Opera Software\Opera Stable\Profile 1\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\Opera Software\Opera Stable\Profile 1\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:OperaCacheCode3
IF EXIST "%APPDATA%\Opera Software\Opera Stable\Profile 2\Code Cache\js" DIR /B/S/A:-D "%APPDATA%\Opera Software\Opera Stable\Profile 2\Code Cache\js" 2>NUL>appdata00
IF EXIST "%APPDATA%\Opera Software\Opera Stable\Profile 2\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\Opera Software\Opera Stable\Profile 2\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:FireFoxCache
IF EXIST "%LOCALA%\Mozilla\Firefox\Profiles" DIR /B/S/A:-D "%LOCALA%\Mozilla\Firefox\Profiles" 2>NUL>locala00
IF EXIST "%LOCALA%\Mozilla\Firefox\Profiles" (
  "%GREP%" -Esi "\\cache2\\entries\\[A-F0-9]{40}$" <locala00 >locala01
  "%SORT%" -f -u <locala01 >locala02
  FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST locala02 (
    "%GREP%" -c "." <locala02 >locala09
    FOR /F "TOKENS=*" %%H IN ( locala09 ) DO @(
      ECHO.%LOCALA%\Mozilla\Firefox\Profiles\^<Profile^>\cache2\entries ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:FireFoxCacheShader
IF EXIST "%APPDATA%\Mozilla\Firefox\Profiles" DIR /B/S/A:-D "%APPDATA%\Mozilla\Firefox\Profiles" 2>NUL>appdata00
IF EXIST "%APPDATA%\Mozilla\Firefox\Profiles" (
  "%GREP%" -Esi "\\shader-cache\\[a-f0-9]{16}$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\Mozilla\Firefox\Profiles\^<Profile^>\shader-cache ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:WireCache
IF EXIST "%APPDATA%\Wire\Cache\Cache_Data" DIR /B/S/A:-D "%APPDATA%\Wire\Cache\Cache_Data" 2>NUL>appdata00
IF EXIST "%APPDATA%\Wire\Cache\Cache_Data" (
  "%GREP%" -Esi "\\Cache_Data\\(f_[a-f0-9]{6,}|data_[0-9]|index)$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\Wire\Cache\Cache_Data ^(%%H^)>>"%TEMP%\001"
      )
  )
)
:WireCacheCode
IF EXIST "%APPDATA%\Wire\Code Cache\js" DIR /B/S/A:-D "%APPDATA%\Wire\Code Cache\js" 2>NUL>appdata00
IF EXIST "%APPDATA%\Wire\Code Cache\js" (
  "%GREP%" -Esi "\\js\\([a-f0-9]{16,}_0|index)$" <appdata00 >appdata01
  "%SORT%" -f -u <appdata01 >appdata02
  FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  DEL /F/Q "%%G" >NUL 2>&1
    )
  IF EXIST appdata02 (
    "%GREP%" -c "." <appdata02 >appdata09
    FOR /F "TOKENS=*" %%H IN ( appdata09 ) DO @(
      ECHO.%APPDATA%\Wire\Code Cache\js ^(%%H^)>>"%TEMP%\001"
      )
  )
)

:GetDumps
IF EXIST "%LOCALA%\CrashDumps" DIR /B/S/A:-D "%LOCALA%\CrashDumps" 2>NUL>"%TEMP%\cdumps00"
IF EXIST "%SYS32%\config\systemprofile\AppData\Local\CrashDumps" DIR /B/S/A:-D "%SYS32%\config\systemprofile\AppData\Local\CrashDumps" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%WINDIR%\Minidump" DIR /B/S/A:-D "%WINDIR%\Minidump" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%USERPROFILE%\Desktop" DIR /B/S/A:-D "%USERPROFILE%\Desktop\Malwarebytes Scan Report 2025-??-?? ??????.txt" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%USERPROFILE%\Desktop" DIR /B/S/A:-D "%USERPROFILE%\Desktop\Malwarebytes Relatório de análise 2025-??-?? ??????.txt" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%USERPROFILE%\OneDrive\Desktop" DIR /B/S/A:-D "%USERPROFILE%\OneDrive\Desktop\Malwarebytes Scan Report 2025-??-?? ??????.txt" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%ALLUSERSPROFILE%\HitmanPro\Logs" DIR /B/S/A:-D "%ALLUSERSPROFILE%\HitmanPro\Logs\HitmanPro_2025????_????.log" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%SYSTEMDRIVE%\FRST\Quarantine" DIR /B/S/A:-D "%SYSTEMDRIVE%\FRST\Quarantine" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%SYSTEMDRIVE%\DrWeb Quarantine" DIR /B/S/A:-D "%SYSTEMDRIVE%\DrWeb Quarantine" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\quickSuper_debug" DIR /B/S/A:-D "%APPDATA%\quickSuper_debug" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\quickhostPs" DIR /B/S/A:-D "%APPDATA%\quickhostPs" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\PowerAdvanced_dbg" DIR /B/S/A:-D "%APPDATA%\PowerAdvanced_dbg" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\soAuth" DIR /B/S/A:-D "%APPDATA%\soAuth" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\hostmon" DIR /B/S/A:-D "%APPDATA%\hostmon" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\Launchvalidate_debug_v1" DIR /B/S/A:-D "%APPDATA%\Launchvalidate_debug_v1" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\UltraDaemon_xkn" DIR /B/S/A:-D "%APPDATA%\UltraDaemon_xkn" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%ALLUSERSPROFILE%\GoogleUP" DIR /B/S/A:-D "%ALLUSERSPROFILE%\GoogleUP" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\backupvalid_alpha" DIR /B/S/A:-D "%APPDATA%\backupvalid_alpha" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%ALLUSERSPROFILE%\Watcherpatch_Mnm" DIR /B/S/A:-D "%ALLUSERSPROFILE%\Watcherpatch_Mnm" 2>NUL>>"%TEMP%\cdumps00"
IF EXIST "%APPDATA%\ScanAuthBg_alpha_5" DIR /B/S/A:-D "%APPDATA%\ScanAuthBg_alpha_5" 2>NUL>>"%TEMP%\cdumps00"

:Rootkits

:Files
     
:Files2
DIR /B/A:-D "%ALLUSERSPROFILE%" 2>NUL>allusersprofile00
DIR /B/A:-D "%APPDATA%" 2>NUL>appdata00
DIR /B/A:-D "%USERPROFILE%\AppData" 2>NUL>userprofileappdata00
DIR /B/A:-D "%LOCALA%" 2>NUL>locala00
DIR /B/A:-D "%LOCALLOW%" 2>NUL>locallow00
DIR /B/A:-D "%STARTUP%" 2>NUL>startup00
DIR /B/A:-D "%SYS32%\config\systemprofile\AppData" 2>NUL>sys32appdata00
DIR /B/A:-D "%COMMON32%" 2>NUL>common3200
DIR /B/A:-D "%PROGFILES32%" 2>NUL>programfiles3200
IF EXIST "%PROGFILES64%" DIR /B/A:-D "%PROGFILES64%" 2>NUL>programfiles6400
IF EXIST "%COMMON64%" DIR /B/A:-D "%COMMON64%" 2>NUL>common6400
IF EXIST "%WINDIR%\SysWOW64" DIR /B/A:-D "%WINDIR%\SysWOW64" 2>NUL>SysWOW6400
IF EXIST "%WTASKS%" DIR /B/A:-D "%WTASKS%\*.job" 2>NUL>WTASKS00

REM ~~~~~ %ALLUSERSPROFILE% SEARCH ~~~~~~~~~
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dat|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <allusersprofile00 >allusersprofile01
"%GREP%" -Esi "\.[0-9]{9,}\.bdinstall\.v2\.bin$" <allusersprofile00 >>allusersprofile01
"%GREP%" -Es "^[a-z]{3}(_ver)?$" <allusersprofile00 >>allusersprofile01
"%GREP%" -Es "^[a-z]{8}\.[a-z]{3}$" <allusersprofile00 >allusersprofile09
"%GREP%" -Evs "^[a-z]{8}\.(txt|reg|doc|pdf|rtf|xls|rar|csv|key)$" <allusersprofile09 >>allusersprofile01
"%SORT%" -f -u <allusersprofile01 >allusersprofile02
FOR /F "TOKENS=*" %%G IN ( allusersprofile02 ) DO @(
  ATTRIB -R -A -S -H "%ALLUSERSPROFILE%\%%G" >NUL 2>&1
  ECHO.%ALLUSERSPROFILE%\%%G>>"%TEMP%\001"
  DEL /F/Q "%ALLUSERSPROFILE%\%%G" >NUL 2>&1
  IF EXIST "%ALLUSERSPROFILE%\%%G" (
    ICACLS "%ALLUSERSPROFILE%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%ALLUSERSPROFILE%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%ALLUSERSPROFILE%\%%G" >NUL 2>&1
    )
)

DIR /B "%ALLUSERSPROFILE%\Microsoft\DRM" 2>NUL|"%GREP%" -Eis "^[A-Z0-9]{12,13}$">redline00
IF ERRORLEVEL 1 GOTO :NetFrameWorkChk
FOR /F "TOKENS=*" %%G IN ( redline00 ) DO @(
  ATTRIB -R -A -S -H "%ALLUSERSPROFILE%\Microsoft\DRM\%%G" >NUL 2>&1
  DIR /B/S/A:-D "%ALLUSERSPROFILE%\Microsoft\DRM\%%G" 2>NUL>>redline01
  )

"%GREP%" -Es "\\ProgramData\\Microsoft\\DRM\\[A-Za-z0-9]{12,13}\\[A-Z][a-z]{3,}[A-Z][a-z]{3,}[A-Z]\.bat$" <redline01 >redline02
IF ERRORLEVEL 1 GOTO :NetFrameWorkChk
"%SORT%" -f -u <redline02 >redline03
DEL /F/Q redline00 redline01 redline02 >NUL 2>&1
FOR /F "TOKENS=*" %%G IN ( redline03 ) DO @(
  ATTRIB -R -A -S -H "%%G" >NUL 2>&1
  ECHO.%%G>>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  IF EXIST "%%G" (
    ICACLS "%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%%G" >NUL 2>&1
    )
)

:NetFrameWorkChk
DIR /B "%ALLUSERSPROFILE%\Microsoft\NetFramework" 2>NUL|"%GREP%" -Eis "^[A-Z0-9]{12,13}$">redline00
IF ERRORLEVEL 1 GOTO :AllUsersTools
FOR /F "TOKENS=*" %%G IN ( redline00 ) DO @(
  ATTRIB -R -A -S -H "%ALLUSERSPROFILE%\Microsoft\NetFramework\%%G" >NUL 2>&1
  DIR /B/S/A:-D "%ALLUSERSPROFILE%\Microsoft\NetFramework\%%G" 2>NUL>>redline01
  )

"%GREP%" -Es "\\ProgramData\\Microsoft\\NetFramework\\[A-Za-z0-9]{12,13}\\[A-Z][a-z]{3,}[A-Z][a-z]{3,}[A-Z]\.bat$" <redline01 >redline02
IF ERRORLEVEL 1 GOTO :AllUsersTools
"%SORT%" -f -u <redline02 >redline03
DEL /F/Q redline00 redline01 redline02 >NUL 2>&1
FOR /F "TOKENS=*" %%G IN ( redline03 ) DO @(
  ATTRIB -R -A -S -H "%%G" >NUL 2>&1
  ECHO.%%G>>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  IF EXIST "%%G" (
    ICACLS "%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%%G" >NUL 2>&1
    )
)

:AllUsersTools
DIR /B/A:-D "%ALLUSERSPROFILE%\Microsoft\Windows\Tools" 2>NUL|"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$">allusersprofile00
"%SORT%" -f -u <allusersprofile00 >allusersprofile01
FOR /F "TOKENS=*" %%G IN ( allusersprofile01 ) DO @(
  ATTRIB -R -A -S -H "%ALLUSERSPROFILE%\Microsoft\Windows\Tools\%%G" >NUL 2>&1
  ECHO.%ALLUSERSPROFILE%\Microsoft\Windows\Tools\%%G>>"%TEMP%\001"
  DEL /F/Q "%ALLUSERSPROFILE%\Microsoft\Windows\Tools\%%G" >NUL 2>&1
  IF EXIST "%ALLUSERSPROFILE%\Microsoft\Windows\Tools\%%G" (
    ICACLS "%ALLUSERSPROFILE%\Microsoft\Windows\Tools\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%ALLUSERSPROFILE%\Microsoft\Windows\Tools\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%ALLUSERSPROFILE%\Microsoft\Windows\Tools\%%G" >NUL 2>&1
    )
)

:Redline1
DIR /B/A:D "%ALLUSERSPROFILE%\????????????" 2>NUL|"%GREP%" -Es "^[a-z]{12}$">redline00
IF ERRORLEVEL 1 GOTO :Redline2
FOR /F "TOKENS=*" %%G IN ( redline00 ) DO @(
  ATTRIB -R -A -S -H "%ALLUSERSPROFILE%\%%G" >NUL 2>&1
  DIR /B/S/A:-D "%ALLUSERSPROFILE%\%%G" 2>NUL>>redline01
  )

"%GREP%" -Es "\\ProgramData\\[a-z]{12}\\[a-z]{12}\.exe$" <redline01 >redline02
IF ERRORLEVEL 1 GOTO :Redline2
"%SORT%" -f -u <redline02 >redline03
DEL /F/Q redline00 redline01 redline02 >NUL 2>&1
FOR /F "TOKENS=*" %%G IN ( redline03 ) DO @(
  ATTRIB -R -A -S -H "%%G" >NUL 2>&1
  ECHO.%%G>>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  IF EXIST "%%G" (
    ICACLS "%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%%G" >NUL 2>&1
    )
)

:Redline2
DIR /B/A:D "%APPDATA%\????????????" 2>NUL|"%GREP%" -Es "^[a-z]{12}$">redline00
IF ERRORLEVEL 1 GOTO :Appdata
FOR /F "TOKENS=*" %%G IN ( redline00 ) DO @(
  ATTRIB -R -A -S -H "%ALLUSERSPROFILE%\%%G" >NUL 2>&1
  DIR /B/S/A:-D "%APPDATA%\%%G" 2>NUL>>redline01
  )


"%GREP%" -Es "\\Roaming\\[a-z]{12}\\[a-z]{12}\.exe$" <redline01 >redline02
IF ERRORLEVEL 1 GOTO :Appdata
"%SORT%" -f -u <redline02 >redline03
DEL /F/Q redline00 redline01 redline02 >NUL 2>&1
FOR /F "TOKENS=*" %%G IN ( redline03 ) DO @(
  ATTRIB -R -A -S -H "%%G" >NUL 2>&1
  ECHO.%%G>>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  IF EXIST "%%G" (
    ICACLS "%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%%G" >NUL 2>&1
    )
)

:Appdata
REM ~~~~~ %APPDATA% SEARCH ~~~~~~~~~
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dat|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <appdata00 >appdata01
"%GREP%" -Es "^[a-f0-9]{32}(thumb)?$|^Default(Album|Artist|Playlist|Track)Art\.png$" <appdata00 >>appdata01
"%GREP%" -Es "^[a-z]{8}\.[a-z]{3}$" <appdata00 >appdata09
"%GREP%" -Evs "^[a-z]{8}\.(txt|reg|doc|pdf|rtf|xls|rar|csv|key)$" <appdata09 >>appdata01
"%SORT%" -f -u <appdata01 >appdata02
FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  ATTRIB -R -A -S -H "%APPDATA%\%%G" >NUL 2>&1
  ECHO.%APPDATA%\%%G>>"%TEMP%\001"
  DEL /F/Q "%APPDATA%\%%G" >NUL 2>&1
  IF EXIST "%APPDATA%\%%G" (
    ICACLS "%APPDATA%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%APPDATA%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%APPDATA%\%%G" >NUL 2>&1
    )
)

DIR /B/A:-D "%APPDATA%\Microsoft" 2>NUL>appdata00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <appdata00 >appdata01
"%GREP%" -Esi "^\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}?$" <appdata00 >>appdata01
"%SORT%" -f -u <appdata01 >appdata02
FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  ATTRIB -R -A -S -H "%APPDATA%\Microsoft\%%G" >NUL 2>&1
  ECHO.%APPDATA%\Microsoft\%%G>>"%TEMP%\001"
  DEL /F/Q "%APPDATA%\Microsoft\%%G" >NUL 2>&1
  IF EXIST "%APPDATA%\Microsoft\%%G" (
    ICACLS "%APPDATA%\Microsoft\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%APPDATA%\Microsoft\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%APPDATA%\Microsoft\%%G" >NUL 2>&1
    )
)

DIR /B/A:-D "%APPDATA%\Microsoft\Templates" 2>NUL>appdata00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <appdata00 >appdata01
"%SORT%" -f -u <appdata01 >appdata02
FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  ATTRIB -R -A -S -H "%APPDATA%\Microsoft\Templates\%%G" >NUL 2>&1
  ECHO.%APPDATA%\Microsoft\Templates\%%G>>"%TEMP%\001"
  DEL /F/Q "%APPDATA%\Microsoft\Templates\%%G" >NUL 2>&1
  IF EXIST "%APPDATA%\Microsoft\Templates\%%G" (
    ICACLS "%APPDATA%\Microsoft\Templates\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%APPDATA%\Microsoft\Templates\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%APPDATA%\Microsoft\Templates\%%G" >NUL 2>&1
    )
)

DIR /B/A:-D "%APPDATA%\Microsoft\Protect" 2>NUL>appdata00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <appdata00 >appdata01
"%SORT%" -f -u <appdata01 >appdata02
FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  ATTRIB -R -A -S -H "%APPDATA%\Microsoft\Protect\%%G" >NUL 2>&1
  ECHO.%APPDATA%\Microsoft\Protect\%%G>>"%TEMP%\001"
  DEL /F/Q "%APPDATA%\Microsoft\Protect\%%G" >NUL 2>&1
  IF EXIST "%APPDATA%\Microsoft\Protect\%%G" (
    ICACLS "%APPDATA%\Microsoft\Protect\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%APPDATA%\Microsoft\Protect\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%APPDATA%\Microsoft\Protect\%%G" >NUL 2>&1
    )
)

REM Remove-MpPreference -ExclusionPath ""
IF EXIST "%APPDATA%\Kryptex" DIR /B/S/A:-D "%APPDATA%\Kryptex" 2>NUL>appdata00
IF EXIST "%APPDATA%\Kryptex" (
"%GREP%" -Esi "\\miners\\kryptex[0-9]{1,}\\kryptex[0-9]{1,}\.exe$" <appdata00 >appdata01
"%GREP%" -Esi "\\miners\.(7z|zip|rar|sfx)$" <appdata00 >>appdata01
"%SORT%" -f -u <appdata01 >appdata02
FOR /F "TOKENS=*" %%G IN ( appdata02 ) DO @(
  ATTRIB -R -A -S -H "%%G" >NUL 2>&1
  ECHO."%%G">>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  IF EXIST "%%G" (
    ICACLS "%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%%G" >NUL 2>&1
    )
  )
)

REM ~~~~~ %USERPROFILE%\AppData SEARCH ~~~~~~~~~
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <userprofileappdata00 >userprofileappdata01
"%SORT%" -f -u <userprofileappdata01 >userprofileappdata02
FOR /F "TOKENS=*" %%G IN ( userprofileappdata02 ) DO @(
  ATTRIB -R -A -S -H "%USERPROFILE%\AppData\%%G" >NUL 2>&1
  ECHO.%USERPROFILE%\AppData\%%G>>"%TEMP%\001"
  DEL /F/Q "%USERPROFILE%\AppData\%%G" >NUL 2>&1
  IF EXIST "%USERPROFILE%\AppData\%%G" (
    ICACLS "%USERPROFILE%\AppData\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%USERPROFILE%\AppData\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%USERPROFILE%\AppData\%%G" >NUL 2>&1
    )
)

REM ~~~~~ %LOCALA% SEARCH ~~~~~~~~~ C:\Users\PC\AppData\Local\FjtzgjmbwgTrEnsABJVLEEMVkUjva (29)
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <locala00 >locala01
"%GREP%" -Esi "^([0-9]{8,}|[0-9a-f]{32}|\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}?)$" <locala00 >>locala01
"%GREP%" -Es "^[A-F0-9]{32}$" <locala00 >>locala01
"%SORT%" -f -u <locala01 >locala02
FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  ATTRIB -R -A -S -H "%LOCALA%\%%G" >NUL 2>&1
  ECHO.%LOCALA%\%%G>>"%TEMP%\001"
  DEL /F/Q "%LOCALA%\%%G" >NUL 2>&1
  IF EXIST "%LOCALA%\%%G" (
    ICACLS "%LOCALA%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%LOCALA%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%LOCALA%\%%G" >NUL 2>&1
    )
)

IF EXIST "%LOCALA%\Apps\2.0" DIR /B/S/A:-D "%LOCALA%\Apps\2.0" 2>NUL>locala00
IF EXIST "%LOCALA%\Apps\2.0" (
"%GREP%" -Esi "\\ScreenConnect\.(ClientService|WindowsBackstageShell|WindowsFileManager|WindowsClient)\.exe$" <locala00 >locala01
"%GREP%" -Esi "\\ScreenConnect\.(Client(Service)?|Core|Windows)\.dll$" <locala00 >>locala01
"%SORT%" -f -u <locala01 >locala02
FOR /F "TOKENS=*" %%G IN ( locala02 ) DO @(
  ECHO."%%G">>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  IF EXIST "%%G" (
    ICACLS "%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%%G" >NUL 2>&1
    )
  )
)

DIR /B/A:D "%LOCALA%\.???????????" 2>NUL|"%GREP%" -Esi "^\.[A-Z0-9]{10}$">python00
IF ERRORLEVEL 1 GOTO :LocalLow
FOR /F "TOKENS=*" %%G IN ( python00 ) DO @(
  ATTRIB -R -A -S -H "%LOCALA%\%%G" >NUL 2>&1
  DIR /B/S/A:-D "%LOCALA%\%%G" 2>NUL>>python01
  )

"%GREP%" -Eis "\\Local\\\.[A-Z0-9]{10}\\[A-Z0-9]{10}\.py$" <python01 >python02
IF ERRORLEVEL 1 GOTO :LocalLow
"%SORT%" -f -u <python02 >python03
DEL /F/Q python00 python01 python02 >NUL 2>&1
FOR /F "TOKENS=*" %%G IN ( python03 ) DO @(
  ATTRIB -R -A -S -H "%%G" >NUL 2>&1
  ECHO.%%G>>"%TEMP%\001"
  DEL /F/Q "%%G" >NUL 2>&1
  IF EXIST "%%G" (
    ICACLS "%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%%G" >NUL 2>&1
    )
)

:LocalLow
REM ~~~~~ %LOCALLOW% SEARCH ~~~~~~~~~
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <locallow00 >locallow01
"%GREP%" -Esi "^[a-f0-9]{64}$" <locallow00 >>locallow01
"%GREP%" -Esi "^DeviceId=[A-F0-9]{4}_DeviceRevisionId" <locallow00 >>locallow01
"%SORT%" -f -u <locallow01 >locallow02
FOR /F "TOKENS=*" %%G IN ( locallow02 ) DO @(
  ATTRIB -R -A -S -H "%LOCALLOW%\%%G" >NUL 2>&1
  ECHO.%LOCALLOW%\%%G>>"%TEMP%\001"
  DEL /F/Q "%LOCALLOW%\%%G" >NUL 2>&1
  IF EXIST "%LOCALLOW%\%%G" (
    ICACLS "%LOCALLOW%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%LOCALLOW%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%LOCALLOW%\%%G" >NUL 2>&1
    )
)

REM ~~~~~ %STARTUP% SEARCH ~~~~~~~~~ 
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|url|vb[e|s])$" <startup00 >startup01
"%GREP%" -Esi "^[a-z0-9_.-]{1,}\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])\.lnk$" <startup00 >>startup01
"%SORT%" -f -u <startup01 >startup02
FOR /F "TOKENS=*" %%G IN ( startup02 ) DO @(
  ATTRIB -R -A -S -H "%STARTUP%\%%G" >NUL 2>&1
  ECHO.%STARTUP%\%%G>>"%TEMP%\001"
  DEL /F/Q "%STARTUP%\%%G" >NUL 2>&1
  IF EXIST "%STARTUP%\%%G" (
    ICACLS "%STARTUP%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%STARTUP%\%%G" >NUL 2>&1
    )
)

REM ~~~~~ %PROGFILES32% SEARCH ~~~~~~~~~ 
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles3200 >programfiles3201
"%SORT%" -f -u <programfiles3201 >programfiles3202
FOR /F "TOKENS=*" %%G IN ( programfiles3202 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\%%G" (
    ICACLS "%PROGFILES32%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\%%G" >NUL 2>&1
    )
)

IF EXIST "%PROGFILES32%\Google" DIR /B/A:-D "%PROGFILES32%\Google" 2>NUL>programfiles3200
IF EXIST "%PROGFILES32%\Google" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles3200 >programfiles3201
"%SORT%" -f -u <programfiles3201 >programfiles3202
FOR /F "TOKENS=*" %%G IN ( programfiles3202 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\Google\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\Google\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\Google\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\Google\%%G" (
    ICACLS "%PROGFILES32%\Google\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\Google\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\Google\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES32%\Windows NT" DIR /B/A:-D "%PROGFILES32%\Windows NT" 2>NUL>programfiles3200
IF EXIST "%PROGFILES32%\Windows NT" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles3200 >programfiles3201
"%SORT%" -f -u <programfiles3201 >programfiles3202
FOR /F "TOKENS=*" %%G IN ( programfiles3202 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\Windows NT\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\Windows NT\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\Windows NT\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\Windows NT\%%G" (
    ICACLS "%PROGFILES32%\Windows NT\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\Windows NT\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\Windows NT\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES32%\Internet Explorer" DIR /B/A:-D "%PROGFILES32%\Internet Explorer" 2>NUL>programfiles3200
IF EXIST "%PROGFILES32%\Internet Explorer" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles3200 >programfiles3201
"%GREP%" -Evsi "^(ExtExport|iediagcmd|ieinstal|ielowutil|iexplore)\.exe$|^(hmmapi|IEShims|sqmapi)\.dll$" <programfiles3201 >programfiles3202
"%SORT%" -f -u <programfiles3202 >programfiles3203
FOR /F "TOKENS=*" %%G IN ( programfiles3203 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\Internet Explorer\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\Internet Explorer\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\Internet Explorer\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\Internet Explorer\%%G" (
    ICACLS "%PROGFILES32%\Internet Explorer\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\Internet Explorer\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\Internet Explorer\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES32%\Mozilla Firefox" DIR /B/A:-D "%PROGFILES32%\Mozilla Firefox" 2>NUL>programfiles3200
IF EXIST "%PROGFILES32%\Mozilla Firefox" (
"%GREP%" -Esi "^kl_(prefs|config)_[a-f0-9]{8,}[_.-][a-f0-9]{4,}[_.-][a-f0-9]{4,}[_.-][a-f0-9]{4,}[_.-][a-f0-9]{8,}[_.-](js|cfg)$" <programfiles3200 >programfiles3201
"%SORT%" -f -u <programfiles3201 >programfiles3202
FOR /F "TOKENS=*" %%G IN ( programfiles3202 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\Mozilla Firefox\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\Mozilla Firefox\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\Mozilla Firefox\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\Mozilla Firefox\%%G" (
    ICACLS "%PROGFILES32%\Mozilla Firefox\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\Mozilla Firefox\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\Mozilla Firefox\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES32%\Windows Sidebar" DIR /B/A:-D "%PROGFILES32%\Windows Sidebar" 2>NUL>programfiles3200
IF EXIST "%PROGFILES32%\Windows Sidebar" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles3200 >programfiles3201
"%SORT%" -f -u <programfiles3201 >programfiles3202
FOR /F "TOKENS=*" %%G IN ( programfiles3202 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\Windows Sidebar\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\Windows Sidebar\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\Windows Sidebar\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\Windows Sidebar\%%G" (
    ICACLS "%PROGFILES32%\Windows Sidebar\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\Windows Sidebar\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\Windows Sidebar\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES32%\Windows Sidebar\Gadgets" DIR /B/A:-D "%PROGFILES32%\Windows Sidebar\Gadgets" 2>NUL>programfiles3200
IF EXIST "%PROGFILES32%\Windows Sidebar\Gadgets" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles3200 >programfiles3201
"%SORT%" -f -u <programfiles3201 >programfiles3202
FOR /F "TOKENS=*" %%G IN ( programfiles3202 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\Windows Sidebar\Gadgets\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\Windows Sidebar\Gadgets\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\Windows Sidebar\Gadgets\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\Windows Sidebar\Gadgets\%%G" (
    ICACLS "%PROGFILES32%\Windows Sidebar\Gadgets\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\Windows Sidebar\Gadgets\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\Windows Sidebar\Gadgets\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES32%\Windows Sidebar\Shared Gadgets" DIR /B/A:-D "%PROGFILES32%\Windows Sidebar\Shared Gadgets" 2>NUL>programfiles3200
IF EXIST "%PROGFILES32%\Windows Sidebar\Shared Gadgets" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles3200 >programfiles3201
"%SORT%" -f -u <programfiles3201 >programfiles3202
FOR /F "TOKENS=*" %%G IN ( programfiles3202 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES32%\Windows Sidebar\Shared Gadgets\%%G" >NUL 2>&1
  ECHO.%PROGFILES32%\Windows Sidebar\Shared Gadgets\%%G>>"%TEMP%\001"
  DEL /F/Q "%PROGFILES32%\Windows Sidebar\Shared Gadgets\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES32%\Windows Sidebar\Shared Gadgets\%%G" (
    ICACLS "%PROGFILES32%\Windows Sidebar\Shared Gadgets\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES32%\Windows Sidebar\Shared Gadgets\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES32%\Windows Sidebar\Shared Gadgets\%%G" >NUL 2>&1
    )
  )
)

REM ~~~~~ %sys32appdata% SEARCH ~~~~~~~~~
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <sys32appdata00 >sys32appdata01
"%SORT%" -f -u <sys32appdata01 >sys32appdata02
FOR /F "TOKENS=*" %%G IN ( sys32appdata02 ) DO @(
  ATTRIB -R -A -S -H "%SYS32%\config\systemprofile\AppData\%%G" >NUL 2>&1
  ECHO.%SYS32%\config\systemprofile\AppData\%%G>>"%TEMP%\001"
  DEL /F/Q "%SYS32%\config\systemprofile\AppData\%%G" >NUL 2>&1
  IF EXIST "%SYS32%\config\systemprofile\AppData\%%G" (
    ICACLS "%SYS32%\config\systemprofile\AppData\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%SYS32%\config\systemprofile\AppData\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%SYS32%\config\systemprofile\AppData\%%G" >NUL 2>&1
    )
)

DIR /B/A:-D "%SYS32%\config\systemprofile\AppData\Local" 2>NUL>sys32appdata00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <sys32appdata00 >sys32appdata01
"%SORT%" -f -u <sys32appdata01 >sys32appdata02
FOR /F "TOKENS=*" %%G IN ( sys32appdata02 ) DO @(
  ATTRIB -R -A -S -H "%SYS32%\config\systemprofile\AppData\Local\%%G" >NUL 2>&1
  ECHO.%SYS32%\config\systemprofile\AppData\Local\%%G>>"%TEMP%\001"
  DEL /F/Q "%SYS32%\config\systemprofile\AppData\Local\%%G" >NUL 2>&1
  IF EXIST "%SYS32%\config\systemprofile\AppData\Local\%%G" (
    ICACLS "%SYS32%\config\systemprofile\AppData\Local\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%SYS32%\config\systemprofile\AppData\Local\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%SYS32%\config\systemprofile\AppData\Local\%%G" >NUL 2>&1
    )
)

DIR /B/A:-D "%SYS32%\config\systemprofile\AppData\LocalLow" 2>NUL>sys32appdata00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <sys32appdata00 >sys32appdata01
"%SORT%" -f -u <sys32appdata01 >sys32appdata02
FOR /F "TOKENS=*" %%G IN ( sys32appdata02 ) DO @(
  ATTRIB -R -A -S -H "%SYS32%\config\systemprofile\AppData\LocalLow\%%G" >NUL 2>&1
  ECHO.%SYS32%\config\systemprofile\AppData\LocalLow\%%G>>"%TEMP%\001"
  DEL /F/Q "%SYS32%\config\systemprofile\AppData\LocalLow\%%G" >NUL 2>&1
  IF EXIST "%SYS32%\config\systemprofile\AppData\LocalLow\%%G" (
    ICACLS "%SYS32%\config\systemprofile\AppData\LocalLow\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%SYS32%\config\systemprofile\AppData\LocalLow\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%SYS32%\config\systemprofile\AppData\LocalLow\%%G" >NUL 2>&1
    )
)
  
DIR /B/A:-D "%SYS32%\config\systemprofile\AppData\Roaming" 2>NUL>sys32appdata00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dat|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <sys32appdata00 >sys32appdata01
"%SORT%" -f -u <sys32appdata01 >sys32appdata02
FOR /F "TOKENS=*" %%G IN ( sys32appdata02 ) DO @(
  ATTRIB -R -A -S -H "%SYS32%\config\systemprofile\AppData\Roaming\%%G" >NUL 2>&1
  ECHO.%SYS32%\config\systemprofile\AppData\Roaming\%%G>>"%TEMP%\001"
  DEL /F/Q "%SYS32%\config\systemprofile\AppData\Roaming\%%G" >NUL 2>&1
  IF EXIST "%SYS32%\config\systemprofile\AppData\Roaming\%%G" (
    ICACLS "%SYS32%\config\systemprofile\AppData\Roaming\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%SYS32%\config\systemprofile\AppData\Roaming\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%SYS32%\config\systemprofile\AppData\Roaming\%%G" >NUL 2>&1
    )
)

DIR /B/A:-D "%PUBLIC%" 2>NUL>public00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dat|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <public00 >public01
"%GREP%" -Evsi "^NTUSER\.DAT$" <public01 >public02
"%SORT%" -f -u <public02 >public03
FOR /F "TOKENS=*" %%G IN ( public03 ) DO @(
  ATTRIB -R -A -S -H "%PUBLIC%\%%G" >NUL 2>&1
  ECHO.%PUBLIC%\%%G>>"%TEMP%\001"
  DEL /F/Q "%PUBLIC%\%%G" >NUL 2>&1
  IF EXIST "%PUBLIC%\%%G" (
    ICACLS "%PUBLIC%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PUBLIC%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PUBLIC%\%%G" >NUL 2>&1
    )
)

DIR /B/A:-D "%SYSTEMDRIVE%\Users" 2>NUL>users00
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dat|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|url|vb[e|s])$" <users00 >users01
"%SORT%" -f -u <users01 >users02
FOR /F "TOKENS=*" %%G IN ( users02 ) DO @(
  ATTRIB -R -A -S -H "%SYSTEMDRIVE%\Users\%%G" >NUL 2>&1
  ECHO.%SYSTEMDRIVE%\Users\%%G>>"%TEMP%\001"
  DEL /F/Q "%SYSTEMDRIVE%\Users\%%G" >NUL 2>&1
  IF EXIST "%SYSTEMDRIVE%\Users\%%G" (
    ICACLS "%SYSTEMDRIVE%\Users\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%SYSTEMDRIVE%\Users\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%SYSTEMDRIVE%\Users\%%G" >NUL 2>&1
    )
)

REM ~~~~~ %COMMON32% SEARCH ~~~~~~~~~ the 32 bit variants of commonfiles and programfiles do not like their echos with quotes. idk why this is. LETS LEARN jk
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <common3200 >common3201
"%SORT%" -f -u <common3201 >common3202
FOR /F "TOKENS=*" %%G IN ( common3202 ) DO @(
  ATTRIB -R -A -S -H "%COMMON32%\%%G" >NUL 2>&1
  ECHO.%COMMON32%\%%G>>"%TEMP%\001"
  DEL /F/Q "%COMMON32%\%%G" >NUL 2>&1
  IF EXIST "%COMMON32%\%%G" (
    ICACLS "%COMMON32%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%COMMON32%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%COMMON32%\%%G" >NUL 2>&1
    )
)
REM ~~~~~ %COMMON64% SEARCH ~~~~~~~~~
IF EXIST "%COMMON64%" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <common6400 >common6401
"%SORT%" -f -u <common6401 >common6402
FOR /F "TOKENS=*" %%G IN ( common6402 ) DO @(
  ATTRIB -R -A -S -H "%COMMON64%\%%G" >NUL 2>&1
  ECHO."%COMMON64%\%%G">>"%TEMP%\001"
  DEL /F/Q "%COMMON64%\%%G" >NUL 2>&1
  IF EXIST "%COMMON64%\%%G" (
    ICACLS "%COMMON64%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%COMMON64%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%COMMON64%\%%G" >NUL 2>&1
    )
  )
)

REM ~~~~~ %PROGFILES64% SEARCH ~~~~~~~~~
IF EXIST "%PROGFILES64%" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles6400 >programfiles6401
"%SORT%" -f -u <programfiles6401 >programfiles6402
FOR /F "TOKENS=*" %%G IN ( programfiles6402 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES64%\%%G" >NUL 2>&1
  ECHO."%PROGFILES64%\%%G">>"%TEMP%\001"
  DEL /F/Q "%PROGFILES64%\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES64%\%%G" (
    ICACLS "%PROGFILES64%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES64%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES64%\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES64%\Google" DIR /B/A:-D "%PROGFILES64%\Google" 2>NUL>programfiles6400
IF EXIST "%PROGFILES64%\Google" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles6400 >programfiles6401
"%SORT%" -f -u <programfiles6401 >programfiles6402
FOR /F "TOKENS=*" %%G IN ( programfiles6402 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES64%\Google\%%G" >NUL 2>&1
  ECHO."%PROGFILES64%\Google\%%G">>"%TEMP%\001"
  DEL /F/Q "%PROGFILES64%\Google\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES64%\Google\%%G" (
    ICACLS "%PROGFILES64%\Google\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES64%\Google\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES64%\Google\%%G" >NUL 2>&1
    )
  )
)
IF EXIST "%PROGFILES64%\Windows NT" DIR /B/A:-D "%PROGFILES64%\Windows NT" 2>NUL>programfiles6400
IF EXIST "%PROGFILES64%\Windows NT" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles6400 >programfiles6401
"%SORT%" -f -u <programfiles6401 >programfiles6402
FOR /F "TOKENS=*" %%G IN ( programfiles6402 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES64%\Windows NT\%%G" >NUL 2>&1
  ECHO."%PROGFILES64%\Windows NT\%%G">>"%TEMP%\001"
  DEL /F/Q "%PROGFILES64%\Windows NT\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES64%\Windows NT\%%G" (
    ICACLS "%PROGFILES64%\Windows NT\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES64%\Windows NT\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES64%\Windows NT\%%G" >NUL 2>&1
    )
  )
)
IF EXIST "%PROGFILES64%\Microsoft" DIR /B/A:-D "%PROGFILES64%\Microsoft" 2>NUL>programfiles6400
IF EXIST "%PROGFILES64%\Microsoft" (
"%GREP%" -Esi ".*\.(bat|bin|au3|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles6400 >programfiles6401
"%SORT%" -f -u <programfiles6401 >programfiles6402
FOR /F "TOKENS=*" %%G IN ( programfiles6402 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES64%\Microsoft\%%G" >NUL 2>&1
  ECHO."%PROGFILES64%\Microsoft\%%G">>"%TEMP%\001"
  DEL /F/Q "%PROGFILES64%\Microsoft\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES64%\Microsoft\%%G" (
    ICACLS "%PROGFILES64%\Microsoft\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES64%\Microsoft\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES64%\Microsoft\%%G" >NUL 2>&1
    )
  )
)
IF EXIST "%PROGFILES64%\Internet Explorer" DIR /B/A:-D "%PROGFILES64%\Internet Explorer" 2>NUL>programfiles6400
IF EXIST "%PROGFILES64%\Internet Explorer" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dll|exe|jar|jse?|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <programfiles6400 >programfiles6401
"%GREP%" -Evsi "^(ExtExport|iediagcmd|ieinstal|ielowutil|iexplore)\.exe$|^(hmmapi|IEShims|sqmapi)\.dll$" <programfiles6401 >programfiles6402
"%SORT%" -f -u <programfiles6402 >programfiles6403
FOR /F "TOKENS=*" %%G IN ( programfiles6403 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES64%\Internet Explorer\%%G" >NUL 2>&1
  ECHO."%PROGFILES64%\Internet Explorer\%%G">>"%TEMP%\001"
  DEL /F/Q "%PROGFILES64%\Internet Explorer\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES64%\Internet Explorer\%%G" (
    ICACLS "%PROGFILES64%\Internet Explorer\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%PROGFILES64%\Internet Explorer\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%PROGFILES64%\Internet Explorer\%%G" >NUL 2>&1
    )
  )
)
IF EXIST "%PROGFILES64%" DIR /B/A:D "%PROGFILES64%" 2>NUL>programfiles6400
IF EXIST "%PROGFILES64%" (
"%GREP%" -Es "^chrome_url_fetcher_[0-9]{4}_[0-9]{10}$" <programfiles6400 >programfiles6401
"%SORT%" -f -u <programfiles6401 >programfiles6402
FOR /F "TOKENS=*" %%G IN ( programfiles6402 ) DO @(
  ATTRIB -R -A -S -H "%PROGFILES64%\%%G" >NUL 2>&1
  ECHO."%PROGFILES64%\%%G">>"%TEMP%\001b"
  RD /S/Q "%PROGFILES64%\%%G" >NUL 2>&1
  IF EXIST "%PROGFILES64%\%%G" (
    ICACLS "%PROGFILES64%\%%G" /GRANT *S-1-1-0:F /C /Q /T >NUL 2>&1
    ICACLS "%PROGFILES64%\%%G" /RESET /C /Q /T >NUL 2>&1
    RD /S/Q "%PROGFILES64%\%%G" >NUL 2>&1
    )
  )
)
REM ~~~~~ SysWOW64 SEARCH ~~~~~~~~~
IF EXIST "%WINDIR%\SysWOW64" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|jar|jse?|pif|eps|ps1|py|hta|tmp|vb[e|s])$" <SysWOW6400 >SysWOW6401
"%GREP%" -Evsi "^(slmgr\.vbs|winrm\.(cmd|vbs))$" <SysWOW6401 >SysWOW6402
"%SORT%" -f -u <SysWOW6402 >SysWOW6403
FOR /F "TOKENS=*" %%G IN ( SysWOW6403 ) DO @(
  ATTRIB -R -A -S -H "%WINDIR%\SysWOW64\%%G" >NUL 2>&1
  ECHO.%WINDIR%\SysWOW64\%%G>>"%TEMP%\001"
  DEL /F/Q "%WINDIR%\SysWOW64\%%G" >NUL 2>&1
  IF EXIST "%WINDIR%\SysWOW64\%%G" (
    ICACLS "%WINDIR%\SysWOW64\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%WINDIR%\SysWOW64\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%WINDIR%\SysWOW64\%%G" >NUL 2>&1
    )
  )
)

REM ~~~~~ WINDOWS TASKS SEARCH ~~~~~~~~~
IF EXIST "%WTASKS%" (
"%GREP%" -Esi ".*\.job$" <WTASKS00 >WTASKS01
"%SORT%" -f -u <WTASKS01 >WTASKS02
FOR /F "TOKENS=*" %%G IN ( WTASKS02 ) DO @(
  ATTRIB -R -A -S -H "%WTASKS%\%%G" >NUL 2>&1
  ECHO.%WTASKS%\%%G>>"%TEMP%\001"
  DEL /F/Q "%WTASKS%\%%G" >NUL 2>&1
  IF EXIST "%WTASKS%\%%G" (
    ICACLS "%WTASKS%\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%WTASKS%\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%WTASKS%\%%G" >NUL 2>&1
    )
  )
)

IF EXIST "%WINDIR%\Fonts" DIR /B/A:-D "%WINDIR%\Fonts" 2>NUL>WTASKS00
IF EXIST "%WINDIR%\Fonts" (
"%GREP%" -Esi ".*\.(bat|bin|au3|ahk|cmd|dat|dll|exe|jar|jse?|json|pif|eps|ps1|py|hta|scr|tmp|vb[e|s])$" <WTASKS00 >WTASKS01
"%GREP%" -Evsi "^StaticCache\.dat$" <WTASKS01 >WTASKS02
"%SORT%" -f -u <WTASKS02 >WTASKS03
FOR /F "TOKENS=*" %%G IN ( WTASKS03 ) DO @(
  ECHO.%WINDIR%\Fonts\%%G>>"%TEMP%\001"
  ATTRIB -R -A -S -H "%WINDIR%\Fonts\%%G" >NUL 2>&1
  DEL /F/Q "%WINDIR%\Fonts\%%G" >NUL 2>&1
  IF EXIST "%WINDIR%\Fonts\%%G" (
    ICACLS "%WINDIR%\Fonts\%%G" /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
    ICACLS "%WINDIR%\Fonts\%%G" /RESET /C /Q >NUL 2>&1
    DEL /F/Q "%WINDIR%\Fonts\%%G" >NUL 2>&1
    )
  )
)

FOR %%G in (
"%ALLUSERSPROFILE%\AppHost.exe"
"%ALLUSERSPROFILE%\audiodg.exe"
"%ALLUSERSPROFILE%\chromedriver\logs.dat"
"%ALLUSERSPROFILE%\Cortana\infatica_agent.exe"
"%ALLUSERSPROFILE%\CrashReporter\CrashReporter.exe"
"%ALLUSERSPROFILE%\DiagnosisSync\current\Microsoft.exe"
"%ALLUSERSPROFILE%\directx\graphics\directxutil.exe"
"%ALLUSERSPROFILE%\Fonts_4\Pictures_Sys\STXService.exe"
"%ALLUSERSPROFILE%\GoogleUP\Chrome\Updater.exe"
"%ALLUSERSPROFILE%\MicrosoftHost.exe"
"%ALLUSERSPROFILE%\NetTrace\1.0.0\refreshNetworkInfo.cmd"
"%ALLUSERSPROFILE%\Pictures_Con\Documents_1\STXService.exe"
"%ALLUSERSPROFILE%\ReaItekHD\taskhost.exe"
"%ALLUSERSPROFILE%\ReaItekHD\taskhostw.exe"
"%ALLUSERSPROFILE%\steam.jpg"
"%ALLUSERSPROFILE%\EFdhpjfCj\qCsewleqYB.exe"
"%ALLUSERSPROFILE%\Win32\CUDA\msvcp140.dll"
"%ALLUSERSPROFILE%\Win32\CUDA\NvidiaHel.exe"
"%ALLUSERSPROFILE%\Win32\CUDA\vcruntime140.dll"
"%ALLUSERSPROFILE%\Windows Tasks Service\winserv.exe"
"%ALLUSERSPROFILE%\Windows\rutserv.exe"
"%ALLUSERSPROFILE%\WindowsTask\AMD.exe"
"%ALLUSERSPROFILE%\WindowsTask\AppModule.exe"
"%ALLUSERSPROFILE%\Watcherpatch_Mnm\IUService.exe"
"%ALLUSERSPROFILE%\WindowsTask\audiodg.exe"
"%APPDATA%\Adobe\upd\rslm.exe"
"%APPDATA%\Cpb_Docker\moagent.exe"
"%APPDATA%\EBUpdate_x64\msn.exe"
"%APPDATA%\efsui\data.exe"
"%APPDATA%\Gitl\mrucl.exe"
"%APPDATA%\pwl_Patch\Compil32.exe"
"%APPDATA%\helpscan\identity_helper.exe"
"%APPDATA%\ScanAuthBg_alpha_5\IsCabView.exe"
"%APPDATA%\hhConfig\identity_helper.exe"
"%APPDATA%\hostmon\ISDbg.exe"
"%APPDATA%\identity_helper.exe"
"%APPDATA%\ITEinboxI2CFlash\bckp_amgr.exe"
"%APPDATA%\ITEinboxI2CFlash\ITERHPGen.exe"
"%APPDATA%\Kernel\Kernel32\kernel32.exe"
"%APPDATA%\Launchvalidate_debug_v1\IsCabView.exe"
"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Adult Player.lnk"
"%APPDATA%\Microsoft\PerfMon\PerfWatson2.exe"
"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Adult Player.lnk"
"%APPDATA%\NetworkSettings\NetworkProtection\networkprotection64.exe"
"%APPDATA%\oexbxoqn\mchost.chm"
"%APPDATA%\quickhostPs\DriverBooster.exe"
"%APPDATA%\quickSuper_debug\WinX_DVD_Ripper_Platinum.exe"
"%APPDATA%\SEO\SEO.exe"
"%APPDATA%\Slate Digital Connect\SDACollector\sdaCollector.vbs"
"%APPDATA%\smss\sessionmsg.exe"
"%APPDATA%\sonicstudio\sonic.exe"
"%APPDATA%\Spectrum\service.exe"
"%APPDATA%\Sys64\wlansinf\svcsys64.exe"
"%APPDATA%\Sysfiles\system.exe"
"%APPDATA%\Sysfilesdriver.exe"
"%APPDATA%\SystemSettingsAdminFlows\service.exe"
"%APPDATA%\SysWOW32\csrss.exe"
"%APPDATA%\utorrent\pro\uTorrentPro.exe"
"%APPDATA%\writerService\ManyCam.exe"
"%LOCALA%\Disk\AutoIt3\AutoIt3_x64.exe"
"%LOCALA%\Google\Chrome\User Data\Default\Web Applications\_crx_fgdjljmcohnealigfnicajkboadjabcf\Adult Player.lnk"
"%LOCALA%\Host App Service\Engine\HostAppServiceUpdater.exe"
"%LOCALA%\InterNotify\CpnsjleBrofser\xrWPcstemqsdjpr.dll"
"%LOCALA%\LavoshGri\php.exe"
"%LOCALA%\Microsoft\BingSvc\BingSvc.exe"
"%LOCALA%\Microsoft\WindowsApps\WindowsDefenderSecurity.exe"
"%LOCALA%\ODA3\asset.txt"
"%LOCALA%\ODA3\ODA3.exe"
"%LOCALA%\Programs\com.gametop.launcher\gt-launcher.exe"
"%LOCALA%\Programs\Common\OneDriveCloud\mbam.ps1"
"%LOCALA%\Programs\Common\OneDriveCloud\taskhostw.exe"
"%LOCALA%\Programs\Common\taskshosts.exe"
"%LOCALA%\Programs\Pinaview\Pinaview.exe"
"%LOCALA%\Python315\python.exe"
"%LOCALA%\Updates\Run.vbs"
"%LOCALA%\Updates\Windows.bat"
"%LOCALA%\Updates\WindowsService.exe"
"%LOCALA%\yzsx_cloud\wdcloud_v2.exe"
"%PROGFILES32%\Client Helper\Client Helper.exe"
"%PROGFILES32%\Google\Chrome\Update.exe"
"%PROGFILES32%\Google\Chrome\Updater.exe"
"%PROGFILES32%\Kryptex\Kryptex.exe"
"%PROGFILES32%\Mozilla Firefox\defaults\pref\autoconfig.js"
"%PROGFILES32%\Mozilla Firefox\bd_config.cfg"
"%PROGFILES32%\Mozilla Firefox\defaults\pref\bd_js_config.js"
"%PROGFILES32%\Mozilla Firefox\mozilla.cfg"
"%PROGFILES32%\uTorrentPro\uTorrentPro.exe"
"%PROGFILES32%\VideoPlayer\VideoPlayerUpdate.bat"
"%PROGFILES32%\AmneziaWG\amneziawg.exe"
"%PROGFILES32%\Windows Sidebar\sidebar.exe"
"%PUBLIC%\ClientRuntime\ServiceClientHelper.exe"
"%PUBLIC%\ClientRuntime\ServiceReporter.exe"
"%PUBLIC%\Documents\Systeem.vbs"
"%PUBLIC%\GlassWireApp\GlassWireApp.vbs"
"%PUBLIC%\libraries\amd\opencl\sppextfileobj.exe"
"%PUBLIC%\libraries\directx\dxcache\ddxdiag.exe"
"%PUBLIC%\Pictures_Temp\Pictures_Temp\SgrmBroker.exe"
"%PUBLIC%\Torrent\PerfLogs\PerfLogs\run.vbs"
"%STARTMENUAUP%\Adobe offers.lnk"
"%STARTUP%\archiveconfig.lnk"
"%STARTUP%\bckp_amgr.lnk"
"%STARTUP%\Fu_Wizard.lnk"
"%STARTUP%\Send to OneNote.lnk"
"%STARTUP%\ITERHPGen.lnk"
"%STARTUP%\fastSecurity_v3.lnk"
"%STARTUP%\Microsoft.NET Framework.exe"
"%STARTUP%\mrucl.lnk"
"%STARTUP%\diawsecxx.lnk"
"%STARTUP%\ProW File Compressor.lnk"
"%STARTUP%\SearchEngineOptimizer.lnk"
"%STARTUP%\Sidebar620.lnk"
"%STARTUP%\start.lnk"
"%STARTUP%\amneziawg.lnk"
"%STARTUP%\StreamChrome5.lnk"
"%STARTUP%\VLCMediaPlayer.exe"
"%SYS32%\Drivers\AliPaladinEx64.sys"
"%SYS32%\Maintenance.vbs"
"%SYS32%\winsvcf\x736594.dat"
"%SYS32%\x977434.dat"
"%SYSTEMDRIVE%\movrmemm\nlnokyi.exe"
"%TEMP%\bzqlyietdwsj.tmp"
"%TEMP%\qdsaknsehgak.xml"
"%USERPROFILE%\Desktop\Adult Player.lnk"
"%USERPROFILE%\ex-list"
"%USERPROFILE%\ex-list2.json"
"%USERPROFILE%\uTorrentPro.dat"
"%USERPROFILE%\zopbzkjwa\opbzkjwa.csproj"
"%WINDIR%\$nya-onimai2\$nya-Onimai.bat"
"%WINDIR%\$nya-onimai3\$nya-Loli.bat"
"%WINDIR%\BitLocker\btlckinteg.js"
"%WINDIR%\Copilot\update.ps1"
"%WINDIR%\OneDrive\onedrivesync.exe"
"%WINDIR%\OneDrive\onedrivesync.js"
"%WINDIR%\security\pywinvera\pythonw.exe"
) DO @(
  IF EXIST "%%G" (
    ATTRIB -R -A -S -H %%G >NUL 2>&1
    ECHO.%%G>>"%TEMP%\001"
    DEL /F/Q %%G >NUL 2>&1
    IF EXIST "%%G" (
      ICACLS %%G /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
      ICACLS %%G /RESET /C /Q >NUL 2>&1
      DEL /F/Q %%G >NUL 2>&1
      )
   )
)


IF EXIST "%PROGFILES64%" (
FOR %%G in (
"%COMMON64%\DalbarnCortinaZ\DalbarnCortinaZ.exe"
"%COMMON64%\DirectionPackage\BitqonDeaktop\lonalofileoWy0415.dll"
"%PROGFILES64%\Honeygain\Honeygain.exe"
"%PROGFILES64%\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe"
"%PROGFILES64%\Lavasoft\Web Companion\Application\WebCompanion.exe"
"%PROGFILES64%\LocalUserHelper\helper.js"
"%PROGFILES64%\Mozilla Firefox\mozilla.cfg"
"%PROGFILES64%\Mozilla Firefox\defaults\pref\autoconfig.js"
"%PROGFILES64%\ProAccelerationOfPC\ProAccelerationOfPC.exe"
"%PROGFILES64%\pwac\ProW\ProW File Compressor.exe"
"%PROGFILES64%\sftmgr\sftmgr.exe"
"%PROGFILES64%\svcmgr\svcmgr.exe"
"%PROGFILES64%\Digital Communications\SAntivirus\SAntivirusIC.exe"
"%PROGFILES64%\Digital Communications\SAntivirus\SAntivirusService.exe"
"%PROGFILES64%\VoiceGate\SkadchFuqction\oleasZstj1z0.dll"
"%PROGFILES64%\WareGoogle\PpafeProper\MiclicyWPbwr.dll"
"%WINDIR%\SysWOW64\unsecapp.exe"
) DO @(
  IF EXIST "%%G" (
    ATTRIB -R -A -S -H %%G >NUL 2>&1
    ECHO.%%G>>"%TEMP%\001"
    DEL /F/Q %%G >NUL 2>&1
    IF EXIST "%%G" (
      ICACLS %%G /GRANT *S-1-1-0:F /C /Q >NUL 2>&1
      ICACLS %%G /RESET /C /Q >NUL 2>&1
      DEL /F/Q %%G >NUL 2>&1
      )
    )
  )
)

FOR %%G in (
"%APPDATA%\obs-studio\logs\*"
"%LOCALA%\AMDIdentifyWindow\cache\qmlcache\*"
"%LOCALA%\AMDSoftwareInstaller\cache\qmlcache\*"
"%LOCALA%\AMD\DxCache\*"
"%LOCALA%\AMD\DxcCache\*"
"%LOCALA%\AMD\VkCache\*"
"%SYS32%\config\systemprofile\AppData\Local\AMD\DxCache\*"
"%SYS32%\config\systemprofile\AppData\Local\AMD\DxcCache\*"
"%WINDIR%\ServiceProfiles\LocalService\AppData\Local\AMD\DxCache\*"
"%WINDIR%\ServiceProfiles\LocalService\AppData\Local\FontCache\*"
"%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Temp\*"
"%WINDIR%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs\*"
"%WINDIR%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\INetCache\*"
"%WINDIR%\ServiceProfiles\NetworkService\AppData\Local\Temp\*"
"%WINDIR%\CbsTemp\*"
"%WINDIR%\SystemTemp\*"
"%WINDIR%\Temp\*"
) DO @DEL /F/Q "%%G" >NUL 2>&1

FOR %%G in (
"%ALLUSERSPROFILE%\Alibaba"
"%ALLUSERSPROFILE%\AlricApplication"
"%ALLUSERSPROFILE%\AlrisitApplication"
"%ALLUSERSPROFILE%\Alsoft"
"%ALLUSERSPROFILE%\AltrsikApplication"
"%ALLUSERSPROFILE%\Altruist"
"%ALLUSERSPROFILE%\Altruistics"
"%ALLUSERSPROFILE%\Altrustix"
"%ALLUSERSPROFILE%\AtritcSoft"
"%ALLUSERSPROFILE%\AtrtisApplication"
"%ALLUSERSPROFILE%\Atructsoft"
"%ALLUSERSPROFILE%\Atuctsoft"
"%ALLUSERSPROFILE%\AweAPCP"
"%ALLUSERSPROFILE%\backupvalid_alpha"
"%ALLUSERSPROFILE%\CDPResource"
"%ALLUSERSPROFILE%\chromedriver"
"%ALLUSERSPROFILE%\crashhandlerinfo"
"%ALLUSERSPROFILE%\CrashReporter"
"%ALLUSERSPROFILE%\DirectX"
"%ALLUSERSPROFILE%\Fonts_4"
"%ALLUSERSPROFILE%\GoogleUP"
"%ALLUSERSPROFILE%\Install"
"%ALLUSERSPROFILE%\Microsoft\IObitUnlocker"
"%ALLUSERSPROFILE%\Microsoft\Windows\Tools"
"%ALLUSERSPROFILE%\Pictures_Con"
"%ALLUSERSPROFILE%\ReaItekHD"
"%ALLUSERSPROFILE%\remcos"
"%ALLUSERSPROFILE%\RunDLL"
"%ALLUSERSPROFILE%\Watcherpatch_Mnm"
"%ALLUSERSPROFILE%\System32"
"%ALLUSERSPROFILE%\Win32"
"%ALLUSERSPROFILE%\Windows Tasks Service"
"%ALLUSERSPROFILE%\Windows11"
"%ALLUSERSPROFILE%\WindowsTask"
"%APPDATA%\$nya-Logs"
"%APPDATA%\aliwangwangData"
"%APPDATA%\ClientHelper"
"%APPDATA%\pwl_Patch"
"%APPDATA%\afuwinX64"
"%APPDATA%\com.gtoppocket.launcher"
"%APPDATA%\EBUpdate_x64"
"%APPDATA%\helpscan"
"%APPDATA%\hhConfig"
"%APPDATA%\Honeygain"
"%APPDATA%\ScanAuthBg_alpha_5"
"%APPDATA%\hostmon"
"%APPDATA%\Kernel\Kernel32"
"%APPDATA%\Launchvalidate_debug_v1"
"%APPDATA%\NetworkSettings\NetworkProtection"
"%APPDATA%\PowerAdvanced_dbg"
"%APPDATA%\quickhostPs"
"%APPDATA%\quickSuper_debug"
"%APPDATA%\RMS_settings"
"%APPDATA%\SEO"
"%APPDATA%\soAuth"
"%APPDATA%\Sys64"
"%APPDATA%\Sysfiles"
"%APPDATA%\UltraDaemon_xkn"
"%APPDATA%\utForpc"
"%APPDATA%\utorrent\pro"
"%APPDATA%\Video Memory stress Test"
"%APPDATA%\WriterRemote_beta"
"%APPDATA%\writerService"
"%LOCALA%\AdvinstAnalytics"
"%LOCALA%\AlricApplication"
"%LOCALA%\AlrisitApplication"
"%LOCALA%\Alsoft"
"%LOCALA%\AltrousikApplication"
"%LOCALA%\AltrsikApplication"
"%LOCALA%\Altruist"
"%LOCALA%\Altruistics"
"%LOCALA%\Altrustix"
"%LOCALA%\ATBOLGgDq"
"%LOCALA%\AtritcSoft"
"%LOCALA%\AtrtisApplication"
"%LOCALA%\Atructsoft"
"%LOCALA%\Atuctsoft"
"%LOCALA%\AweAPCP"
"%LOCALA%\Browserupdphenix"
"%LOCALA%\clienthelper-updater"
"%LOCALA%\com.gametop.launcher-updater"
"%LOCALA%\ExtensionOptimizer"
"%LOCALA%\Google\Chrome\User Data\Default\Web Applications\_crx_fgdjljmcohnealigfnicajkboadjabcf"
"%LOCALA%\Host App Service"
"%LOCALA%\IJQMFPCmtOTdSU"
"%LOCALA%\kryptex-app-updater"
"%LOCALA%\Microsoft\BGAHelperLib"
"%LOCALA%\Microsoft\BingSvc"
"%LOCALA%\ProtectBrowser"
"%LOCALA%\runtimes"
"%LOCALA%\utorrentpro-updater"
"%LOCALA%\WWCEF"
"%PROGFILES32%\Client Helper"
"%PROGFILES32%\Kryptex"
"%PROGFILES32%\RDP Wrapper"
"%PROGFILES32%\AmneziaWG"
"%PROGFILES32%\VideoPlayer"
"%PUBLIC%\libraries\amd"
"%PUBLIC%\libraries\directx"
"%PUBLIC%\Pictures_Temp"
"%STARTMENUCU%\Programs\Pinaview"
"%SYSTEMDRIVE%\movrmemm"
"%WINDIR%\$nya-onimai2"
"%WINDIR%\$nya-onimai3"
"%WINDIR%\runtimes"
) DO @(
  IF EXIST %%G (
    ATTRIB -R -A -S -H %%G >NUL 2>&1
    ECHO.%%G>>"%TEMP%\001b"
    RD /S/Q %%G >NUL 2>&1
    IF EXIST %%G (
      ICACLS %%G /GRANT *S-1-1-0:F /C /Q /T >NUL 2>&1
      ICACLS %%G /RESET /C /Q /T >NUL 2>&1
      RD /S/Q %%G >NUL 2>&1
    )
  )
)

IF EXIST "%PROGFILES64%" (
FOR %%G in (
"%COMMON64%\DalbarnCortinaZ"
"%COMMON64%\DirectionPackage\BitqonDeaktop"
"%PROGFILES64%\AlibabaProtect"
"%PROGFILES64%\AliWangWang"
"%PROGFILES64%\AlricApplication"
"%PROGFILES64%\AlrisitApplication"
"%PROGFILES64%\Alsoft"
"%PROGFILES64%\AltrousikApplication"
"%PROGFILES64%\AltrsikApplication"
"%PROGFILES64%\Altruist"
"%PROGFILES64%\Altruistics"
"%PROGFILES64%\AtritcSoft"
"%PROGFILES64%\AtrtisApplication"
"%PROGFILES64%\Atuctsoft"
"%PROGFILES64%\AweAPCP"
"%PROGFILES64%\Honeygain"
"%PROGFILES64%\Lavasoft\Web Companion"
"%PROGFILES64%\LocalUserHelper"
"%PROGFILES64%\ProAccelerationOfPC"
"%PROGFILES64%\sftmgr"
"%PROGFILES64%\svcmgr"
"%PROGFILES64%\Digital Communications"
"%PROGFILES64%\WareGoogle\PpafeProper"
) DO @(
  IF EXIST %%G (
    ATTRIB -R -A -S -H %%G >NUL 2>&1
    ECHO.%%G>>"%TEMP%\001b"
    RD /S/Q %%G >NUL 2>&1
    IF EXIST %%G (
      ICACLS %%G /GRANT *S-1-1-0:F /C /Q /T >NUL 2>&1
      ICACLS %%G /RESET /C /Q /T >NUL 2>&1
      RD /S/Q %%G >NUL 2>&1
      )
    )
  )
)

:BitsTransfer
IF EXIST %SYS32%\chcp.com CHCP 437>NUL
IF EXIST %SYS32%\WindowsPowerShell\v1.0\powershell.exe @POWERSHELL -command "Get-BitsTransfer -AllUsers | Where-Object { $_.JobState -CContains 'Error' } | Remove-BitsTransfer" >NUL 2>&1
IF EXIST %SYS32%\chcp.com CHCP 65001>NUL

:JM
@CALL jm.bat


:EdgeDefault
IF NOT EXIST "%LOCALA%\Microsoft\Edge\User Data\Default\Preferences" GOTO :EdgeProfile1
COPY /Y "%LOCALA%\Microsoft\Edge\User Data\Default\Preferences" "%TEMP%\edgeprefsdefault00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\edgeprefsdefault00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :EdgeProfile1
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\edgeprefsdefault00" >"%TEMP%\edgeprefsdefault01"
COPY /Y "%TEMP%\edgeprefsdefault01" "%LOCALA%\Microsoft\Edge\User Data\Default\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifEDG% ^(Default^)>>"%TEMP%\001"

:EdgeProfile1
IF NOT EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Preferences" GOTO :EdgeProfile2
COPY /Y "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Preferences" "%TEMP%\edgeprefs1prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\edgeprefs1prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :EdgeProfile2
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\edgeprefs1prof00" >"%TEMP%\edgeprefs1prof01"
COPY /Y "%TEMP%\edgeprefs1prof01" "%LOCALA%\Microsoft\Edge\User Data\Profile 1\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifEDG% ^(Profile 1^)>>"%TEMP%\001"

:EdgeProfile2
IF NOT EXIST "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Preferences" GOTO :ChromeDefault
COPY /Y "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Preferences" "%TEMP%\edgeprefs2prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\edgeprefs2prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :ChromeDefault
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\edgeprefs2prof00" >"%TEMP%\edgeprefs2prof01"
COPY /Y "%TEMP%\edgeprefs2prof01" "%LOCALA%\Microsoft\Edge\User Data\Profile 2\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifEDG% ^(Profile 2^)>>"%TEMP%\001"

:ChromeDefault
IF NOT EXIST "%LOCALA%\Google\Chrome\User Data\Default\Preferences" GOTO :ChromeProfile1
COPY /Y "%LOCALA%\Google\Chrome\User Data\Default\Preferences" "%TEMP%\chromeprefsdefault00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\chromeprefsdefault00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :ChromeProfile1
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\chromeprefsdefault00" >"%TEMP%\chromeprefsdefault01"
COPY /Y "%TEMP%\chromeprefsdefault01" "%LOCALA%\Google\Chrome\User Data\Default\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifCHR% ^(Default^)>>"%TEMP%\001"

:ChromeProfile1
IF NOT EXIST "%LOCALA%\Google\Chrome\User Data\Profile 1\Preferences" GOTO :ChromeProfile2
COPY /Y "%LOCALA%\Google\Chrome\User Data\Profile 1\Preferences" "%TEMP%\chromeprefs1prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\chromeprefs1prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :ChromeProfile2
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\chromeprefs1prof00" >"%TEMP%\chromeprefs1prof01"
COPY /Y "%TEMP%\chromeprefs1prof01" "%LOCALA%\Google\Chrome\User Data\Profile 1\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifCHR% ^(Profile 1^)>>"%TEMP%\001"

:ChromeProfile2
IF NOT EXIST "%LOCALA%\Google\Chrome\User Data\Profile 2\Preferences" GOTO :BraveDefault
COPY /Y "%LOCALA%\Google\Chrome\User Data\Profile 2\Preferences" "%TEMP%\chromeprefs2prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\chromeprefs2prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :BraveDefault
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\chromeprefs2prof00" >"%TEMP%\chromeprefs2prof01"
COPY /Y "%TEMP%\chromeprefs2prof01" "%LOCALA%\Google\Chrome\User Data\Profile 2\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifCHR% ^(Profile 2^)>>"%TEMP%\001"

:BraveDefault
IF NOT EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Preferences" GOTO :BraveProfile1
COPY /Y "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Preferences" "%TEMP%\braveprefsdefault00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\braveprefsdefault00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :BraveProfile1
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\braveprefsdefault00" >"%TEMP%\braveprefsdefault01"
COPY /Y "%TEMP%\braveprefsdefault01" "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Default\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifBRV% ^(Default^)>>"%TEMP%\001"

:BraveProfile1
IF NOT EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Preferences" GOTO :BraveProfile2
COPY /Y "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Preferences" "%TEMP%\braveprefs1prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\braveprefs1prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :BraveProfile2
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\braveprefs1prof00" >"%TEMP%\braveprefs1prof01"
COPY /Y "%TEMP%\braveprefs1prof01" "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 1\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifBRV% ^(Profile 1^)>>"%TEMP%\001"

:BraveProfile2
IF NOT EXIST "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Preferences" GOTO :YandexDefault
COPY /Y "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Preferences" "%TEMP%\braveprefs2prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\braveprefs2prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :YandexDefault
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\braveprefs2prof00" >"%TEMP%\braveprefs2prof01"
COPY /Y "%TEMP%\braveprefs2prof01" "%LOCALA%\BraveSoftware\Brave-Browser\User Data\Profile 2\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifBRV% ^(Profile 2^)>>"%TEMP%\001"

:YandexDefault
IF NOT EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Preferences" GOTO :YandexProfile1
COPY /Y "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Preferences" "%TEMP%\yandexprefsdefault00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\yandexprefsdefault00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :YandexProfile1
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\yandexprefsdefault00" >"%TEMP%\yandexprefsdefault01"
COPY /Y "%TEMP%\yandexprefsdefault01" "%LOCALA%\Yandex\YandexBrowser\User Data\Default\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifBRV% ^(Default^)>>"%TEMP%\001"

:YandexProfile1
IF NOT EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Preferences" GOTO :YandexProfile2
COPY /Y "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Preferences" "%TEMP%\yandexprefs1prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\yandexprefs1prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :YandexProfile2
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\yandexprefs1prof00" >"%TEMP%\yandexprefs1prof01"
COPY /Y "%TEMP%\yandexprefs1prof01" "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 1\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifBRV% ^(Profile 1^)>>"%TEMP%\001"

:YandexProfile2
IF NOT EXIST "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Preferences" GOTO :VivaldiDefault
COPY /Y "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Preferences" "%TEMP%\yandexprefs2prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\yandexprefs2prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :VivaldiDefault
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\yandexprefs2prof00" >"%TEMP%\yandexprefs2prof01"
COPY /Y "%TEMP%\yandexprefs2prof01" "%LOCALA%\Yandex\YandexBrowser\User Data\Profile 2\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifBRV% ^(Profile 2^)>>"%TEMP%\001"


:VivaldiDefault
IF NOT EXIST "%LOCALA%\Vivaldi\User Data\Default\Preferences" GOTO :VivaldiProfile1
COPY /Y "%LOCALA%\Vivaldi\User Data\Default\Preferences" "%TEMP%\vivaldiprefsdefault00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\vivaldiprefsdefault00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :VivaldiProfile1
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\vivaldiprefsdefault00" >"%TEMP%\vivaldiprefsdefault01"
COPY /Y "%TEMP%\vivaldiprefsdefault01" "%LOCALA%\Vivaldi\User Data\Default\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifVIV% ^(Default^)>>"%TEMP%\001"

:VivaldiProfile1
IF NOT EXIST "%LOCALA%\Vivaldi\User Data\Profile 1\Preferences" GOTO :VivaldiProfile2
COPY /Y "%LOCALA%\Vivaldi\User Data\Profile 1\Preferences" "%TEMP%\vivaldiprefs1prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\vivaldiprefs1prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :VivaldiProfile2
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\vivaldiprefs1prof00" >"%TEMP%\vivaldiprefs1prof01"
COPY /Y "%TEMP%\vivaldiprefs1prof01" "%LOCALA%\Vivaldi\User Data\Profile 1\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifVIV% ^(Profile 1^)>>"%TEMP%\001"

:VivaldiProfile2
IF NOT EXIST "%LOCALA%\Vivaldi\User Data\Profile 2\Preferences" GOTO :ComodoDefault
COPY /Y "%LOCALA%\Vivaldi\User Data\Profile 2\Preferences" "%TEMP%\vivaldiprefs2prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\vivaldiprefs2prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :ComodoDefault
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\vivaldiprefs2prof00" >"%TEMP%\vivaldiprefs2prof01"
COPY /Y "%TEMP%\vivaldiprefs2prof01" "%LOCALA%\Vivaldi\User Data\Profile 2\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifVIV% ^(Profile 2^)>>"%TEMP%\001"

:ComodoDefault
IF NOT EXIST "%LOCALA%\Comodo\Dragon\User Data\Default\Preferences" GOTO :ComodoProfile1
COPY /Y "%LOCALA%\Comodo\Dragon\User Data\Default\Preferences" "%TEMP%\comodoprefsdefault00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\comodoprefsdefault00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :ComodoProfile1
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\comodoprefsdefault00" >"%TEMP%\comodoprefsdefault01"
COPY /Y "%TEMP%\comodoprefsdefault01" "%LOCALA%\Comodo\Dragon\User Data\Default\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifCMD% ^(Default^)>>"%TEMP%\001"

:ComodoProfile1
IF NOT EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Preferences" GOTO :ComodoProfile2
COPY /Y "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Preferences" "%TEMP%\comodoprefs1prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\comodoprefs1prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :ComodoProfile2
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\comodoprefs1prof00" >"%TEMP%\comodoprefs1prof01"
COPY /Y "%TEMP%\comodoprefs1prof01" "%LOCALA%\Comodo\Dragon\User Data\Profile 1\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifCMD% ^(Profile 1^)>>"%TEMP%\001"

:ComodoProfile2
IF NOT EXIST "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Preferences" GOTO :OperaDefault
COPY /Y "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Preferences" "%TEMP%\comodoprefs2prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\comodoprefs2prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :OperaDefault
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\comodoprefs2prof00" >"%TEMP%\comodoprefs2prof01"
COPY /Y "%TEMP%\comodoprefs2prof01" "%LOCALA%\Comodo\Dragon\User Data\Profile 2\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifCMD% ^(Profile 2^)>>"%TEMP%\001"

:OperaDefault
IF NOT EXIST "%APPDATA%\Opera Software\Opera Stable\Default\Preferences" GOTO :OperaProfile1
COPY /Y "%APPDATA%\Opera Software\Opera Stable\Default\Preferences" "%TEMP%\operaprefsdefault00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\operaprefsdefault00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :OperaProfile1
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\operaprefsdefault00" >"%TEMP%\operaprefsdefault01"
COPY /Y "%TEMP%\operaprefsdefault01" "%APPDATA%\Opera Software\Opera Stable\Default\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifOPR% ^(Default^)>>"%TEMP%\001"

:OperaProfile1
IF NOT EXIST "%APPDATA%\Opera Software\Opera Stable\Profile 1\Preferences" GOTO :OperaProfile2
COPY /Y "%APPDATA%\Opera Software\Opera Stable\Profile 1\Preferences" "%TEMP%\operaprefs1prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\operaprefs1prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :OperaProfile2
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\operaprefs1prof00" >"%TEMP%\operaprefs1prof01"
COPY /Y "%TEMP%\operaprefs1prof01" "%APPDATA%\Opera Software\Opera Stable\Profile 1\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifOPR% ^(Profile 1^)>>"%TEMP%\001"

:OperaProfile2
IF NOT EXIST "%APPDATA%\Opera Software\Opera Stable\Profile 2\Preferences" GOTO :TidyReg
COPY /Y "%APPDATA%\Opera Software\Opera Stable\Profile 2\Preferences" "%TEMP%\operaprefs2prof00" >NUL 2>&1
"%GREP%" -Pis "\},\x22notifications\x22:\{\x22http.*\},\x22password_protection\x22:\{" <"%TEMP%\operaprefs2prof00" >"%TEMP%\%random%"
IF ERRORLEVEL 1 GOTO :TidyReg
"%SED%" -r "s/\},\x22notifications\x22:\{.*\},\x22password_protection\x22:\{/\},\x22notifications\x22:\{\},\x22password_protection\x22:\{/g" <"%TEMP%\operaprefs2prof00" >"%TEMP%\operaprefs2prof01"
COPY /Y "%TEMP%\operaprefs2prof01" "%APPDATA%\Opera Software\Opera Stable\Profile 2\Preferences" >NUL 2>&1
ECHO.%Log_PushNotifOPR% ^(Profile 2^)>>"%TEMP%\001"

:FireFoxPushNotif
REM sqlite3 permissions.sqlite "SELECT * FROM moz_perms;">new2.txt
REM "%GREP%" -Evs "\|desktop-notification\|" <new2.txt >new3.txt

:TidyReg
REM Finally, 32-bit and 64-bit registry entries use different formats. The 32-bit registry uses the Windows Registry Editor Version 5.0 (REGEDIT5) format, while the 64-bit registry entries use the Windows Registry Editor Version 6.0 (REGEDIT6)
IF %ARCH%==x64 (
  FOR /F "TOKENS=*" %%G IN ( regbad.cfg ) DO @(
  REG DELETE "%%G" /REG:64 /F >NUL 2>&1
  IF NOT ERRORLEVEL 1 (
    ECHO."%%G">>"%TEMP%\004"
    )
  )
)

IF %ARCH%==x86 (
  FOR /F "TOKENS=*" %%G IN ( regbad.cfg ) DO @(
  REG DELETE "%%G" /REG:32 /F >NUL 2>&1
  IF NOT ERRORLEVEL 1 (
    ECHO."%%G">>"%TEMP%\004"
    )
  )
)

:TidyReg2
IF EXIST "%TEMP%\FMRSlogh.txt" @DEL /F/Q "%TEMP%\FMRSlogh.txt" >NUL 2>&1
REG QUERY HKLM\Software\Microsoft\Tracing 2>NUL|"%GREP%" -Es "RAS[A-Z0-9]{5}$">"%TEMP%\FMRSlogh.txt"
REG QUERY HKCU\Software 2>NUL|"%GREP%" -Eis "\\Rmc-[A-Z0-9]{6}$">>"%TEMP%\FMRSlogh.txt"
FOR /F "usebackq delims=" %%G in ("%TEMP%\FMRSlogh.txt") DO (
   ECHO."%%G">>"%TEMP%\004"
   REG DELETE "%%G" /F >NUL 2>&1
)

:DoLog
ECHO.# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #>"%TEMP%\FMRS.txt"
ECHO.# Furtivex Malware Removal Script v5.6.6>>"%TEMP%\FMRS.txt"
ECHO.# https://furtivex.net>>"%TEMP%\FMRS.txt"
ECHO.# %Log_Microsoft% %OS% %ARCH% %DisplayVersion% %LanguageCode% // %ACPCode% // %OEMCPCode%>>"%TEMP%\FMRS.txt"
ECHO.# %datetime% - "%username%">>"%TEMP%\FMRS.txt"
ECHO.# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
ECHO.# %Log_Processes%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
IF EXIST "%TEMP%\005" (
  "%SORT%" -f -u <"%TEMP%\005" >"%TEMP%\005rdy"
  "%SED%" -r "s/\\\\/\\/g" <"%TEMP%\005rdy" >"%TEMP%\005rdy2"
  TYPE "%TEMP%\005rdy2">>"%TEMP%\FMRS.txt"
  echo.>>"%TEMP%\FMRS.txt"
)

ECHO.# %Log_Drivers%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
IF EXIST "%TEMP%\000" (
  "%SORT%" -f -u <"%TEMP%\000" >"%TEMP%\000rdy"
  TYPE "%TEMP%\000rdy">>"%TEMP%\FMRS.txt"
  echo.>>"%TEMP%\FMRS.txt"
)

ECHO.# %Log_Services%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
IF EXIST "%TEMP%\000b" (
  "%SORT%" -f -u <"%TEMP%\000b" >"%TEMP%\000brdy"
  TYPE "%TEMP%\000brdy">>"%TEMP%\FMRS.txt"
  echo.>>"%TEMP%\FMRS.txt"
)

ECHO.# %Log_Files%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
  IF EXIST "%TEMP%\001" (
  "%SORT%" -f -u <"%TEMP%\001" >"%TEMP%\001_rdy"
  TYPE "%TEMP%\001_rdy">>"%TEMP%\FMRS.txt"
  echo.>>"%TEMP%\FMRS.txt"
)

ECHO.# %Log_Folders%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
IF EXIST "%TEMP%\001b" (
  "%SORT%" -f -u <"%TEMP%\001b" >"%temp%\001brdy"
  TYPE "%TEMP%\001brdy">>"%TEMP%\FMRS.txt"
  echo.>>"%TEMP%\FMRS.txt"
)

ECHO.# %Log_Tasks%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
IF EXIST "%TEMP%\002" (
  "%SORT%" -f -u <"%TEMP%\002" >"%TEMP%\002rdy"
  TYPE "%TEMP%\002rdy">>"%TEMP%\FMRS.txt"
  echo.>>"%TEMP%\FMRS.txt"
)

ECHO.# %Log_Registry%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
IF EXIST "%TEMP%\004" (
  "%SORT%" -f -u <"%TEMP%\004" >"%TEMP%\004rdy"
  TYPE "%TEMP%\004rdy">>"%TEMP%\FMRS.txt"
  echo.>>"%TEMP%\FMRS.txt"
)

ECHO.# %Log_Miscellaneous%:>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
IF EXIST "%TEMP%\006" (
  "%SORT%" -f -u <"%TEMP%\006" >"%TEMP%\006rdy"
  TYPE "%TEMP%\006rdy">>"%TEMP%\FMRS.txt"
)

ECHO.%RestorePoint%>>"%TEMP%\FMRS.txt"
ECHO.

IF EXIST "%TEMP%\bl00" (
  TYPE "%TEMP%\bl00">>"%TEMP%\FMRS.txt"
)

IF EXIST "%TEMP%\jm00" (
  TYPE "%TEMP%\jm00">>"%TEMP%\FMRS.txt"
)

IF EXIST "%TEMP%\cdumps00" (
  TYPE "%TEMP%\cdumps00">>"%TEMP%\FMRS.txt"
)
IF EXIST "%TEMP%\m1ss1ng00" (
  ECHO.>>"%TEMP%\FMRS.txt"
  TYPE "%TEMP%\m1ss1ng00">>"%TEMP%\FMRS.txt"
)

echo.>>"%TEMP%\FMRS.txt"
echo.>>"%TEMP%\FMRS.txt"
ECHO.# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #>>"%TEMP%\FMRS.txt"
"%SED%" -r "s/(\x22|\x00+)//g; s/Sysnative/System32/; s/HKEY_LOCAL_MACHINE/HKLM/; s/HKEY_CURRENT_USER/HKCU/; s/HKEY_CLASSES_ROOT/HKCR/; s/HKEY_USERS/HKU/" <"%TEMP%\FMRS.txt" >"%SYSTEMDRIVE%\FMRS_%datetime%.txt"

IF EXIST "%USERPROFILE%\OneDrive\Desktop" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\OneDrive\Desktop\FMRS_%datetime%.txt" >NUL 2>&1
IF EXIST "%USERPROFILE%\OneDrive\Escritorio" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\OneDrive\Escritorio\FMRS_%datetime%.txt" >NUL 2>&1
IF EXIST "%USERPROFILE%\OneDrive\Рабочий стол" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\OneDrive\Рабочий стол\FMRS_%datetime%.txt" >NUL 2>&1
IF EXIST "%USERPROFILE%\OneDrive\Pulpit" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\OneDrive\Pulpit\FMRS_%datetime%.txt" >NUL 2>&1

IF EXIST "%USERPROFILE%\Desktop" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\Desktop\FMRS_%datetime%.txt" >NUL 2>&1
IF EXIST "%USERPROFILE%\Escritorio" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\Escritorio\FMRS_%datetime%.txt" >NUL 2>&1
IF EXIST "%USERPROFILE%\Рабочий стол" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\Рабочий стол\FMRS_%datetime%.txt" >NUL 2>&1
IF EXIST "%USERPROFILE%\Pulpit" @COPY /Y "%SYSTEMDRIVE%\FMRS_%datetime%.txt" "%USERPROFILE%\Pulpit\FMRS_%datetime%.txt" >NUL 2>&1

IF EXIST %WINDIR%\regedit.exe @REGEDIT /S helpdefend.reg

:Abort
REM ~~~~~ Restore original settings ~~~~
REG COPY HKCU\Console_furtivex HKCU\Console /S /F >NUL 2>&1
REG DELETE HKCU\Console_furtivex /F >NUL 2>&1

FOR %%G in (
acp0?
allusersprofile0?
appdata0?
bl0?
cdumps0?
common320?
common640?
hiddenav0?
info0?
jm0?
lang0?
locala0?
locallow0?
m1ss1ng0?
oemcp0?
programfiles320?
programfiles640?
PSproc??
public0?
python0?
startup0?
redline0?
runonce0?
svc0?
sys32appdata0?
SysWOW640?
tasks0?
temp0?
userprofileappdata0?
users0?
WTASKS0?
w1tchav0?
WMICproc??
) DO @(
  DEL /F/Q "%CD%\%%G" >NUL 2>&1
  DEL /F/Q "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\%%G" >NUL 2>&1
)

RD /S/Q "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh\dependencies" >NUL 2>&1

DEL /F/S/Q "%TEMP%\*" >NUL 2>&1
RD /S/Q "%TEMP%\APPX.sqsea8jx7jvjxqrpbw2ybdelh" >NUL 2>&1
:eof