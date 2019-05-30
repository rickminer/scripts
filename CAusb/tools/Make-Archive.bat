@ECHO OFF
SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~d0\

PATH %~dp0bin;%PATH%

:: Create the self-installing EXE for importing
:: First create the config.txt
ECHO ;^^!@Install@^^!UTF-8^^!> temp.txt
ECHO Title="NMFS CA Installer v1.0">> temp.txt
ECHO BeginPrompt="USB Key must be inserted. Do you want to continue?">> temp.txt
ECHO ExecuteFile="cmd.exe">>temp.txt
ECHO ExecuteParameters="/C \"tools\bin\install.bat\"">> temp.txt
ECHO ;^^!@InstallEnd@^^!>> temp.txt

:: Convert to UTF-8
powershell -command "Get-Content temp.txt | Set-Content -Encoding utf8 config.txt"

7zr a CAtools.7z *.ico *.inf *.bat tools .git .gitignore

:: add date to the installer
FOR /F "tokens=6" %%i IN (.git\logs\HEAD) DO @(FOR /F %%j IN ('powershell -command "'{0:yyyyMMdd}' -f ([datetime]'1970-01-01 00:00:00').AddSeconds(%%i)"') DO @SET DATE=%%j)

COPY /B tools\bin\7zSD.sfx + config.txt + CATools.7z Install_CA_%DATE%.exe

DEL /Q /F temp.txt config.txt CATools.7z
GOTO EXIT

:USAGE
ECHO Usage: %~nx0 
ECHO.
ECHO     This tool creates an update installer for the tools and scripts required for this functionality.
ECHO.

:EXIT
POPD
ENDLOCAL