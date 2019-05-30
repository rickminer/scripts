@ECHO OFF

:: Require the username of the signing token
if [%~1]==[] GOTO USAGE

SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~dp0
PATH %~dp0bin;%dp0%yubico-piv-tool\bin;%PATH%
SET RANDFILE=%~dp0.rnd
SET PIV_NAME=piv-%~1
SET PIV_DIR=..\issued\%PIV_NAME%
:: Add number if multiple directories exist
FOR /F "delims=~ tokens=1,2" %%X IN ('dir /B %PIV_DIR%* 2^>nul') DO SET /A "_N=%%Y+0"
IF DEFINED _N IF _N GTR 0 SET PIV_DIR=%PIV_DIR%~%_N%

IF NOT EXIST %PIV_DIR% ECHO ERROR: CN not found: %PIV_DIR%. && GOTO USAGE

:: Get the KEY and PUK
FOR /F "tokens=1,2,3 delims=: " %%X IN (%PIV_DIR%\%PIV_NAME%-PINs.txt) DO IF "%%Z" NEQ "" (SET %%Y=%%Z) ELSE (SET %%X=%%Y)

:: Create the self-installing EXE for importing
:: First create the config.txt
ECHO ;^^!@Install@^^!UTF-8^^!> %PIV_DIR%\temp.txt
ECHO Title="NMFS YubiKey PIN Reset Tool v1.0">> %PIV_DIR%\temp.txt
ECHO BeginPrompt="YubiKey must be inserted. Do you want to continue?">> %PIV_DIR%\temp.txt
ECHO ExecuteFile="cmd.exe">> %PIV_DIR%\temp.txt
ECHO ExecuteParameters="/C \"SET \"KEY=%KEY%\" ^&^& SET \"PUK=%PUK%\" ^&^& bin\reset_pw.bat\"">> %PIV_DIR%\temp.txt
ECHO MiscFlags="4">> %PIV_DIR%\temp.txt
ECHO ;^^!@InstallEnd@^^!>> %PIV_DIR%\temp.txt

:: Convert to UTF-8
powershell -command "Get-Content %PIV_DIR%\temp.txt | Set-Content -Encoding utf8 %PIV_DIR%\config.txt"

:: Zip required files
7zr a %PIV_DIR%\reset.7z yubico-piv-tool bin\reset_pw.bat

:: Create exe
COPY /B bin\7zSD.sfx + %PIV_DIR%\config.txt + %PIV_DIR%\reset.7z %PIV_DIR%\reset_pw_%PIV_NAME%.exe

:END
:: Remove files for PIV except for the PIN,PUK,MGMT codes
DEL /Q /F %PIV_DIR%\temp.txt %PIV_DIR%\config.txt %PIV_DIR%\reset.7z
GOTO EXIT

:USAGE
ECHO Usage: %~nx0 ^<CN^>
ECHO     CN          The common name, usually the email address or username of the
ECHO                 person who will have the PIV
ECHO.
ECHO     A self running tool to reset a PIN is generated. the tool will prompt the
ECHO     user for the new PIN.
ECHO.

:EXIT
POPD
ENDLOCAL