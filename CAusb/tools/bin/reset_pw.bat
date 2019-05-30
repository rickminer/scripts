@ECHO OFF

SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~dp0..
:: Require the username of the signing token
IF NOT DEFINED KEY ECHO ERROR: Missing KEY variable. && GOTO USAGE
IF NOT DEFINED PUK ECHO ERROR: Missing PUK variable. && GOTO USAGE
IF NOT EXIST yubico-piv-tool ECHO ERROR: Missing piv-tool. && GOTO USAGE

PATH %CD%\yubico-piv-tool\bin;%PATH%

:: Reset the YubiKey NEO PIV applet
yubico-piv-tool -a verify-pin -P 4711 2> nul
yubico-piv-tool -a verify-pin -P 4711 2> nul
yubico-piv-tool -a verify-pin -P 4711 2> nul
yubico-piv-tool -a change-puk -P 4711 -N 67567 2> nul
yubico-piv-tool -a change-puk -P 4711 -N 67567 2> nul
yubico-piv-tool -a change-puk -P 4711 -N 67567 2> nul
yubico-piv-tool -a reset

yubico-piv-tool -a set-mgm-key -n %KEY% 2> nul
yubico-piv-tool --key=%KEY% -a change-puk -P 12345678 -N %PUK% 2>nul
yubico-piv-tool --key=%KEY% -a change-pin -P 123456

PAUSE

:END
GOTO EXIT

:USAGE
ECHO Usage: %~nx0
ECHO.
ECHO     This script depends on some information. First, an environment variables:
ECHO         KEY      This is the mgmt key for the YubiKey
ECHO         PUK      This is the PUK for the YubiKey
ECHO.

:EXIT
POPD
ENDLOCAL