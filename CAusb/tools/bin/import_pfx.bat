@ECHO OFF

SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~dp0..
:: Require the username of the signing token
IF NOT DEFINED KEY GOTO USAGE
IF NOT DEFINED PW GOTO USAGE
IF NOT EXIST *auth.pfx GOTO USAGE
IF NOT EXIST *sign.pfx GOTO USAGE
IF NOT EXIST *mgmt.pfx GOTO USAGE
IF NOT EXIST yubico-piv-tool GOTO USAGE

PATH %dp0%yubico-piv-tool\bin;%PATH%

:: Get PIV_NAME
FOR /F "tokens=1,2 delims=-" %%X in ('dir /b *auth.pfx') DO SET PIV_NAME=%%X-%%Y

yubico-piv-tool --key=%KEY% -a import-key -a import-certificate -s 9a -K PKCS12 -p %PW% -i %PIV_NAME%-auth.pfx
yubico-piv-tool --key=%KEY% -a import-key -a import-certificate -s 9c -K PKCS12 -p %PW% -i %PIV_NAME%-sign.pfx
yubico-piv-tool --key=%KEY% -a import-key -a import-certificate -s 9d -K PKCS12 -p %PW% -i %PIV_NAME%-mgmt.pfx

:: Set CHUID
yubico-piv-tool --key=%KEY% -a set-chuid

:END
GOTO EXIT

:USAGE
ECHO Usage: %~nx0
ECHO.
ECHO     This script depends on several things. First, two environment variables:
ECHO         KEY        This is the management key for the YubiKey
ECHO         PW         This is the password for the private keys in the PKCS12 files
ECHO.
ECHO     Second, three PKCS12/PFX files in the same directory:
ECHO         auth.pfx   This is the authentication certificate (slot 9a)
ECHO         sign.pfx   This is the signature certificate (slot 9c)
ECHO         mgmt.pfx   This is the management certificate (slot 9d)
ECHO.
ECHO.

:EXIT
POPD
ENDLOCAL