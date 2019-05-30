@ECHO OFF

SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~dp0
PATH %~dp0bin;%dp0%yubico-piv-tool\bin;%PATH%
SET RANDFILE=%~dp0.rnd
SET ROOTDIR=..\auth\root-ca

::Create Directories
mkdir %ROOTDIR%\private
mkdir %ROOTDIR%\db
mkdir %ROOTDIR%\crl
mkdir %ROOTDIR%\certs

::Create database
copy nul %ROOTDIR%\db\root-ca.db > nul
copy nul %ROOTDIR%\db\root-ca.db.attr > nul
echo 01 > %ROOTDIR%\db\root-ca.crt.srl
echo 01 > %ROOTDIR%\db\root-ca.crl.srl

:: Create root-ca certificate passphrase
FOR /F %%P IN ('openssl rand -base64 24 2^> nul') do @echo %%P>%ROOTDIR%\private\root-ca.pwd

:: Create CA request
openssl req -new -config etc\root-ca.conf -out %ROOTDIR%\root-ca.csr -keyout %ROOTDIR%\private\root-ca.key -passout file:%ROOTDIR%\private\root-ca.pwd

:: Create CA certificate
openssl ca -batch -selfsign -config etc\root-ca.conf -in %ROOTDIR%\root-ca.csr -out ..\root-ca.crt -extensions root_ca_ext -passin file:%ROOTDIR%\private\root-ca.pwd

DEL /Q /F %ROOTDIR%\root-ca.csr

GOTO EXIT

:USAGE
ECHO Usage: %~nx0 
ECHO     This tool is used for creating a new Root CA. It will overwrite the current
ECHO     CA so make sure to copy the old CA data for any backup purposes.
ECHO.

:EXIT
POPD
ENDLOCAL