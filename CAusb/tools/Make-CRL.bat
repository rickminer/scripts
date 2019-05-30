@ECHO OFF
SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~dp0

:: Require the username of the signing token
if [%~1]==[] GOTO USAGE

PATH %~dp0bin;%dp0%yubico-piv-tool\bin;%PATH%
SET RANDFILE=%~dp0.rnd
SET CA_NAME=signing-ca-%~1
SET CA_DIR=..\auth\%CA_NAME%
SET ROOTDIR=..\auth\root-ca

:: Create root-ca CRL
openssl ca -batch -gencrl -config etc\root-ca.conf -out %ROOTDIR%\crl\root-ca.crl -passin file:%ROOTDIR%\private\root-ca.pwd
COPY /Y %ROOTDIR%\crl\root-ca.crl ..\

:: Create signing CA crls
FOR /F %%C IN ('DIR /B /S ..\auth\*.conf') DO @CALL :GENCRL "%%C"

GOTO EXIT

:GENCRL
openssl ca -batch -gencrl -config %1 -out %~dp1crl\%~n1.crl -passin file:%~dp1private\%~n1.pwd
COPY /Y %~dp1crl\%~n1.crl ..\
GOTO EXIT

:USAGE
ECHO Usage: %~nx0 ^<SIGNINGCA^>
ECHO.
ECHO     This tool updates the CRL for the CAs present in the auth folder.
ECHO.

:EXIT
POPD
ENDLOCAL