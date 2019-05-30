@ECHO OFF

:: Require the username of the signing token
if [%~1]==[] GOTO USAGE
if [%~2]==[] GOTO USAGE
:: Check for valid reasons
if [%~2] EQU [keyCompromise] GOTO START
if [%~2] EQU [CACompromise] GOTO START
if [%~2] EQU [superseded] GOTO START
if [%~2] EQU [cessationOfOperation] GOTO START
GOTO USAGE

:START
SETLOCAL EnableDelayedExpansion EnableExtensions
SET CERT_DIR=%~dp1
PUSHD %~dp0
PATH %~dp0bin;%dp0%yubico-piv-tool\bin;%PATH%
SET RANDFILE=%~dp0.rnd

:: Determine conf file
SET CA=%CERT_DIR:~8,-7%
SET CA_DIR=%CERT_DIR:~0,-7%
IF [%CA%] EQU [root-ca] (
    SET CONF=etc\root-ca.conf
) ELSE (
    SET CONF=%CA_DIR%\%CA%.conf
)

:: Revoke Certificate
openssl ca -batch -config %CONF% -revoke %CERT_DIR%\%~nx1 -crl_reason %~2 -passin file:%CA_DIR%\private\%CA%.pwd

:: Update CRL
create_crl

ECHO Make sure to upload the CRL to the distribution point.

GOTO EXIT

:USAGE
ECHO Usage: %~nx0 ^<CERT^> ^<REASON^>
ECHO     CERT        The location in the auth folder of the issued certificate file
ECHO     REASON      One of these values: keyCompromise, CACompromise, superseded,
ECHO                 or cessationOfOperation
ECHO.
ECHO     This tool revokes a certificate. To use you must give the file location
ECHO     for the certificate you wish to revoke and a reason for doing so. The
ECHO     reason must be one of these values: keyCompromise, CACompromise,
ECHO     superseded, or cessationOfOperation.
ECHO.

:EXIT
POPD
ENDLOCAL