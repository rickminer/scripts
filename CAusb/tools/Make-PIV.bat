@ECHO OFF

:: Require the username of the signing token
if [%~1]==[] GOTO USAGE
if [%~2]==[] GOTO USAGE

SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~dp0
PATH %~dp0bin;%dp0%yubico-piv-tool\bin;%PATH%
SET RANDFILE=%~dp0.rnd
SET CA_NAME=signing-ca-%~1
SET CA_DIR=..\auth\%CA_NAME%
SET PIV_NAME=piv-%~2
SET PIV_DIR=..\issued\%PIV_NAME%
:: Add number if multiple directories exist
FOR /F "delims=~ tokens=1,2" %%X IN ('dir /B %PIV_DIR%* 2^>nul') DO SET /A "_N=%%Y+1"
IF DEFINED _N SET PIV_DIR=%PIV_DIR%~%_N%
MKDIR %PIV_DIR%

:START
:: Create certificate passphrase
FOR /F %%P IN ('openssl rand -base64 24 2^> nul') DO @(echo.| SET /P ="%%P"> %CA_DIR%\private\%PIV_NAME%.pwd)

:: Create signing-ca configuration file
sed "s/{USERNAME}/%~2/g" etc\piv.conf > %PIV_DIR%\%PIV_NAME%.conf

:: Create AUTH CSR
openssl req -new -config %PIV_DIR%\%PIV_NAME%.conf -out %CA_DIR%\%PIV_NAME%-auth.csr -keyout %CA_DIR%\private\%PIV_NAME%-auth.key -passout file:%CA_DIR%\private\%PIV_NAME%.pwd
:: Create SIGN CSR
openssl req -new -config %PIV_DIR%\%PIV_NAME%.conf -out %CA_DIR%\%PIV_NAME%-sign.csr -keyout %CA_DIR%\private\%PIV_NAME%-sign.key -passout file:%CA_DIR%\private\%PIV_NAME%.pwd
:: Create MGMT CSR
openssl req -new -config %PIV_DIR%\%PIV_NAME%.conf -out %CA_DIR%\%PIV_NAME%-mgmt.csr -keyout %CA_DIR%\private\%PIV_NAME%-mgmt.key -passout file:%CA_DIR%\private\%PIV_NAME%.pwd

:: Sign certificates
openssl ca -batch -config %CA_DIR%\%CA_NAME%.conf -in %CA_DIR%\%PIV_NAME%-auth.csr -out %PIV_DIR%\%PIV_NAME%-auth.crt -extensions auth_ext -passin file:%CA_DIR%\private\%CA_NAME%.pwd
openssl ca -batch -config %CA_DIR%\%CA_NAME%.conf -in %CA_DIR%\%PIV_NAME%-sign.csr -out %PIV_DIR%\%PIV_NAME%-sign.crt -extensions sign_ext -passin file:%CA_DIR%\private\%CA_NAME%.pwd
openssl ca -batch -config %CA_DIR%\%CA_NAME%.conf -in %CA_DIR%\%PIV_NAME%-mgmt.csr -out %PIV_DIR%\%PIV_NAME%-mgmt.crt -extensions mgmt_ext -passin file:%CA_DIR%\private\%CA_NAME%.pwd

:: Check to see if this is for a new key or a new certificate, if this user already has a key use the same PIN, PUK, etc.
IF EXIST ..\issued\%PIV_NAME% GOTO EXISTING_KEY

:NEW_KEY
:: Create new PIN, PUK, Management key
FOR /F %%K IN ('openssl rand 48 2^> nul ^| hexdump -v -e "/1 ""%%02X""" ^| cut -c1-48') DO @IF [%%K] EQU [] (GOTO START) ELSE (SET KEY=%%K)
ECHO MGMT KEY: %KEY% > %PIV_DIR%\%PIV_NAME%-PINs.txt
FOR /F %%K IN ('openssl rand 6 2^> nul ^| hexdump -v -e "/1 ""%%u""" ^| cut -c1-6') DO @SET PIN=%%K
ECHO Initial PIN: %PIN% >> %PIV_DIR%\%PIV_NAME%-PINs.txt
FOR /F %%K IN ('openssl rand 6 2^> nul ^| hexdump -v -e "/1 ""%%u""" ^| cut -c1-8') DO @SET PUK=%%K
ECHO PUK: %PUK% >>%PIV_DIR%\%PIV_NAME%-PINs.txt

GOTO POST_PIN

:EXISTING_KEY
IF NOT EXIST ..\issued\%PIV_NAME%\%PIV_NAME%-PINs.txt ECHO PINs file does not exist at ..\issued\%PIV_NAME% && GOTO NEW_KEY
COPY /Y ..\issued\%PIV_NAME%\%PIV_NAME%-PINs.txt %PIV_DIR%\
FOR /F "tokens=1,2,3 delims=: " %%X IN (%PIV_DIR%\%PIV_NAME%-PINs.txt) DO IF "%%Z" NEQ "" (SET %%Y=%%Z) ELSE (SET %%X=%%Y)

:POST_PIN
:: Duplicate password so that PFX works correctly and store for exe
ECHO.>>%CA_DIR%\private\%PIV_NAME%.pwd
FOR /F %%P IN (%CA_DIR%\private\%PIV_NAME%.pwd) DO @(
  ECHO.| SET /P ="%%P">> %CA_DIR%\private\%PIV_NAME%.pwd
  SET PW=%%P
  )
dos2unix %CA_DIR%\private\%PIV_NAME%.pwd

:: Create PKCS12/PFX files for self installing certificates
openssl pkcs12 -export -nodes -out %PIV_DIR%\%PIV_NAME%-auth.pfx -inkey %CA_DIR%\private\%PIV_NAME%-auth.key -in %PIV_DIR%\%PIV_NAME%-auth.crt -passin file:%CA_DIR%\private\%PIV_NAME%.pwd -passout file:%CA_DIR%\private\%PIV_NAME%.pwd
openssl pkcs12 -export -nodes -out %PIV_DIR%\%PIV_NAME%-sign.pfx -inkey %CA_DIR%\private\%PIV_NAME%-sign.key -in %PIV_DIR%\%PIV_NAME%-sign.crt -passin file:%CA_DIR%\private\%PIV_NAME%.pwd -passout file:%CA_DIR%\private\%PIV_NAME%.pwd
openssl pkcs12 -export -nodes -out %PIV_DIR%\%PIV_NAME%-mgmt.pfx -inkey %CA_DIR%\private\%PIV_NAME%-mgmt.key -in %PIV_DIR%\%PIV_NAME%-mgmt.crt -passin file:%CA_DIR%\private\%PIV_NAME%.pwd -passout file:%CA_DIR%\private\%PIV_NAME%.pwd

:: Create the self-installing EXE for importing
:: First create the config.txt
ECHO ;^^!@Install@^^!UTF-8^^!> %PIV_DIR%\temp.txt
ECHO Title="NMFS YubiKey Certificate Installer v1.0">> %PIV_DIR%\temp.txt
ECHO BeginPrompt="YubiKey must be inserted. Do you want to continue?">> %PIV_DIR%\temp.txt
ECHO ExecuteFile="cmd.exe">> %PIV_DIR%\temp.txt
ECHO ExecuteParameters="/C \"SET \"KEY=%KEY%\" ^&^& SET \"PW=%PW%\" ^&^& import_pfx.bat\"">> %PIV_DIR%\temp.txt
ECHO ;^^!@InstallEnd@^^!>> %PIV_DIR%\temp.txt

:: Convert to UTF-8
powershell -command "Get-Content %PIV_DIR%\temp.txt | Set-Content -Encoding utf8 %PIV_DIR%\config.txt"

:: Zip required files
7zr a %PIV_DIR%\certs.7z %PIV_DIR%\*.pfx yubico-piv-tool bin\import_pfx.bat

:: Create exe
COPY /B bin\7zSD.sfx + %PIV_DIR%\config.txt + %PIV_DIR%\certs.7z %PIV_DIR%\install_certs_%PIV_NAME%.exe

SET /P SETUP=Do you want to install to a Yubikey now (Y/N)? 
IF /I "%SETUP%" EQU "N" GOTO END
IF /I "%SETUP%" EQU "NO" GOTO END

:INSERT
ykinfo -s > nul 2>&1
IF %ERRORLEVEL% GTR 0 ECHO Please insert Yubikey. && PAUSE && GOTO INSERT

ykinfo -s -v

:: Enable CCID
ykpersonalize -m 6 -y

ECHO Remove and re-insert YubiKey. && PAUSE

:: Reset the YubiKey NEO PIV applet
yubico-piv-tool -a verify-pin -P 4711 2> nul
yubico-piv-tool -a verify-pin -P 4711 2> nul
yubico-piv-tool -a verify-pin -P 4711 2> nul
yubico-piv-tool -a change-puk -P 4711 -N 675678 2> nul
yubico-piv-tool -a change-puk -P 4711 -N 675678 2> nul
yubico-piv-tool -a change-puk -P 4711 -N 675678 2> nul
yubico-piv-tool -a reset

yubico-piv-tool -a set-mgm-key -n %KEY%
yubico-piv-tool --key=%KEY% -a change-pin -P 123456 -N %PIN%
yubico-piv-tool --key=%KEY% -a change-puk -P 12345678 -N %PUK%

:: Import certificates and keys to NEO
:: Auth - 9a
yubico-piv-tool --key=%KEY% -a import-key -a import-certificate -s 9a -K PKCS12 -p %PW% -i %PIV_DIR%\%PIV_NAME%-auth.pfx
:: Sign - 9c
yubico-piv-tool --key=%KEY% -a import-key -a import-certificate -s 9c -K PKCS12 -p %PW% -i %PIV_DIR%\%PIV_NAME%-sign.pfx
:: Mgmt - 9d
yubico-piv-tool --key=%KEY% -a import-key -a import-certificate -s 9d -K PKCS12 -p %PW% -i %PIV_DIR%\%PIV_NAME%-mgmt.pfx

:: Set CHUID
yubico-piv-tool --key=%KEY% -a set-chuid

yubico-piv-tool -a status

:END
:: Remove files for PIV except for the PIN,PUK,MGMT codes
DEL /Q /F %CA_DIR%\private\%PIV_NAME%*.key %CA_DIR%\private\%PIV_NAME%*.pwd %CA_DIR%\%PIV_NAME%*.csr %PIV_DIR%\temp.txt %PIV_DIR%\config.txt %PIV_DIR%\certs.7z %PIV_DIR%\*.pfx
GOTO EXIT

:USAGE
ECHO Usage: %~nx0 ^<CA^> ^<CN^>
ECHO     CA          The name of the signing CA (eg Rick.Miner, will translate to
ECHO                 signing-ca-Rick.Miner)
ECHO     CN          The common name, usually the email address or username of the
ECHO                 person who will have the PIV
ECHO.
ECHO     This tool creates the certificates required for a YubiKey PIV card. It then
ECHO     can put thecertificates onto the YubiKey. If an existing key exists for the
ECHO     same CN then the same PINs will be used. A self-installing certificate tool
ECHO     will also be created.
ECHO.

:EXIT
POPD
ENDLOCAL