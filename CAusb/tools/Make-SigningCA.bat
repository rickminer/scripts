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
SET TARGET=%~d2

:: Check to see if signing CA exists, if it does just prompt for the USB creation
IF EXIST %CA_DIR% GOTO SETUP_DRIVE

::Create Directories
MKDIR %CA_DIR%\private
MKDIR %CA_DIR%\db
MKDIR %CA_DIR%\crl
MKDIR %CA_DIR%\certs

::Create database
COPY nul %CA_DIR%\db\%CA_NAME%.db > nul
COPY nul %CA_DIR%\db\%CA_NAME%.db.attr > nul
ECHO 01 > %CA_DIR%\db\%CA_NAME%.crt.srl
ECHO 01 > %CA_DIR%\db\%CA_NAME%.crl.srl

:: Create signing-ca certificate passphrase
FOR /F %%P IN ('openssl rand -base64 24 2^> nul') do @(echo.| SET /P ="%%P" > %CA_DIR%\private\%CA_NAME%.pwd)

:: Create signing-ca configuration file
sed "s/{USERNAME}/%~1/g" etc\signing-ca.conf > %CA_DIR%\%CA_NAME%.conf

:: Create CA request
openssl req -new -config %CA_DIR%\%CA_NAME%.conf -out %CA_DIR%\%CA_NAME%.csr -keyout %CA_DIR%\private\%CA_NAME%.key -passout file:%CA_DIR%\private\%CA_NAME%.pwd

:: Create CA certificate
openssl ca -batch -config etc\root-ca.conf -in %CA_DIR%\%CA_NAME%.csr -out ..\%CA_NAME%.crt -extensions signing_ca_ext -passin file:%ROOTDIR%\private\root-ca.pwd

:: Make CA CRL certificate to root
openssl ca -batch -gencrl -config %CA_DIR%\%CA_NAME%.conf -out %CA_DIR%\crl\%CA_NAME%.crl -passin file:%CA_DIR%\private\%CA_NAME%.pwd
COPY /Y %CA_DIR%\crl\%CA_NAME%.crl ..\

DEL /Q /F %CA_DIR%\%CA_NAME%.csr

:SETUP_DRIVE
SET /P SETUP=Do you want to setup the USB stick now (Y/N)? 
IF /I "%SETUP%" EQU "N" GOTO EXIT
IF /I "%SETUP%" EQU "NO" GOTO EXIT

:: Make sure that target drive is removable media
:: DriveType: 0-Unknown, 1-No Root Dir, 2-Removable Disk, 3-Local Disk, 4-Network Drive, 5-CD, 6-RAM Disk
if [%~2]==[] GOTO USAGE
SET TARGET=%~d2
IF NOT EXIST %TARGET% GOTO USAGE
FOR /F "tokens=2 delims==" %%X IN ('wmic logicaldisk where "Caption='%TARGET%'" get DriveType /format:list') do SET _type=%%X
IF "%_type%" NEQ "2" GOTO USAGE

:: Warning
ECHO WARNING!! This will erase all contents of %TARGET%. Hit ENTER to continue...
PAUSE

:: Format target drive
FORMAT %TARGET% /FS:NTFS /Q /V:CA_USB

:: BitLocker Encrypt target drive
ECHO Configure %TARGET% to be encrypted with BitLocker and a smartcard
BitLockerWizard %TARGET% T

:: Copy the current folder structure
COPY /Y ..\*.* tools %TARGET%\
MKDIR %TARGET%\issued
MKDIR %TARGET%\auth
MOVE /Y %CA_DIR% %TARGET%\auth\

GOTO EXIT

:USAGE
ECHO Usage: %~nx0 ^<USERNAME^> ^<DEST^>
ECHO     USERNAME    The username of the person who will have the signing token CA
ECHO     DEST        The drive letter of the destination USB drive (eg F:), this will
ECHO                 erase the contents of the drive
ECHO.
ECHO     This tool is used for creating a new Signing CA. It requires the username
ECHO     of the person who will be using the signing CA to create NMFS Identity
ECHO     YubiKeys.Then the tool can move all of the necessary files and folders for
ECHO     the signing CA to a USB. You can just setup the CA with USERNAME and then
ECHO     come back later to setup the USB. IF the CA directory is present it will
ECHO     immediately prompt for the USB creation.
ECHO.

:EXIT
POPD
ENDLOCAL