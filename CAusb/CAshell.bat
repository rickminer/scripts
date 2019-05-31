@ECHO OFF

PUSHD %~dp0
PATH %PATH%;%~dp0tools\bin;%~dp0tools;"%~dp0tools\YubiKey Manager";"%~dp0tools\YubiKey Personalization Tool";
SETLOCAL

:: Setup DOSKEY aliases
DOSKEY Setup-YubiKey="yubikey-personalization-gui.exe"
DOSKEY Manage-PIV="ykman-gui.exe"

ECHO.
ECHO ##################################################
ECHO ###                                            ###
ECHO ###            NMFS Identity CA USB            ###
ECHO ###                                            ###
ECHO ##################################################
ECHO.
ECHO.
ECHO This USB contains the tools for the NMFS Identity
ECHO CA. Below is a summary of the tools available.
ECHO.
ECHO.
:: Call the usage information for all of the batch files, put the batch file name as the first argument
FOR /F %%I IN ('DIR /B \tools\*-*.bat') DO CALL :USAGE %%I
ECHO Usage: Setup-YubiKey
ECHO     This tool runs the personalization tool.
ECHO.
ECHO Usage: Manage-PIV
ECHO     This tool provides a graphical way to see and
ECHO     manage the smartcard applet on the Yubikey.
ECHO.
ENDLOCAL
IF NOT DEFINED CA_START @(cmd /Q /E:ON /V:ON /K "set CA_START=Y")
GOTO :EOF

:USAGE
:: Call the Usage Label for the file provied in %1
SET BATCH=%1
SHIFT
%BATCH% %*