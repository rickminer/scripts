@ECHO OFF

PUSHD %~dp0
PATH %PATH%;%~dp0tools\bin;%~dp0tools;"%~dp0tools\YubiKey NEO Manager";"%~dp0tools\YubiKey PIV Manager";
SETLOCAL

:: Setup DOSKEY aliases
DOSKEY Setup-NEO="neoman.exe"
DOSKEY Manage-PIV="pivman.exe"

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
ECHO Usage: Setup-NEO
ECHO     This tool allows for turning on the CCID of
ECHO     the YubiKey NEO allowing for smartcard use.
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