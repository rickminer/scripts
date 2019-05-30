@ECHO OFF

SETLOCAL EnableDelayedExpansion EnableExtensions
PUSHD %~dp0..

:DRIVE_PROMPT
wmic logicaldisk where "DriveType=2" get Name,VolumeName,Size
SET /P DRIVE=Enter the drive (with colon) you would like to install/update the tools to: 

IF NOT EXIST %DRIVE% GOTO DRIVE_PROMPT
FOR /F "tokens=2 delims==" %%X IN ('wmic logicaldisk where "Caption='%DRIVE%'" get DriveType /format:list') do SET _type=%%X
IF "%_type%" NEQ "2" GOTO USAGE

ROBOCOPY .\ %DRIVE%\ *.* /E

:EXIT
POPD
ENDLOCAL