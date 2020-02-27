::ffmpeg -i "Instant Meeting 2016-05-04.webm" -ss 00:00:00 -t 01:33:53 -codec copy test.webm
::ffmpeg -i "Instant Meeting 2016-05-04.webm" -codec copy -f segment -segment_time 00:30:00 -map 0 "Instant Meeting 2016-05-04 %03d.webm"
@ECHO OFF
SETLOCAL
IF "%~1" EQU "" (ECHO ERROR: Provide file to split. && GOTO END)
IF NOT EXIST "%~dpnx1" (ECHO ERROR: File must exist! && GOTO END)
SET FPATH=%~dp1
SET FNAME=%~n1
SET FEXT=%~x1


:: Initialize
SET _IDX=0
SET SEEN=00:00:00
FOR /F %%N IN ('ffprobe -v error -show_entries format^=duration -of default^=noprint_wrappers^=1^:nokey^=1 -sexagesimal "%~1"') DO SET FLEN=%%N

:LOOP
ffmpeg -i "%~1" -codec copy -ss %SEEN% -fs 20Mi "%FPATH%%FNAME% %_IDX%%FEXT%" >nul 2>&1
FOR /F %%N IN ('ffprobe -v error -show_entries format^=duration -of default^=noprint_wrappers^=1^:nokey^=1 -sexagesimal "%FPATH%%FNAME% %_IDX%%FEXT%"') DO SET NEXT=%%N
FOR /F %%A IN ('powershell -command "'{0:h\:mm\:ss\.ffffff}' -f ((New-TimeSpan 00:00:00 %SEEN%).Add((New-TimeSpan 00:00:00 %NEXT%)))"') DO SET SEEN=%%A
SET /A "_IDX+=1"
ECHO Added new segment (%_IDX%) lasting %NEXT%...
IF %SEEN% GEQ %FLEN% GOTO END
GOTO LOOP

:END
ENDLOCAL