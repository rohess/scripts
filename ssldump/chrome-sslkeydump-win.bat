@ECHO OFF

REM Windows script for Webconferencing cpature automation
REM cleans up everything, starts capture as well as chrome with parameters, finishes on keypress
REM PARAMETER (optional): first part of capture file name
REM TODO: move hardcoded stuff to variables
REM ###############################




REM Name for capture - could be "teams", "meet", etc

set LABEL=%~1
if "%LABEL%"=="" set LABEL=meet

REM make sure you can write there
if not exist c:\temp  mkdir c:\temp

REM name of file is arbitrary - just make sure its configured 
REM in Wireshark under protocols/TLS as (Pre)-Master-Secret logfile name
set SSLKEYLOGFILE=C:\temp\SSLKEYFILE

REM make sure Chrome is not already running
echo "kill running chromes"
Taskkill /F /IM chrome.exe

echo "clear DNS"
ipconfig /flushdns


REM start capture via dumpcap - filter some noise, keep mdns udp 5353 to see what we see
REM create timestamp - wild PS magic, but "date" doesn't cut it
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set TS=%%i

"C:\Program Files\Wireshark\dumpcap.exe"   -i ethernet -n -f "(not broadcast and not multicast and not port 3389) or udp port 5353" -w "c:\temp\cap\%LABEL%_%TS%.pcapng"

REM start searches for chrome.exe, regardless where it is
REM start chrome.exe

start "" chrome.exe ^
  --user-data-dir=C:\demo-profile ^
  --disable-extensions ^
  --use-fake-device-for-media-stream ^
  --use-fake-ui-for-media-stream ^
  --remote-debugging-port=9222 ^
  --window-position=0,0 --window-size=960,1040 ^
  "https://meet.google.com/eve-baez-bye"

timeout  3 >nul
powershell -NoProfile -Command "Invoke-RestMethod -Method Put -Uri 'http://127.0.0.1:9222/json/new?chrome://webrtc-internals/' | Out-Null"


REM keep shell open as long as capture needs to run
echo "Stop capture"
pause
