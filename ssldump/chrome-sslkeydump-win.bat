@ECHO OFF
setlocal

REM Windows script for Webconferencing capture automation
REM cleans up everything, starts capture as well as chrome with parameters,
REM finishes on keypress and embeds the TLS keys into the capture (DSB)
REM PARAMETER (optional): first part of capture file name
REM ###############################

REM ---- configuration -----------------------------------------------
set LABEL=%~1
if "%LABEL%"=="" set LABEL=meet
set CAPDIR=C:\temp\cap
set WS=C:\Program Files\Wireshark
set IFACE=ethernet

REM Google Meet
REM set "URL=https://meet.google.com/eve-baez-bye"

REM MS Teams
REM set "URL=https://teams.live.com/meet/9360936935810?p=ALos3Pb6N8Gm9Oq0l2&launchType=web&launchAgent=join_launcher_web&lightExperience=true"

REM Webex
set "URL=https://meet1754097804582-5056.webex.com/meet/pr27407883594"

echo "%URL%"

REM -------------------------------------------------------------------

if not exist "%CAPDIR%" mkdir "%CAPDIR%"

REM timestamp - "date" doesn't cut it
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set TS=%%i
set BASE=%CAPDIR%\%LABEL%_%TS%

REM one key log per take - Chrome only ever appends to this file
set SSLKEYLOGFILE=%BASE%.keys

echo kill running chromes
taskkill /F /IM chrome.exe >nul 2>&1
timeout 3 >nul

echo clear DNS
ipconfig /flushdns

REM start capture - filter some noise, keep mdns udp 5353 to see what we see
start "dumpcap" "%WS%\dumpcap.exe" -i %IFACE% -f "(not broadcast and not multicast and not port 3389) or udp port 5353" -w "%BASE%.pcapng"

timeout 3 >nul

start "" chrome.exe ^
  --user-data-dir=C:\demo-profile ^
  --disable-extensions ^
  --use-fake-device-for-media-stream ^
  --use-fake-ui-for-media-stream ^
  --remote-debugging-port=9222 ^
  --window-position=0,0 --window-size=960,1040 ^
  "%URL%"

timeout 3 >nul
powershell -NoProfile -Command "Invoke-RestMethod -Method Put -Uri 'http://127.0.0.1:9222/json/new?chrome://webrtc-internals/' | Out-Null"

echo Press a key to stop capture
pause >nul

REM manually close Chrome first so the key log is complete, then stop capture - or not, works also otherwise
REM taskkill /IM chrome.exe >nul 2>&1
REM timeout 2 >nul
taskkill /IM dumpcap.exe /F >nul 2>&1
timeout 1 >nul

REM embed TLS secrets into the pcapng
if exist "%SSLKEYLOGFILE%" (
  "%WS%\editcap.exe" --inject-secrets "tls,%SSLKEYLOGFILE%" "%BASE%.pcapng" "%BASE%_dsb.pcapng"
  echo Written: %BASE%_dsb.pcapng
  del "%BASE%.pcapng"
) else (
  echo No key log found - capture left without secrets: %BASE%.pcapng
)

endlocal