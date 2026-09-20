@ECHO OFF

REM make sure you can write there
if not exist c:\temp  mkdir c:\temp

REM name of file is arbitrary - just make sure its configured 
REM in Wireshark under protocols/TLS as (Pre)-Master-Secret logfile name
set SSLKEYLOGFILE=C:\temp\SSLKEYFILE

REM make sure Chrome is not already running
echo "kill running chromes"
Taskkill /F /IM chrome.exe

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


echo "Wait 10 secs for Chrome to start before starting capture ..."
timeout 10 >nul

REM start capture via dumpcap 

"C:\Program Files\Wireshark\dumpcap.exe"   -i ethernet -n -f "not broadcast and not multicast and not port 3389" -w c:\temp\cap\cap1.pcapng

REM keep shell open to see what has happened in case of errors 
echo "Stop capture"
pause
