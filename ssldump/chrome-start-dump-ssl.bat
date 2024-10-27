REM make sure you can write there
if not exist c:\temp  mkdir c:\temp

REM name of file is arbitrary - just make sure its configured 
REM in Wireshark under protocols/TLS as (Pre)-Master-Secret logfile name
set SSLKEYLOGFILE=C:\temp\SSLKEYFILE

REM make sure Chrome is not already running
Taskkill /F /IM chrome.exe

REM start searches for chrome.exe, regardless where it is
start chrome.exe

REM alternatively you can qualify your full path - but this is system dependend
REM "C:\Program Files\Google\Chrome\Application\chrome.exe"

REM keep shell open to see what has happened in case of errors 
pause
