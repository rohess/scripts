REM make sure you can write there
if not exist c:\temp  mkdir c:\temp

REM name of file is arbitrary - just make sure its configured 
REM in Wireshark under protocols/TLS as (Pre)-Master-Secret logfile name
set SSLKEYLOGFILE=C:\temp\SSLKEYFILE

REM make sure Chrome is not already running
Taskkill /F /IM chrome.exe

REM change path as needed
"C:\Program Files\Google\Chrome\Application\chrome.exe"

