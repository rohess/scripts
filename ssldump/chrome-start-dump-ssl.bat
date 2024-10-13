# make sure you can write there
if not exist c:\temp  mkdir c:\temp

# name of file is arbitrary - just make sure its configured 
# in Wireshark under protocols/TLS as (Pre)-Master-Secret logfile name
set SSLKEYLOGFILE=C:\temp\SSLKEYFILE

# make sure Chrome is not already running
Taskkill /F /IM chrome.exe

# change path as needed
# make sure chrome is not already running, otherwise it reuses the running process,
# which does not see the environment variable
"C:\Program Files\Google\Chrome\Application\chrome.exe"

