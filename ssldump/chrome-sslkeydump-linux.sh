#!/bin/bash
export SSLKEYLOGFILE=~/SSLKEYFILE
# kill running instances, otherwiese the env var is not picked up - same for chrome and chromium
killall -9 chrome
# open chrome or chromium with webrtc internals and the page with the goto sessions 
#chromium
google-chrome "https://app.goto.com/meeting/957100141"
