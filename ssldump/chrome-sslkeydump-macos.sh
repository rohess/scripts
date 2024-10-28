#!/bin/bash
# we use the home directory - because only this seems realiably writable. 
export SSLKEYLOGFILE=~/SSLKEYFILE
# kill running instances, otherwiese the env var is not picked up
killall -9 "Google Chrome"
# open chrome with webrtc internals and the page with the goto sessions
open -a 'google chrome.app' "chrome://webrtc-internals" "https://app.goto.com/meeting/957100141"
