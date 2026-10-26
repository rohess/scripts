#!/bin/bash
mkdir -p "$HOME/ff-webrtc-test"
SSLKEYLOGFILE="$HOME/ff-keys.log" \
/Applications/Firefox.app/Contents/MacOS/firefox \
  --profile "$HOME/ff-webrtc-test" --no-remote \
  "https://app.goto.com" &
