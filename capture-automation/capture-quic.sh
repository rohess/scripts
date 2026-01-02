#!/usr/bin/env bash

URL="$1"
BROWSER="${2:-chrome}"
DURATION="${3:-20}"

if [[ -z "$URL" ]]; then
  echo "usage: $0 <url> [chrome|edge|firefox] [seconds]"
  exit 1
fi

HOST=$(echo "$URL" | awk -F/ '{print $3}')
TS=$(date -u +"%Y%m%d_%H%M%SZ")

PCAP_RAW="quic_${HOST}_${TS}.pcapng"
PCAP_FINAL="quic_${HOST}_${TS}_decrypted.pcapng"
KEYS="quic_${HOST}_${TS}.keys.log"
PROFILE="$(mktemp -d)"

export SSLKEYLOGFILE="$PWD/$KEYS"

OS="$(uname)"

# ---------- tool paths ----------
if [[ "$OS" == "Darwin" ]]; then
  DUMPCAP="${DUMPCAP:-/Applications/Wireshark.app/Contents/MacOS/dumpcap}"
  EDITCAP="${EDITCAP:-/Applications/Wireshark.app/Contents/MacOS/editcap}"
  CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
  EDGE="${EDGE:-/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge}"
  FIREFOX="${FIREFOX:-/Applications/Firefox.app/Contents/MacOS/firefox}"
  for bin in "$DUMPCAP" "$EDITCAP"; do
    if [[ ! -x "$bin" ]]; then
      echo "ERROR: not executable: $bin"
      exit 1
    fi
  done
  sudo dscacheutil -flushcache

elif [[ "$OS" == "Linux" ]]; then
  DUMPCAP="${DUMPCAP:-$(command -v dumpcap)}"
  EDITCAP="${EDITCAP:-$(command -v editcap)}"
  CHROME="${CHROME:-$(command -v google-chrome || command -v chromium || true)}"
  EDGE="${EDGE:-$(command -v microsoft-edge || true)}"
  FIREFOX="${FIREFOX:-$(command -v firefox)}"

  command -v resolvectl >/dev/null && sudo resolvectl flush-caches || true
else
  echo "Unsupported OS: $OS"
  exit 1
fi

# ---------- start capture ----------
echo "$DUMPCAP"
CAP_LOG="dumpcap_${TS}.log"
sudo "$DUMPCAP" -i en0 -Z "$USER" -w "$PCAP_RAW" >"$CAP_LOG" &
CAP_PID=$!
sleep 2

# ---------- launch browser ----------
case "$BROWSER" in
  chrome)
    "$CHROME" \
      --user-data-dir="$PROFILE" \
      --no-first-run \
      --enable-quic \
      --origin-to-force-quic-on="$HOST:443" \
      "$URL" >/dev/null 2>&1 &
    ;;
  edge)
    "$EDGE" \
      --user-data-dir="$PROFILE" \
      --no-first-run \
      --enable-quic \
      --origin-to-force-quic-on="$HOST:443" \
      "$URL" >/dev/null 2>&1 &
    ;;
  firefox)
    cat > "$PROFILE/prefs.js" <<EOF
user_pref("network.http.http3.enabled", true);
user_pref("network.http.http3.only", true);
EOF
    "$FIREFOX" -profile "$PROFILE" "$URL" >/dev/null 2>&1 &
    ;;
  *)
    echo "Unknown browser: $BROWSER"
    kill $CAP_PID
    exit 1
    ;;
esac

BROWSER_PID=$!
sleep "$DURATION"

# ---------- teardown ----------
kill "$BROWSER_PID" 2>/dev/null
sudo kill "$CAP_PID"

# ---------- inject secrets ----------
"$EDITCAP" --inject-secrets tls,"$KEYS" "$PCAP_RAW" "$PCAP_FINAL"

echo "PCAP (raw):        $PCAP_RAW"
echo "PCAP (decrypted):  $PCAP_FINAL"
echo "KEYS:              $KEYS"

