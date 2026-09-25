# chrome-sslkeydump

Start Chrome with `SSLKEYLOGFILE` set, so its TLS session keys are logged and a packet capture of the session can be decrypted in Wireshark. Meant for looking at the signalling of web conferencing tools (GoTo, Teams, Webex, Zoom, Google Meet).

Chrome only reads `SSLKEYLOGFILE` at startup, so every script first kills running Chrome instances.

## Scripts

| Script | What it does |
|---|---|
| `chrome-sslkeydump-macos.sh` | Sets `SSLKEYLOGFILE=~/SSLKEYFILE`, kills Chrome, opens `chrome://webrtc-internals` and the meeting URL. |
| `chrome-sslkeydump-linux.sh` | Same for Linux (`google-chrome`; swap in `chromium` if needed). Opens only the meeting URL. |
| `chrome-sslkeydump-win.bat` | Full capture run: starts `dumpcap`, launches Chrome, waits for a keypress, stops the capture and embeds the TLS keys into the pcapng. |

On macOS and Linux you run the capture yourself (Wireshark, `tcpdump`, `dumpcap`) and load `~/SSLKEYFILE` under Preferences → Protocols → TLS → *(Pre)-Master-Secret log filename*, or embed it:

```
editcap --inject-secrets tls,$HOME/SSLKEYFILE capture.pcapng capture_dsb.pcapng
```

## Windows script

```
chrome-sslkeydump-win.bat [LABEL]
```

`LABEL` is the first part of the file names (default `meet`). One run:

1. Kills Chrome and flushes the DNS cache, so DNS lookups show up in the capture.
2. Starts `dumpcap` on `IFACE`, filtering out broadcast, multicast and RDP (keeps mDNS on UDP 5353).
3. Starts Chrome with a separate profile, no extensions, fake camera/microphone and remote debugging on port 9222, then opens `chrome://webrtc-internals` in a new tab.
4. Waits for a keypress, stops `dumpcap`, and writes `LABEL_TIMESTAMP_dsb.pcapng` with the keys embedded. The raw capture is deleted; the `.keys` file is kept.

Configure at the top of the script:

| Variable | Default |
|---|---|
| `CAPDIR` | `C:\temp\cap` |
| `WS` | `C:\Program Files\Wireshark` |
| `IFACE` | `ethernet` (list interfaces with `dumpcap -D`) |
| `URL` | Meeting URL; examples for Meet, Teams, Webex, Zoom and GoTo are included, uncomment one |

Requires Chrome and Wireshark (for `dumpcap` and `editcap`) to be installed.

## Notes

- The meeting URLs in the scripts are examples; replace them with your own.
- The key log lets anyone decrypt the captured TLS traffic. Treat both the key file and `_dsb.pcapng` files as sensitive.
- On macOS and Linux the key file is reused and only ever appended to. Delete it between sessions if you want one per capture.
- The decrypted captures work with [`webrtc-extract-sdp`](../webrtc-extract-sdp/) to pull out the SDP offers and answers.

## License

MIT. See `LICENSE`.
