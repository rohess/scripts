# GoTo and other JSON signalling: goto-extract-sdp.py

Part of [webrtc-extract-sdp](README.md), which covers requirements, test data, capture preparation and the options shared by all scripts.

Finds SDP embedded in JSON, typically a string inside a WebSocket or HTTP/2 message with escaped `\r\n`, sometimes JSON-encoded twice or nested in a vendor envelope.

```
$ python3 goto-extract-sdp.py test-data/goto_audio-signaling.pcapng
#1   frame 32      t=    0.190s  offer    192.168.102.79:61322 -> 23.239.237.146:443  m=audio,audio,audio,audio,audio ice-ufrag=L//A candidates=0 lines=147
      -> sdp_out/01_frame32_offer.sdp
#2   frame 40      t=    0.210s  answer   23.239.237.146:443 -> 192.168.102.79:61322  m=audio,audio,audio,audio,audio ice-ufrag=tnn4 candidates=0 lines=94
      -> sdp_out/02_frame40_answer.sdp
#3   frame 57      t=    0.871s  offer    192.168.102.79:61322 -> 23.239.237.146:443  m=audio,audio,audio,audio,audio,audio ice-ufrag=L//A candidates=1 lines=167
      -> sdp_out/03_frame57_offer.sdp
#4   frame 66      t=    0.893s  answer   23.239.237.146:443 -> 192.168.102.79:61322  m=audio,audio,audio,audio,audio,audio ice-ufrag=tnn4 candidates=1 lines=108
      -> sdp_out/04_frame66_answer.sdp
```

Features:

- **Generic for JSON signalling:** doesn't depend on vendor field names and works over WebSocket text, HTTP/2 DATA or HTTP/1.1 bodies. It only helps if the SDP is sent as text inside JSON; binary formats such as protobuf (Google Meet) produce no output.
- **Labels offers and answers** by pairing each `"sdp"` with its `"type"`, and records frame, time and direction.
- **One file per SDP** with real line breaks, ready for diffing.
- **Summary per SDP** (media sections, ICE ufrag, candidates, line count) makes renegotiations and trickle ICE visible at a glance.

## Usage

```
python3 goto-extract-sdp.py CAPTURE [-o OUTDIR] [-k KEYLOG] [-Y FILTER] [--tshark PATH] [-p]
```

The common options `-k`, `-o`, `--tshark` and `-p` are described in the [main README](README.md#usage). The default output directory is `sdp_out`. Specific to this script:

| Option | Description |
|---|---|
| `-Y`, `--filter` | Wireshark display filter that limits which packets are searched (default: `websocket \|\| http2 \|\| http \|\| json`) |

```
python3 goto-extract-sdp.py call.pcapng -k sslkeys.log -p          # separate key log, print SDPs
python3 goto-extract-sdp.py call.pcapng -Y 'ip.addr == 23.239.237.146'   # one signalling server only
python3 goto-extract-sdp.py call.pcapng -Y tls                     # nothing found? search all decrypted TLS
```

Output files are named `NN_frameFRAME_TYPE.sdp` (e.g. `03_frame57_offer.sdp`), where `TYPE` is `offer`, `answer`, `pranswer` or `unknown`. Line endings are normalised to `\n`.

## How it works

1. Runs `tshark -T json -x --no-duplicate-keys`; `-x` exposes decrypted TLS, reassembled/unmasked WebSocket payloads and decompressed data.
2. Walks every string in the dissection tree and decodes hex byte fields back to text, so the SDP is found however Wireshark dissected the payload.
3. Recursively searches parsed JSON (including JSON inside JSON strings) for `"sdp"` values starting with `v=0`, paired with the nearest `"type"`. Falls back to a regex for non-JSON messages.
4. Removes duplicates, keeping the copy with a type label.

The reported frame is where Wireshark shows the reassembled message, i.e. the **last** TCP segment.

## Limitations

- **Trickled ICE candidates** sent as separate messages are not extracted; `candidates=` only counts `a=candidate` lines inside the SDP.
- Vendors sending ICE/DTLS parameters as individual fields or protobuf produce no output (see [Google Meet](README-meet.md) for one such case). Tip: take the ICE ufrag from STUN `stun.att.username` and search the decrypted signalling for it.
- The whole tshark JSON output is held in memory; narrow large captures with `-Y`.
- No output usually means TLS isn't decrypted. Statistics → Protocol Hierarchy should show `websocket`, `http2` or `json` under TLS.

## Wireshark plugin: webrtc-sdp_in_json.lua

[webrtc-sdp_in_json.lua](wireshark/webrtc-sdp_in_json.lua) is the Wireshark counterpart for JSON signalling such as GoTo's. It takes every JSON string that starts with `v=0` and passes it to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work. The protocol column shows `WebSocket/JSON/SDP`.

Install: set Preferences → Protocols → WebSocket → *Dissect websocket text as* → **JSON**, copy the plugin to the *Personal Lua Plugins* folder (Help → About Wireshark → Folders), then Analyze → Reload Lua Plugins. Tested with Wireshark 4.6.8 on macOS on a capture taken on Windows.

With tshark:

```
$ tshark -X lua_script:wireshark/webrtc-sdp_in_json.lua -o websocket.text_type:JSON -r test-data/goto_audio-signaling.pcapng -Y sdp
   32 0.189826500 192.168.102.79 → 23.239.237.146 WebSocket/JSON/SDP 220 WebSocket Text [FIN] [MASKED], JSON
   40 0.210184400 23.239.237.146 → 192.168.102.79 WebSocket/JSON/SDP 367 WebSocket Text [FIN] , JSON
   57 0.870906500 192.168.102.79 → 23.239.237.146 WebSocket/JSON/SDP 230 WebSocket Text [FIN] [MASKED], JSON
   66 0.892672600 23.239.237.146 → 192.168.102.79 WebSocket/JSON/SDP 774 WebSocket Text [FIN] , JSON
```

Don't load it together with `webrtc-sdp_in_teams.lua` when looking at Teams captures: the Teams offer is a JSON string over HTTP/2, so both plugins dissect it and the SDP shows up twice.
## Viewing JSON SDP in Wireshark

- Ctrl+F on **Packet details** searches tree labels, which are truncated at 240 characters, so text deep inside a JSON-wrapped SDP is never found. Use a display filter instead.
- Set Preferences → Protocols → WebSocket → *Dissect websocket text as* → **JSON**, then filter with, for example:

  ```
  json.value.string contains "a=candidate"
  json.value.string == "offer" || json.value.string == "answer"
  ```

[webrtc-sdp_in_json.lua](#wireshark-plugin-webrtc-sdp_in_jsonlua) passes these JSON strings to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work.
