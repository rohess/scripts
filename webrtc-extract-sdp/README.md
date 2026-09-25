# webrtc-extract-sdp

Pull WebRTC **SDP offers and answers** out of a TLS-decrypted packet capture and save them as readable files.

WebRTC leaves signalling to the vendor, so the SDP rarely shows up as "SDP" in Wireshark. Each product needs its own approach:

| Script | Product | Signalling transport |
|---|---|---|
| `goto-extract_sdp.py` | GoTo (and other JSON-based signalling) | TLS / WebSocket or HTTP/2 / JSON containing SDP text |
| `meet-exctract-sdp.py` | Google Meet | TLS / HTTP/2 / protobuf (no SDP on the wire) |

## Requirements

- Python 3.7+ (3.8+ for the Meet script), standard library only
- `tshark` (Wireshark 3.x or newer) on your `PATH`
  - macOS: add Wireshark's CLI tools to the path, or use `/Applications/Wireshark.app/Contents/MacOS/tshark`
  - Debian/Ubuntu: `sudo apt install tshark`
  - Windows: add `C:\Program Files\Wireshark` to `PATH`
- Decryptable TLS: keys embedded in the pcapng, or a separate `SSLKEYLOGFILE` (see [Preparing a capture](#preparing-a-capture))

## Test data

[test-data/](test-data/) contains sample captures with TLS secrets embedded, so they work without a key log:

| File | Use with |
|---|---|
| `goto_audio-signaling.pcapng` | `python3 goto-extract_sdp.py test-data/goto_audio-signaling.pcapng` |
| `meet9_signaling.pcapng` | `python3 meet-exctract-sdp.py test-data/meet9_signaling.pcapng` |

Anyone with these files can read the decrypted signalling, so only share captures of test calls.

## goto-extract_sdp.py

Finds SDP embedded in JSON, typically a string inside a WebSocket or HTTP/2 message with escaped `\r\n`, sometimes JSON-encoded twice or nested in a vendor envelope.

```
$ python3 goto-extract_sdp.py test-data/goto_audio-signaling.pcapng
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

### Usage

```
python3 goto-extract_sdp.py CAPTURE [-o OUTDIR] [-k KEYLOG] [-Y FILTER] [-p]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file |
| `-o`, `--outdir` | Output directory for the `.sdp` files (default: `sdp_out`) |
| `-k`, `--keylog` | TLS key log file (`SSLKEYLOGFILE` format). Not needed if the keys are embedded in the pcapng. |
| `-Y`, `--filter` | Wireshark display filter that limits which packets are searched (default: `websocket \|\| http2 \|\| http \|\| json`) |
| `-p`, `--print` | Also print each full SDP to stdout |

```
python3 goto-extract_sdp.py call.pcapng -k sslkeys.log -p          # separate key log, print SDPs
python3 goto-extract_sdp.py call.pcapng -Y 'ip.addr == 23.239.237.146'   # one signalling server only
python3 goto-extract_sdp.py call.pcapng -Y tls                     # nothing found? search all decrypted TLS
```

Output files are named `NN_frameFRAME_TYPE.sdp` (e.g. `03_frame57_offer.sdp`), where `TYPE` is `offer`, `answer`, `pranswer` or `unknown`. Line endings are normalised to `\n`.

### How it works

1. Runs `tshark -T json -x --no-duplicate-keys`; `-x` exposes decrypted TLS, reassembled/unmasked WebSocket payloads and decompressed data.
2. Walks every string in the dissection tree and decodes hex byte fields back to text, so the SDP is found however Wireshark dissected the payload.
3. Recursively searches parsed JSON (including JSON inside JSON strings) for `"sdp"` values starting with `v=0`, paired with the nearest `"type"`. Falls back to a regex for non-JSON messages.
4. Removes duplicates, keeping the copy with a type label.

The reported frame is where Wireshark shows the reassembled message, i.e. the **last** TCP segment.

### Limitations

- **Trickled ICE candidates** sent as separate messages are not extracted; `candidates=` only counts `a=candidate` lines inside the SDP.
- Vendors sending ICE/DTLS parameters as individual fields or protobuf produce no output (see the Meet script for one such case). Tip: take the ICE ufrag from STUN `stun.att.username` and search the decrypted signalling for it.
- The whole tshark JSON output is held in memory; narrow large captures with `-Y`.
- No output usually means TLS isn't decrypted. Statistics → Protocol Hierarchy should show `websocket`, `http2` or `json` under TLS.

## meet-exctract-sdp.py

Google Meet never sends SDP over the wire. The browser's offer and the SFU's answer are exchanged as protobuf in a single gRPC-web call, `google.rtc.meetings.v1.MediaSessionService/CreateMediaSession`, over HTTP/2. The script:

1. Uses tshark to locate the HTTP/2 stream(s) carrying `CreateMediaSession` and reassembles the request (client offer) and response (server answer) bodies.
2. Unwraps gzip/base64 as needed and decodes the protobuf with a built-in decoder (no `protoc` or `.proto` files).
3. Renders each side as **approximate SDP**: ICE ufrag/pwd, DTLS fingerprint and setup role, candidates, codecs with fmtp, header extensions and pre-negotiated data channels. Protobuf fields without an SDP equivalent are listed as `;` comments.
4. Lists the STUN connectivity checks that use the negotiated ufrags, showing where media actually flows.

```
$ python3 meet-exctract-sdp.py test-data/meet9_signaling.pcapng -o /tmp/meet
Found 1 CreateMediaSession call(s)
[1] t=0.899s  (tcp.stream 0, h2 stream 53, req frame 640, resp frame 804)
  server ufrag b2RcUacC6cJBPAoKAAiKYigCIAMQ  candidates:
      udp    74.125.250.248:3478  prio 2130706436
      udp    74.125.250.248:19305  prio 2130706431
      tcp    74.125.250.130:19305  prio 2130706430
      ssltcp 74.125.250.130:443  prio 2130706429
Written:
  /tmp/meet/meet9_signaling-01-offer.sdp.txt
  /tmp/meet/meet9_signaling-01-offer.pb.txt
  /tmp/meet/meet9_signaling-01-offer.bin
  /tmp/meet/meet9_signaling-01-answer.sdp.txt
  /tmp/meet/meet9_signaling-01-answer.pb.txt
  /tmp/meet/meet9_signaling-01-answer.bin
```

### Usage

```
python3 meet-exctract-sdp.py CAPTURE [--keylog KEYLOG] [-o OUTDIR] [--tshark PATH]
python3 meet-exctract-sdp.py --bodies REQ RESP [-o OUTDIR]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file |
| `--keylog` | TLS key log file. Not needed if the keys are embedded. |
| `-o`, `--outdir` | Output directory (default: `<capture>_meet_sdp`, or `meet_sdp_out` with `--bodies`) |
| `--tshark` | Path to tshark if it isn't on `PATH` |
| `--bodies REQ RESP` | Skip tshark and decode request/response bodies exported from Wireshark or DevTools (raw, gzip or base64) |

Output per `CreateMediaSession` call (`NN` = call number):

| File | Content |
|---|---|
| `<prefix>-NN-{offer,answer}.sdp.txt` | Approximate SDP rendering |
| `<prefix>-NN-{offer,answer}.pb.txt` | Raw protobuf in `protoc --decode_raw` style |
| `<prefix>-NN-{offer,answer}.bin` | Decoded protobuf body |
| `<prefix>-ice-checks.tsv` | STUN binding requests using the negotiated ufrags, with USE-CANDIDATE flag |

### Limitations

- Protobuf field meanings are reverse-engineered from a single capture; guesses (e.g. DTLS setup mapping, BUNDLE, sctp-port) are marked with `;` in the output. The result is for reading, not for feeding into a WebRTC stack.
- Google may change the RPC or message layout at any time.

## Preparing a capture

Set `SSLKEYLOGFILE` before starting the browser, then capture as usual. To make the capture self-contained, embed the keys:

```
editcap --inject-secrets tls,sslkeys.log capture.pcapng capture-with-keys.pcapng
```

Anyone with the resulting file can read the decrypted signalling.

## Viewing JSON SDP in Wireshark

- Ctrl+F on **Packet details** searches tree labels, which are truncated at 240 characters, so text deep inside a JSON-wrapped SDP is never found. Use a display filter instead.
- Set Preferences → Protocols → WebSocket → *Dissect websocket text as* → **JSON**, then filter with, for example:

  ```
  json.value.string contains "a=candidate"
  json.value.string == "offer" || json.value.string == "answer"
  ```

The companion Lua plugin `sdp_in_json.lua` passes these JSON strings to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work. [https://github.com/rohess/wireshark_plugins/tree/main/webrtc-sdp-in-json](https://github.com/rohess/wireshark_plugins/tree/main/webrtc-sdp-in-json)

## License

MIT  See `LICENSE`.
