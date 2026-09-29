# Google Meet: meet-extract-sdp.py

Part of [webrtc-extract-sdp](README.md), which covers requirements, test data, capture preparation and the options shared by all scripts.

Google Meet never sends SDP over the wire. The browser's offer and the SFU's answer are exchanged as protobuf in a single gRPC-web call, `google.rtc.meetings.v1.MediaSessionService/CreateMediaSession`, over HTTP/2. The script:

1. Uses tshark to locate the HTTP/2 stream(s) carrying `CreateMediaSession` and reassembles the request (client offer) and response (server answer) bodies.
2. Unwraps gzip/base64 as needed and decodes the protobuf with a built-in decoder (no `protoc` or `.proto` files).
3. Renders each side as **approximate SDP**: ICE ufrag/pwd, DTLS fingerprint and setup role, candidates, codecs with fmtp, header extensions and pre-negotiated data channels. Protobuf fields without an SDP equivalent are listed as `;` comments.
4. Lists the STUN connectivity checks that use the negotiated ufrags, showing where media actually flows.

```
$ python3 meet-extract-sdp.py test-data/meet9_signaling.pcapng -o /tmp/meet
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

## Usage

```
python3 meet-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH]
python3 meet-extract-sdp.py --bodies REQ RESP [-o OUTDIR]
```

The common options `-k`, `-o` and `--tshark` are described in the [main README](README.md#usage); this script has no `-p`. The default output directory is `<capture>_meet_sdp`, or `meet_sdp_out` with `--bodies`. Specific to this script:

| Option | Description |
|---|---|
| `--bodies REQ RESP` | Skip tshark and decode request/response bodies exported from Wireshark or DevTools (raw, gzip or base64) |

Output per `CreateMediaSession` call (`NN` = call number):

| File | Content |
|---|---|
| `<prefix>-NN-{offer,answer}.sdp.txt` | Approximate SDP rendering |
| `<prefix>-NN-{offer,answer}.pb.txt` | Raw protobuf in `protoc --decode_raw` style |
| `<prefix>-NN-{offer,answer}.bin` | Decoded protobuf body |
| `<prefix>-ice-checks.tsv` | STUN binding requests using the negotiated ufrags, with USE-CANDIDATE flag |

## Limitations

- Protobuf field meanings are reverse-engineered from a single capture; guesses (e.g. DTLS setup mapping, BUNDLE, sctp-port) are marked with `;` in the output. The result is for reading, not for feeding into a WebRTC stack.
- Google may change the RPC or message layout at any time.

## Wireshark plugin: webrtc-sdp_in_meet.lua

[webrtc-sdp_in_meet.lua](wireshark/webrtc-sdp_in_meet.lua) does the same decoding inside Wireshark. On the HTTP/2 DATA frames of `CreateMediaSession` it renders the offer and answer as SDP and passes them to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work. The rendered SDP also appears as an extra bytes tab (`Meet SDP offer` / `Meet SDP answer`).

Install: copy it to the *Personal Lua Plugins* folder (Help → About Wireshark → Folders), then Analyze → Reload Lua Plugins. It needs decrypted TLS and the default HTTP/2 settings (body reassembly and decompression). No other preferences are needed.

Next to the SDP, the `sdp_in_meet` tree shows the ICE/DTLS values, candidates, the pre-negotiated data channels, notes on guessed mappings (kept out of the SDP so it parses cleanly) and protobuf fields with no SDP equivalent.

```
sdp_in_meet                                  frames carrying the Meet offer/answer
sdp_in_meet.type == "answer"
sdp_in_meet.datachannel.label == "dcrpc"
sdp.media_attr contains "candidate"
```

With tshark:

```
$ tshark -X lua_script:wireshark/webrtc-sdp_in_meet.lua -r test-data/meet9_signaling.pcapng -Y sdp_in_meet
  641 0.899262800 192.168.102.77 → 142.251.155.5 HTTP2/PB(<UNKNOWN>)/SDP 1243 DATA[53] (PROTOBUF) [Meet SDP offer]
  804 1.040942600 142.251.155.5 → 192.168.102.77 HTTP2/SDP 189 DATA[53] (text/plain) [Meet SDP answer]

$ tshark -X lua_script:wireshark/webrtc-sdp_in_meet.lua -r test-data/meet9_signaling.pcapng -Y sdp_in_meet -O sdp_in_meet,sdp
```
