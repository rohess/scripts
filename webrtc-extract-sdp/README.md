# webrtc-extract-sdp

Pull WebRTC **SDP offers and answers** out of a TLS-decrypted packet capture and save them as readable files.

WebRTC leaves signalling to the vendor, so the SDP rarely shows up as "SDP" in Wireshark. Each product needs its own approach. The Python scripts write the SDP to files; the Wireshark plugins in [wireshark/](wireshark/) show the same SDP in the packet tree:

| Product | Script | Wireshark plugin | Signalling transport |
|---|---|---|---|
| GoTo (and other JSON-based signalling) | `goto-extract-sdp.py` | `webrtc-sdp_in_json.lua` | TLS / WebSocket or HTTP/2 / JSON containing SDP text |
| Google Meet | `meet-extract-sdp.py` | `webrtc-sdp_in_meet.lua` | TLS / HTTP/2 / protobuf (no SDP on the wire) |
| Microsoft Teams | `teams-extract-sdp.py` | `webrtc-sdp_in_teams.lua` | Offer: TLS / HTTP/2 / JSON. Answer: TLS / WebSocket (Trouter) / base64+gzip JSON |
| Cisco Webex (web client) | `webex-extract-sdp.py` | `webrtc-sdp_in_webex.lua` | TLS / HTTP/2 / JSON (Locus) / ROAP JSON string containing SDP. Offer and answer in one PUT request/response |

All scripts take `-k`/`--keylog`, `-o`/`--outdir` and `--tshark`.

## Requirements

- Python 3.7+ (3.8+ for the Meet and Teams scripts), standard library only
- `tshark` (Wireshark 3.x or newer) on your `PATH`, or pass its location with `--tshark`
  - macOS: add Wireshark's CLI tools to the path, or use `/Applications/Wireshark.app/Contents/MacOS/tshark`
  - Debian/Ubuntu: `sudo apt install tshark`
  - Windows: add `C:\Program Files\Wireshark` to `PATH`
- Decryptable TLS: keys embedded in the pcapng, or a separate `SSLKEYLOGFILE` (see [Preparing a capture](#preparing-a-capture))

## Test data

[test-data/](test-data/) contains sample captures with TLS secrets embedded, so they work without a key log:

| File | Use with |
|---|---|
| `goto_audio-signaling.pcapng` | `python3 goto-extract-sdp.py test-data/goto_audio-signaling.pcapng` |
| `meet9_signaling.pcapng` | `python3 meet-extract-sdp.py test-data/meet9_signaling.pcapng` |
| `teams_signaling.pcapng` | `python3 teams-extract-sdp.py test-data/teams_signaling.pcapng` |
| `webex_20260921_204532_-first-20secs-cleaned.pcapng` | `python3 webex-extract-sdp.py test-data/webex_20260921_204532_-first-20secs-cleaned.pcapng` |

Anyone with these files can read the decrypted signalling, so only share captures of test calls.

## goto-extract-sdp.py

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

### Usage

```
python3 goto-extract-sdp.py CAPTURE [-o OUTDIR] [-k KEYLOG] [-Y FILTER] [--tshark PATH] [-p]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file |
| `-o`, `--outdir` | Output directory for the `.sdp` files (default: `sdp_out`) |
| `-k`, `--keylog` | TLS key log file (`SSLKEYLOGFILE` format). Not needed if the keys are embedded in the pcapng. |
| `-Y`, `--filter` | Wireshark display filter that limits which packets are searched (default: `websocket \|\| http2 \|\| http \|\| json`) |
| `--tshark` | Path to tshark if it isn't on `PATH` |
| `-p`, `--print` | Also print each full SDP to stdout |

```
python3 goto-extract-sdp.py call.pcapng -k sslkeys.log -p          # separate key log, print SDPs
python3 goto-extract-sdp.py call.pcapng -Y 'ip.addr == 23.239.237.146'   # one signalling server only
python3 goto-extract-sdp.py call.pcapng -Y tls                     # nothing found? search all decrypted TLS
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

### Wireshark plugin: webrtc-sdp_in_json.lua

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

## meet-extract-sdp.py

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

### Usage

```
python3 meet-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH]
python3 meet-extract-sdp.py --bodies REQ RESP [-o OUTDIR]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file |
| `-k`, `--keylog` | TLS key log file. Not needed if the keys are embedded. |
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

### Wireshark plugin: webrtc-sdp_in_meet.lua

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

## teams-extract-sdp.py

Teams sends real SDP, but the offer and the answer travel on different connections:

- **Offer**: the browser POSTs the join request to the conversation service (`https://api.flightproxy.skype.com/api/v2/cp/conv-…/conv/<id>`) over HTTP/2. The JSON body carries the SDP in `callInvitation.mediaContent.blob` (`contentType` `application/sdp-ngc-1.0`).
- **Answer**: the call controller calls back through the Trouter WebSocket (`*.trouter.skype.com`) with a socket.io-style frame `3:::{"method":"POST","url":"…/call/acceptance/","body":"…"}`. The `body` is base64-encoded gzip (`X-Microsoft-Skype-Content-Encoding: gzip`) of a JSON document with the SDP in `callAcceptance.mediaContent.blob`.

The script:

1. Uses tshark to find HTTP/2 streams whose body mentions `mediaContent` (or whose path looks like a conversation/call-controller request) and takes the reassembled bodies.
2. Reads all WebSocket payloads as raw bytes, strips the socket.io prefix and decodes `body` (plain JSON, base64, gzip are detected automatically).
3. Exports every JSON string that starts with `v=0` as SDP, byte for byte as sent (CRLF kept). `callInvitation` → offer, `callAcceptance`/`mediaAnswer` → answer. Offers and answers are paired via `mediaContent.mediaLegId`.
4. Prints a per-mid table: SDP direction of the offer, the **effective** direction from `mediaContent.mediaDescriptions` (Teams overrides the SDP there, e.g. mids 2–6 and 11 are `sendrecv` in the SDP but `recvonly` in effect), the answer direction, answer codecs and `x-ssrc-range`s.
5. Lists the STUN connectivity checks that use the negotiated ufrags.

```
$ python3 teams-extract-sdp.py test-data/teams_signaling.pcapng -o /tmp/teams
Found 2 SDP(s) in 1 call leg(s)

[1] mediaLegId 1B459D653E924AEA9FE6EF6694F0FE97
  OFFER  frame 1283 t=34.880s  HTTP/2 request (tcp.stream 15, h2 stream 19)  192.168.102.78:54914 -> 98.66.218.35:443
      https://api.flightproxy.skype.com/api/v2/cp/conv-swce-03-prod-aks.conv.skype.com/conv/Spru-Tgp-kK-pNoJNsnNTA?...
      callInvitation.mediaContent.blob  (application/sdp-ngc-1.0)
      13 m-lines, 810 lines, ice-ufrag=EhSM setup=actpass candidates=1
        a=candidate:3189342728 1 udp 2122260223 192.168.102.78 64474 typ host
      note: 24 extmap lines use backslash URIs as sent on the wire: http:\\www.ietf.org\id\draft-holmer-rmcat-..., ...
      note: mediaParameter: {"sendSideBWSeed":{"seedValueBitsPerSec":558736}}
  ANSWER frame 1385 t=35.796s  WebSocket POST callback "call/acceptance" (tcp.stream 12)  72.144.120.211:443 -> 192.168.102.78:58930
      body.<decoded>.callAcceptance.mediaContent.blob  (application/sdp-ngc-1.0)
      13 m-lines, 410 lines, ice-ufrag=Yh3A setup=passive candidates=2
        a=candidate:1 1 UDP 54001663 48.208.184.155 3478 typ relay raddr 10.0.2.122 rport 3478 MTURNID 14851909894487247346
        a=candidate:3 1 tcp-pass 18087935 48.208.184.155 3478 typ relay raddr 10.0.2.122 rport 3478
      chain-id e6501dd9-3ccd-4645-8dd0-282d9ca8dc3e
  per-mid (effective = offer's mediaContent.mediaDescriptions, * = overrides SDP):
  mid  kind    label                     offer dir  effective   answer dir  answer codecs                ...
  0    audio   main-audio                sendrecv   -           (sendrecv)  120:CN 111:OPUS 97:RED ...
  1    video   main-video                sendrecv   sendrecv    (sendrecv)  107:H264(42C01E) 99:rtx>107
  2    video   main-video                sendrecv   recvonly *  (sendrecv)  107:H264(42C01E) 99:rtx>107
  ...
  12   x-data  data                      sendrecv   -           (sendrecv)  127:x-data 126:rtx>127
  offer -> answer: 916 ms

First ICE check: frame 1397 at t=35.952s -> 48.208.184.155:3478  (6 checks total)
```

`(sendrecv)` means the m-section has no direction attribute, so the default applies.

### Usage

```
python3 teams-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH] [-p]
python3 teams-extract-sdp.py --bodies FILE [FILE ...] [-o OUTDIR]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file |
| `-k`, `--keylog` | TLS key log file. Not needed if the keys are embedded. |
| `-o`, `--outdir` | Output directory (default: `<capture>_teams_sdp`, or `teams_sdp_out` with `--bodies`) |
| `--tshark` | Path to tshark if it isn't on `PATH` |
| `-p`, `--print` | Also print the full SDPs |
| `--bodies FILE…` | Skip tshark and decode bodies exported from Wireshark or DevTools: the join request JSON, a Trouter frame (`3:::{…}`), or base64/gzip data |

Output per call leg (`NN` = leg number):

| File | Content |
|---|---|
| `<prefix>-NN-{offer,answer}.sdp` | SDP exactly as sent (CRLF line endings) |
| `<prefix>-NN-{offer,answer}.json` | Decoded signalling JSON the SDP came from (join request / decoded acceptance body) |
| `<prefix>-NN-sdpK.{sdp,json}` | SDPs found under other JSON keys (role unknown) |
| `<prefix>-ice-checks.tsv` | STUN binding requests using the negotiated ufrags, with USE-CANDIDATE flag |

### Limitations

- Tested with the Teams web client joining a consumer (teams.live.com) meeting. Other clients or tenants may use other callbacks (e.g. `call/mediaAnswer`, renegotiation); they are picked up as long as the SDP sits in a JSON string starting with `v=0`.
- The `.json` files contain the meeting URL, passcode and participant IDs. Review them before sharing.
- Trickled candidates were not seen in the test capture, so only the candidates inside the SDP are shown.

### Wireshark plugin: webrtc-sdp_in_teams.lua

[webrtc-sdp_in_teams.lua](wireshark/webrtc-sdp_in_teams.lua) does the same inside Wireshark. It finds the offer in the HTTP/2 join request and the answer in the Trouter `call/acceptance` callback (decoding base64/gzip), and passes both to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work. The SDP also appears as an extra bytes tab (`Teams SDP offer` / `Teams SDP answer`); select *Session Description Protocol* and use File → Export Packet Bytes to save it.

Install: copy it to the *Personal Lua Plugins* folder (Help → About Wireshark → Folders), then Analyze → Reload Lua Plugins. It needs decrypted TLS and the default HTTP/2 settings (body reassembly). No other preferences are needed. Remove `webrtc-sdp_in_json.lua` from the plugins folder while you do this, or the offer's SDP is dissected twice. Webex ROAP bodies are skipped, so it can stay loaded next to `webrtc-sdp_in_webex.lua`.

Next to the SDP, the `sdp_in_teams` tree shows the JSON path, `mediaLegId` with a link to the matching offer/answer frame and the offer→answer delay, ICE/DTLS values, candidates, and one entry per m-section with SDP direction, effective direction from `mediaDescriptions`, `x-ssrc-range` and codecs. Notes flag the backslash extmap URIs and `mediaParameter`.

A second protocol, `teams_trouter`, annotates every Trouter WebSocket message (socket.io frame type, event name, method, URL, callback name, link token, status, chain ID) and shows the decoded callback body as a JSON tree.

```
sdp_in_teams                                   frames carrying a Teams offer/answer
sdp_in_teams.type == "answer"
sdp_in_teams.mid.effective_direction == "recvonly"
teams_trouter.callback == "call/acceptance"
teams_trouter.event == "trouter.connected"
sdp.media_attr contains "x-ssrc-range"
```

With tshark:

```
$ tshark -X lua_script:wireshark/webrtc-sdp_in_teams.lua -r test-data/teams_signaling.pcapng -Y sdp_in_teams
 1283 34.879994300 192.168.102.78 → 98.66.218.35 HTTP2/JSON/SDP 273 DATA[19], JSON (application/json) [Teams SDP offer]
 1385 35.796205700 72.144.120.211 → 192.168.102.78 WebSocket/JSON/SDP 959 WebSocket Text [FIN]  [Trouter call/acceptance], JSON [Teams SDP answer]

$ tshark -2 -X lua_script:wireshark/webrtc-sdp_in_teams.lua -r test-data/teams_signaling.pcapng -Y sdp_in_teams -O sdp_in_teams,teams_trouter,sdp
```

Use `-2` (two-pass) to get the *Answer in* link on the offer frame as well.

## webex-extract-sdp.py

The Webex web client exchanges SDP inside **ROAP** messages, Webex's own offer/answer envelope. They travel in **Locus** REST calls over HTTP/2. There is no SIP and no WebSocket SDP. Each ROAP message is a JSON document sent as a *string* inside the JSON body, so it must be decoded twice:

| Step | HTTP/2 request | JSON path | ROAP messageType |
|---|---|---|---|
| Join | `POST /locus/api/v1/loci/call` | `localMedias[0].localSdp` | `TURN_DISCOVERY_REQUEST` |
| | 200 response | `mediaConnections[0].remoteSdp` | `TURN_DISCOVERY_RESPONSE`: TURN URLs and credentials in `roapMessage.headers` |
| Offer | `PUT /locus/api/v1/loci/<locus>/participant/<id>/media` | `localMedias[0].localSdp` | `OFFER`, SDP in `roapMessage.sdps[0]` |
| | 200 response | `mediaConnections[0].remoteSdp` | `ANSWER` (header `includeAnswerInHttpResponse`) |
| | | `mediaConnections[0].localSdp` | echo of the `OFFER` |

Both sides send `noOkInTransaction`, so no ROAP `OK` follows. The Mercury WebSocket only carries `locus.difference` state events, no SDP.

The join and offer bodies also carry the client's reachability report (`clientMediaPreferences.reachability`). The client measures it with plain STUN Binding Requests (no USERNAME) against the clusters that Calliope (`POST /calliope/api/discovery/v1/clusters`) returned. The chosen cluster comes back as `mediaConnections[0].mediaAgentCluster`.

The script:

1. Uses tshark to find HTTP/2 streams with ROAP, Locus or Calliope bodies and takes the reassembled bodies (gzip responses are decompressed).
2. JSON-decodes every `localSdp`/`remoteSdp` string and reads `roapMessage` (`messageType`, `seq`, `tieBreaker`, `headers`, `sdps`). Messages are grouped into transactions by `seq`, and echoes are checked against the original.
3. Exports every SDP in `sdps` byte for byte as sent (CRLF kept), and prints TURN servers and credentials from TURN discovery.
4. Prints a per-mid table (content main/slides, `jmp-source` CSI, directions, answer transport profile, `b=TIAS`, codecs). Notes flag Webex-specific SDP: placeholder `0.0.0.0:9` candidates, `ice-lite`, `RTP/AVP` answering `UDP/TLS/RTP/SAVPF`, `xTLS` and FQDN candidates, reused foundations, `max-message-size` mismatch, simulcast SSRC groups and per-SSRC `max-fs`.
5. Compares the reachability report with the STUN probes actually seen. Probes are matched to Calliope clusters and grouped into rounds, and the table shows the fastest RTT per cluster and round.
6. Lists the STUN connectivity checks that use the negotiated ufrags, with USE-CANDIDATE and the peer-reflexive mapped address.

```
$ python3 webex-extract-sdp.py test-data/webex_20260921_204532_-first-20secs-cleaned.pcapng -o /tmp/webex
Found 4 ROAP message(s) in 2 transaction(s)

[seq 0] TURN_DISCOVERY_REQUEST / TURN_DISCOVERY_RESPONSE
  TURN_DISCOVERY_REQUEST  frame 3270 t=16.679s  HTTP/2 POST request (tcp.stream 69, h2 stream 3)  192.168.102.78:62232 -> 170.72.238.49:443
      https://locus-k.wbx2.com/locus/api/v1/loci/call?alternateRedirect=true
      localMedias[0].localSdp  version=2
      headers: includeAnswerInHttpResponse, noOkInTransaction
      echoed in frame 3280 mediaConnections[0].localSdp (identical)
  TURN_DISCOVERY_RESPONSE frame 3280 t=16.811s  HTTP/2 200 response (tcp.stream 69, h2 stream 3)  170.72.238.49:443 -> 192.168.102.78:62232
      ...
      TURN url      turns:xlm120.public.wlhrm-p-2.prod.infra.webex.com:443?transport=tcp
      TURN url      turns:xlm120.ds.public.wlhrm-p-2.prod.infra.webex.com:443?transport=tcp
      TURN username webexturnuser  password ...
      media agent   wlhrm.wlhrm (crc)
  turn_discovery_request -> turn_discovery_response: 132 ms

[seq 1] OFFER / ANSWER
  OFFER                   frame 3480 t=18.951s  HTTP/2 PUT request (tcp.stream 69, h2 stream 7)  192.168.102.78:62232 -> 170.72.238.49:443
      https://locus-k.wbx2.com/locus/api/v1/loci/3a1aca39-.../participant/140c0f6d-.../media
      localMedias[0].localSdp  version=2  tieBreaker=4294967294
      5 m-lines, 232 lines, ice-ufrag=xfCJ setup=actpass candidates=3
        a=candidate:dummy1 1 udp 3 0.0.0.0 9 typ host
        ...
      echoed in frame 3508 mediaConnections[0].localSdp (identical)
  ANSWER                  frame 3508 t=19.048s  HTTP/2 200 response (tcp.stream 69, h2 stream 7)  170.72.238.49:443 -> 192.168.102.78:62232
      5 m-lines, 163 lines, ice-ufrag=4SwvSbJCH7ldgvIT7+exeoSJlwbyLfdZ setup=passive ice-lite candidates=11
        a=candidate:0 1 UDP 2130706431 144.196.72.136 5004 typ host
        ...
        a=candidate:6 1 xTLS 1795159807 xlm120.public.wlhrm-p-2.prod.infra.webex.com 443 typ host tcptype passive fingerprint sha-1;DD:D9:...
  offer -> answer: 97 ms
  per-mid:
  mid  kind         content  offer csi   offer dir   answer dir  answer proto   answer TIAS  answer codecs
  0    video        main     486307073   sendrecv    sendrecv    RTP/AVP        40000000     102:H264(420034,pm1) 103:rtx>102
  1    audio        main     486307072   sendrecv    sendrecv    RTP/AVP        1000000      111:opus
  2    video        slides   1486019329  sendrecv    sendrecv    RTP/AVP        20000000     108:H264(424034,pm1) 109:rtx>108
  3    audio        slides   1486019328  sendrecv    sendrecv    RTP/AVP        256000       111:opus
  24   application  -        -           (sendrecv)  (sendrecv)  UDP/DTLS/SCTP  -            webrtc-datachannel
  note: offer has only placeholder candidates (0.0.0.0:9) - the media server learns the client address as peer-reflexive from the ICE checks
  note: answer transport profile differs from offer: UDP/TLS/RTP/SAVPF -> RTP/AVP
  note: answer has 2 xTLS candidate(s) - Webex-specific transport (TLS on 443), ignored by browser ICE
  ...

Locus media updates without ROAP:
  frame 4290 t=25.059s request  localMedias[0].localSdp: audioMuted=False, videoMuted=False
  ...

Reachability
  Calliope cluster list in frame 2240: 8 clusters, 48 STUN targets
  client report (clientMediaPreferences.reachability) sent in frame(s) 3270, 3480, test duration 10965 ms
  STUN round 1: frames 2309-2764, t=6.969s, 32 targets, 38 requests (6 retransmits), 0 unanswered
  STUN round 2: frames 3288-3414, t=17.041s, 31 targets, 33 requests (2 retransmits), 0 unanswered
  rep. = reported by the client, STUN rN = fastest measured binding RTT per cluster and round
  cluster        rep. udp  rep. tcp  rep. xtls  STUN r1  STUN r2
  wamsm.wamsm.*  124 ms    no        1592 ms    51 ms    22 ms
  wlhrm.wlhrm.*  137 ms    no        646 ms     58 ms    27 ms    <- media
  wjedm.wjedm.*  167 ms    no        838 ms     89 ms    75 ms
  ...

First ICE check: frame 3534 at t=19.197s 192.168.102.78:49816 -> 144.196.72.136:5004/udp  (7 checks total)
  -> 144.196.72.136:5004  6 checks, 5 with USE-CANDIDATE, mapped (prflx) 80.136.59.151:64079
  -> 144.196.72.136:9000  1 checks, 0 with USE-CANDIDATE, mapped (prflx) 80.136.59.151:17664
  answer -> first ICE check: 148 ms
```

`(sendrecv)` means the m-section has no direction attribute, so the default applies. The reported latencies are much higher than the STUN RTTs seen on the wire, probably because the client times its whole ICE gathering per cluster rather than one binding round trip.

### Usage

```
python3 webex-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH] [-p]
python3 webex-extract-sdp.py --bodies FILE [FILE ...] [-o OUTDIR]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file |
| `-k`, `--keylog` | TLS key log file. Not needed if the keys are embedded. |
| `-o`, `--outdir` | Output directory (default: `<capture>_webex_sdp`, or `webex_sdp_out` with `--bodies`) |
| `--tshark` | Path to tshark if it isn't on `PATH` |
| `-p`, `--print` | Also print the full SDPs |
| `--bodies FILE…` | Skip tshark and decode Locus request/response bodies exported from Wireshark or DevTools (JSON, optionally gzip) |

Output:

| File | Content |
|---|---|
| `<prefix>-seqN-{offer,answer}.sdp` | SDP exactly as sent (CRLF line endings), `N` = ROAP seq |
| `<prefix>-locus-FRAME-{request,response}.json` | Locus body with the nested `localSdp`/`remoteSdp` strings decoded |
| `<prefix>-reachability.tsv` | One row per STUN reachability probe: round, cluster, RTT, retransmits, mapped address |
| `<prefix>-ice-checks.tsv` | STUN binding requests using the negotiated ufrags, with USE-CANDIDATE flag and mapped address |

### Limitations

- Tested with the Webex web client (Chrome) joining a personal-room meeting as a guest. Native Webex apps use other transports and signalling.
- The test capture covers only the first 20 s, so it has no renegotiation (screen share, re-offer). Later ROAP transactions are picked up as long as they travel as Locus HTTP/2 bodies. Server-initiated offers over Mercury are not handled.
- The TURN-TLS connection to the media node (port 443) is not decrypted, because Chrome doesn't write WebRTC TURN-TLS secrets to `SSLKEYLOGFILE`.
- The output and `.json` files contain locus and participant IDs, tokens, ICE passwords and TURN credentials. Review them before sharing.

### Wireshark plugin: webrtc-sdp_in_webex.lua

[webrtc-sdp_in_webex.lua](wireshark/webrtc-sdp_in_webex.lua) does the same inside Wireshark. It decodes the ROAP messages in the Locus HTTP/2 bodies and passes offer and answer to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work. The SDP also appears as an extra bytes tab (`Webex ROAP OFFER` / `Webex ROAP ANSWER`). The echoed offer in the answer frame is linked to the original and not dissected a second time.

Install: copy it to the *Personal Lua Plugins* folder (Help → About Wireshark → Folders), then Analyze → Reload Lua Plugins. It needs decrypted TLS and the default HTTP/2 settings (body reassembly and decompression). No other preferences are needed.

The `sdp_in_webex` tree shows ROAP type, seq, tieBreaker and headers; locus and participant ID; mute state; request/response links with delay; TURN URLs and credentials; the media agent cluster; ICE/DTLS values; candidates; and one entry per m-section with content, direction, transport profile, `b=TIAS`, CSI, codecs, simulcast group and per-SSRC `max-fs`. Webex-specific SDP is flagged as expert info (Analyze → Expert Information). Frames with a reachability report or the Calliope cluster list get their own subtree.

Two more protocols annotate the rest of the setup:

- `webex_mercury` labels every Mercury WebSocket message (type, `eventType`, ack, locus URL) and shows it as a JSON tree.
- `webex_stun` labels STUN reachability probes and responses with their Calliope cluster and RTT, and ICE connectivity checks with the ROAP seq and USE-CANDIDATE.

```
sdp_in_webex                                   frames carrying ROAP / Locus media / reachability
sdp_in_webex.roap.type == "ANSWER"
sdp_in_webex.turn.url
sdp_in_webex.reach.udp_ms < 150
webex_mercury.event == "locus.difference"
webex_stun.kind == "reachability" && webex_stun.cluster contains "wamsm"
webex_stun.use_candidate
sdp.media_attr contains "xTLS"
```

With tshark:

```
$ tshark -X lua_script:wireshark/webrtc-sdp_in_webex.lua -r test-data/webex_20260921_204532_-first-20secs-cleaned.pcapng -Y 'sdp_in_webex.roap.type'
 3270 16.679204900 192.168.102.78 → 170.72.238.49 HTTP2/JSON 1496 DATA[3], JSON (application/json) [ROAP TURN_DISCOVERY_REQUEST seq=0]
 3280 16.811380800 170.72.238.49 → 192.168.102.78 HTTP2/JSON 104 DATA[3], DATA[3], JSON (application/json) [ROAP TURN_DISCOVERY_RESPONSE seq=0]
 3480 18.951082800 192.168.102.78 → 170.72.238.49 HTTP2/JSON/SDP 1162 DATA[7], JSON (application/json) [ROAP OFFER seq=1]
 3508 19.048437500 170.72.238.49 → 192.168.102.78 HTTP2/JSON/SDP 104 DATA[7], DATA[7], JSON (application/json) [ROAP ANSWER seq=1]

$ tshark -2 -X lua_script:wireshark/webrtc-sdp_in_webex.lua -r test-data/webex_20260921_204532_-first-20secs-cleaned.pcapng -Y sdp_in_webex -O sdp_in_webex,sdp
```

Use `-2` (two-pass) to get the *ROAP response in* link on the request frames as well.

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

[webrtc-sdp_in_json.lua](#wireshark-plugin-webrtc-sdp_in_jsonlua) passes these JSON strings to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work.

## License

MIT  See `LICENSE`.
