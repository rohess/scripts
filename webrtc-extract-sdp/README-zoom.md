# Zoom: zoom-extract-sdp.py

Part of [webrtc-extract-sdp](README.md), which covers requirements, test data, capture preparation and the options shared by all scripts.

The Zoom web client uses no SIP and no REST call for SDP. All signalling runs over **WebSockets to one "RWG" host** (e.g. `zoomiad20624799165rwg.iad.zoom.us`; the name encodes the IP and region). The same host is also the ICE-lite media server. Every binary WebSocket message holds one or more Zoom records:

```
record := type:u8  len:u16be  body[len]
  0x01 / 0x02   session handshake (C->S / S->C), opaque
  0x03 / 0x04   ping / pong: u32 counter, u32 timestamp, 00, 37 f9, channel, 00 (pong echoes the ping)
  0x05          data: u16 seq, 00, 37 f9, channel (0x09 /webclient, 0x0a /wc/media), flags,
                subtype (0x0d JSON, 0x0a ACK), sub-header ..., JSON {"evt": <int>, "seq": <int>, "body": {...}}
```

The browser builds **two RTCPeerConnections**, each negotiated on its own WebSocket:

| PeerConnection | WebSocket | Messages | SDP |
|---|---|---|---|
| PC-DC: data channel only (`m=application`) | `/webclient/<meeting>` | `evt 24321` offer / `evt 24322` answer | Plain string in `offer.sdp` / `answer.sdp` |
| PC-AUDIO: 2 send + 3 receive audio m-lines | `/wc/media/<meeting>?mode=16` | `evt 32769`, `body.type` 4 = pre-offer (empty), 1 = offer, 2 = answer, 3 = confirm | gzip + base64 in `body.sdp` (`"sdpEncoding": 1`) |

The offers carry no candidates and none are trickled. The server is ICE-lite and learns the client address as peer-reflexive from the ICE checks. TURN/STUN servers arrive in `evt 4130` (before the offers) and again in the join response `evt 4098`.

The script:

1. Uses tshark to find the WebSocket upgrades to `/webclient/` and `/wc/media/`, then dumps the unmasked payload of every WebSocket message on those connections.
2. Splits the Zoom records and decodes the JSON after the sub-header. The sub-header layout varies, so the script looks for the first `{"` and ignores trailing bytes.
3. Exports every SDP byte for byte as sent (CRLF kept), after gunzip/base64 where needed. PC-DC offers and answers are paired by order on their WebSocket, PC-AUDIO by connection + `peerID` + `msgID` (the answer has no `sessionID`).
4. Prints the ICE servers, a per-mid table (directions, SSRCs, Opus profile of the offer, answer codecs) and notes on Zoom-specific SDP: no candidates in the offer, non-zero `t=`, `ice-lite`, the same port on UDP and TCP, codecs dropped and `rtcp-fb` added by the answer, and the same DTLS fingerprint on both PeerConnections.
5. Maps STUN checks to their PeerConnection via the USERNAME and shows who sent them: the audio server sends its own checks despite `a=ice-lite`, the data channel server doesn't.
6. Prints a setup timeline: WebSocket upgrades, ICE servers, offers/answers, first ICE check and success, DTLS, meeting join (`evt 4301` / `4098`) and first SRTCP/SRTP. SRTP and SRTCP are identified by their first bytes (RFC 7983), because Wireshark shows them as plain data or misdissects them.

```
$ python3 zoom-extract-sdp.py test-data/Zoom4-start.pcapng -o /tmp/zoom
Zoom WebSockets
  tcp.stream 12   zoomiad20624799165rwg.iad.zoom.us  /webclient/4846855567  101 in frame 2780 t=3.292s  147 message(s)
  tcp.stream 13   zoomiad20624799165rwg.iad.zoom.us  /wc/media/4846855567?mode=16  101 in frame 2824 t=3.853s  70 message(s)
  ...
ICE servers in frame 2788 (evt 4130 media SDK config)
  turn:turniad02.iad.zoom.us:3478?transport=udp  username 06493C3A-...:1790081367136  credential ...
  ...
Found 4 SDP(s) in 2 negotiation(s)

[1] PC-DC (data channel)
  OFFER     frame 2790 t=3.493s  evt 24321 C->S (webclient, tcp.stream 12)  192.168.102.79:62459 -> 206.247.99.165:443
      offer.sdp (plain)  1 m-lines, 17 lines, ice-ufrag=RfLA setup=actpass candidates=0
  ANSWER    frame 2794 t=3.597s  evt 24322 S->C (webclient, tcp.stream 12)  206.247.99.165:443 -> 192.168.102.79:62459
      answer.sdp (plain)  1 m-lines, 22 lines, ice-ufrag=374C56B5A62DBA43EFAE473ADCE0A4CC0698 setup=passive ice-lite candidates=4
        a=candidate:1 1 UDP 2130450431 206.247.99.165 8801 typ host
        a=candidate:2 1 UDP 2130450175 206.247.99.165 3478 typ host
        ...
  offer -> answer: 104 ms
  ...

[2] PC-AUDIO  peerID 0 msgID 1
  PRE-OFFER frame 2848 t=4.014s  evt 32769 C->S (media mode=16, tcp.stream 13)  192.168.102.79:57728 -> 206.247.99.165:443
  OFFER     frame 2850 t=4.014s  evt 32769 C->S (media mode=16, tcp.stream 13)  192.168.102.79:57728 -> 206.247.99.165:443
      body: type=1  confID=06493C3A-...  sessionID=2  peerID=0  msgID=1  sdpEncoding=1
      featureToggles: webrtc_dynamic_egress_media_streams=true, ...
      body.sdp (gzip+base64)  5 m-lines, 153 lines, ice-ufrag=qNCb setup=actpass candidates=0
  ANSWER    frame 2862 t=4.127s  evt 32769 S->C (media mode=16, tcp.stream 13)  206.247.99.165:443 -> 192.168.102.79:57728
      body.sdp (gzip+base64)  5 m-lines, 133 lines, ice-ufrag=344f05e8+8284+4e78+9b87+b132b47d85d7+010 setup=passive ice-lite candidates=4
        a=candidate:1 1 udp 2130706175 206.247.99.165 8804 typ host
        a=candidate:2 1 tcp 1694498559 206.247.99.165 8801 typ host tcptype passive
        ...
  CONFIRM   frame 2869 t=4.153s  evt 32769 C->S (media mode=16, tcp.stream 13)  192.168.102.79:57728 -> 206.247.99.165:443
  offer -> answer: 113 ms
  per-mid:
  mid  kind   offer dir  offer ssrc  offer opus     answer dir  answer ssrc  answer codecs
  0    audio  sendonly   4167787425  swb 48k fec    recvonly    -            111:opus
  1    audio  sendonly   3999427109  fb 96k no-fec  recvonly    -            111:opus
  2    audio  recvonly   -           stereo fec     sendonly    83502589     111:opus 63:red>111
  3    audio  recvonly   -           stereo fec     sendonly    3514928771   111:opus 63:red>111
  4    audio  recvonly   -           stereo fec     sendonly    2521889482   111:opus 63:red>111
  note: offer has no candidates (and none are trickled) - the ICE-lite server learns the client address as peer-reflexive from the ICE checks
  note: offer has t=3999070167 0 (browsers send t=0 0) - SDP munged by the Zoom client
  note: answer is ice-lite - the browser is ICE controlling
  note: answer drops codecs: CN, G722, PCMA, PCMU, telephone-event
  note: answer adds rtcp-fb not in the offer: opus nack

note: both PeerConnections' answers use the same DTLS fingerprint sha-256 BD:3F:27:5E:1F:56:A3:E... (one server certificate)

SSRC announcement (evt 32776, frame 3968): normal_ssrc=4167787425 (0xF86B63A1), share_ssrc=3999427109 (0xEE626A25)

ICE checks
  [1] PC-DC
    client 192.168.102.79:49512 -> 206.247.99.165:8801/udp  11 request(s), 11 answered, 10 USE-CANDIDATE, mapped (prflx) 93.212.136.30:8466  first frame 2796 t=3.612s
    client 192.168.102.79:49512 -> 206.247.99.165:3478/udp  23 request(s), 0 answered, 0 USE-CANDIDATE  first frame 2801 t=3.665s
    no server-initiated checks (pure ICE-lite behaviour)
  [2] PC-AUDIO
    client 192.168.102.79:59878 -> 206.247.99.165:8804/udp  11 request(s), 11 answered, 9 USE-CANDIDATE, mapped (prflx) 93.212.136.30:23068  first frame 2867 t=4.147s
    server 206.247.99.165:8804 -> 192.168.102.79:59878/udp  11 request(s), 11 answered, 0 USE-CANDIDATE  first frame 2880 t=4.251s

Setup timeline
  t=   3.292s  +      0 ms  frame 2780   WebSocket 101 webclient
  t=   3.408s  +    116 ms  frame 2788   evt 4130 media SDK config
  t=   3.493s  +    201 ms  frame 2790   PC-DC offer
  t=   3.597s  +    305 ms  frame 2794   PC-DC answer
  t=   3.612s  +    320 ms  frame 2796   PC-DC first ICE check -> 206.247.99.165:8801
  t=   3.716s  +    424 ms  frame 2802   PC-DC ICE success, mapped 93.212.136.30:8466
  ...
  t=   4.462s  +   1170 ms  frame 2913   PC-AUDIO DTLS server ChangeCipherSpec/Finished
  t=   5.233s  +   1942 ms  frame 2967   PC-AUDIO first SRTCP (S->C)
  t=  23.162s  +  19870 ms  frame 3513   evt 4301 join meeting
  t=  23.524s  +  20232 ms  frame 3594   evt 4098 join response
  t=  23.683s  +  20391 ms  frame 3968   evt 32776 SSRC announcement
  t=  24.916s  +  21624 ms  frame 5050   evt 8203 audio on
  t=  24.925s  +  21633 ms  frame 5069   PC-AUDIO first SRTP (C->S)
  media pre-warmed: ICE/DTLS up 18.7 s before the meeting join request (evt 4301)
```

Both PeerConnections are up (ICE + DTLS) about 19 s before the meeting join: the client warms up media while the preview/join screen is shown. Opus profiles follow RFC 7587 (`maxplaybackrate` 24000 = `swb`, 48000 = `fb`).

## Usage

```
python3 zoom-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH] [-p]
python3 zoom-extract-sdp.py --payloads FILE [FILE ...] [-o OUTDIR]
```

The common options `-k`, `-o`, `--tshark` and `-p` are described in the [main README](README.md#usage). The default output directory is `<capture>_zoom_sdp`, or `zoom_sdp_out` with `--payloads`. Specific to this script:

| Option | Description |
|---|---|
| `--payloads FILE…` | Skip tshark and decode unmasked WebSocket binary payloads, e.g. saved with File → Export Packet Bytes on the WebSocket *Payload* field |

Output (`NN` = negotiation number, `PC` = `dc` or `audio`):

| File | Content |
|---|---|
| `<prefix>-NN-PC-{offer,answer}.sdp` | SDP exactly as sent (CRLF line endings) |
| `<prefix>-messages.ndjson` | Every decoded Zoom record: frame, time, direction, WebSocket, record type, channel, ping counter, `evt` and JSON |
| `<prefix>-ice-checks.tsv` | STUN binding requests using the negotiated ufrags: PeerConnection, initiator (client/server), USE-CANDIDATE, response frame and mapped address |

## Limitations

- Tested with the Zoom web client (Chrome, installed as a PWA) joining a personal meeting room, muted and without video. The native Zoom client uses a different transport.
- The record sub-header is reverse-engineered from one capture. The script only relies on the record header, the `37 f9` magic and the JSON; everything in between is shown undecoded.
- The meanings of `evt 32769` types 4 (pre-offer, empty SDP) and 3 (confirm) are inferred.
- The `/wc/media?mode=5` and `mode=2` WebSockets carry no Zoom records after their text welcome message, only opaque binary data. They are listed but not decoded.
- The test capture has no renegotiation (video, screen share). Later offers/answers are picked up as long as they use the same `evt` codes.
- Media is DTLS-SRTP, and the join response announces Zoom's own end-to-end encryption (`e2eEncrypt`, `encType`), so the media payload stays opaque.
- The output and the `.ndjson` file contain the meeting number and passcode, auth tokens, display name, ICE passwords and TURN credentials. Review them before sharing.

## Wireshark plugin: webrtc-sdp_in_zoom.lua

[webrtc-sdp_in_zoom.lua](wireshark/webrtc-sdp_in_zoom.lua) does the same inside Wireshark. It registers as a heuristic dissector for WebSocket payloads, splits the Zoom records and hands each JSON message to Wireshark's built-in JSON dissector, so `json.*` filters work. The offers and answers are decoded (gzip+base64 where needed) and passed to the built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work. The SDP also appears as an extra bytes tab (e.g. `Zoom SDP offer (PC-AUDIO)`).

Install: copy it to the *Personal Lua Plugins* folder (Help → About Wireshark → Folders), then Analyze → Reload Lua Plugins. It needs decrypted TLS. No preferences are needed.

It adds three protocols:

- `zoom_ws` shows each record: type, length, seq, magic, channel, flags, `evt` (with name) and `seq`. It also shows the ICE/TURN servers from `evt 4130`/`4098`, the SSRCs from `evt 32776` and the link-quality reports (`evt 32770`). Client pings are linked to the server's pong, with the WebSocket RTT.
- `sdp_in_zoom` shows PeerConnection, type, `sessionID`/`peerID`/`msgID`, `featureToggles`, links between offer and answer with the delay, ICE/DTLS values, candidates, and one entry per m-section with direction, SSRCs, codecs and Opus fmtp. Zoom-specific SDP is flagged as expert info (Analyze → Expert Information).
- `zoom_stun` labels ICE checks and responses with their PeerConnection and with who sent the check (client or server).

```
sdp_in_zoom                                    frames carrying a Zoom offer/answer
sdp_in_zoom.pc == "PC-AUDIO" && sdp_in_zoom.type == "answer"
zoom_ws.evt == 4098                            join response
zoom_ws.turn.url                               ICE/TURN server configuration
zoom_ws.ping.rtt_ms > 150
zoom_stun.initiator == "server"                checks sent by the ICE-lite server
sdp.media_attr contains "ssrc"
```

With tshark:

```
$ tshark -X lua_script:wireshark/webrtc-sdp_in_zoom.lua -r test-data/Zoom4-start.pcapng -Y sdp_in_zoom
 2790 3.492741500 192.168.102.79 → 206.247.99.165 WebSocket/Zoom/JSON/SDP 643 WebSocket Binary [FIN] [MASKED], JSON [Zoom PC-DC offer]
 2794 3.597140200 206.247.99.165 → 192.168.102.79 WebSocket/Zoom/JSON/SDP 973 WebSocket Binary [FIN] , JSON [Zoom PC-DC answer]
 2848 4.013969300 192.168.102.79 → 206.247.99.165 WebSocket/Zoom/JSON 225 WebSocket Binary [FIN] [MASKED], JSON [Zoom PC-AUDIO pre-offer]
 2850 4.014232700 192.168.102.79 → 206.247.99.165 WebSocket/Zoom/JSON/SDP 340 WebSocket Binary [FIN] [MASKED], JSON [Zoom PC-AUDIO offer]
 2862 4.126840000 206.247.99.165 → 192.168.102.79 WebSocket/Zoom/JSON/SDP 191 WebSocket Binary [FIN] , JSON [Zoom PC-AUDIO answer]
 2869 4.152905200 192.168.102.79 → 206.247.99.165 WebSocket/Zoom/JSON 216 WebSocket Binary [FIN] [MASKED], JSON [Zoom PC-AUDIO confirm]

$ tshark -X lua_script:wireshark/webrtc-sdp_in_zoom.lua -r test-data/Zoom4-start.pcapng -Y 'zoom_ws.ping.counter'
 3002 7.042909400 192.168.102.79 → 206.247.99.165 WebSocket/Zoom 98 WebSocket Binary [FIN] [MASKED] [Zoom client ping #1]
 3004 7.146743900 206.247.99.165 → 192.168.102.79 WebSocket/Zoom 94 WebSocket Binary [FIN]  [Zoom server pong #1 rtt 103.8 ms]
 3005 7.156768400 206.247.99.165 → 192.168.102.79 WebSocket/Zoom 94 WebSocket Binary [FIN]  [Zoom server ping #1]
 3007 7.164005800 192.168.102.79 → 206.247.99.165 WebSocket/Zoom 98 WebSocket Binary [FIN] [MASKED] [Zoom client pong #1]
 ...

$ tshark -2 -X lua_script:wireshark/webrtc-sdp_in_zoom.lua -r test-data/Zoom4-start.pcapng -Y sdp_in_zoom -O sdp_in_zoom,sdp
```

Use `-2` (two-pass) to get the *Answer in* link on the offer frames as well. The server's pings are linked to the client's pong, but no RTT is shown for them: at a capture point next to the client, that interval is only the client's response time.

By default Wireshark shows Zoom's SRTP/SRTCP as plain UDP data. With the `rtp_udp` heuristic enabled (Analyze → Enabled Protocols, or `tshark --enable-heuristic rtp_udp`), it shows SRTP and SRTCP. The RTCP XR packets are then flagged as malformed, and the first RTCP SR (frame 5068) still shows as plain UDP.
