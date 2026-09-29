# Cisco Webex: webex-extract-sdp.py

Part of [webrtc-extract-sdp](README.md), which covers requirements, test data, capture preparation and the options shared by all scripts.

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

## Usage

```
python3 webex-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH] [-p]
python3 webex-extract-sdp.py --bodies FILE [FILE ...] [-o OUTDIR]
```

The common options `-k`, `-o`, `--tshark` and `-p` are described in the [main README](README.md#usage). The default output directory is `<capture>_webex_sdp`, or `webex_sdp_out` with `--bodies`. Specific to this script:

| Option | Description |
|---|---|
| `--bodies FILE…` | Skip tshark and decode Locus request/response bodies exported from Wireshark or DevTools (JSON, optionally gzip) |

Output:

| File | Content |
|---|---|
| `<prefix>-seqN-{offer,answer}.sdp` | SDP exactly as sent (CRLF line endings), `N` = ROAP seq |
| `<prefix>-locus-FRAME-{request,response}.json` | Locus body with the nested `localSdp`/`remoteSdp` strings decoded |
| `<prefix>-reachability.tsv` | One row per STUN reachability probe: round, cluster, RTT, retransmits, mapped address |
| `<prefix>-ice-checks.tsv` | STUN binding requests using the negotiated ufrags, with USE-CANDIDATE flag and mapped address |

## Limitations

- Tested with the Webex web client (Chrome) joining a personal-room meeting as a guest. Native Webex apps use other transports and signalling.
- The test capture covers only the first 20 s, so it has no renegotiation (screen share, re-offer). Later ROAP transactions are picked up as long as they travel as Locus HTTP/2 bodies. Server-initiated offers over Mercury are not handled.
- The TURN-TLS connection to the media node (port 443) is not decrypted, because Chrome doesn't write WebRTC TURN-TLS secrets to `SSLKEYLOGFILE`.
- The output and `.json` files contain locus and participant IDs, tokens, ICE passwords and TURN credentials. Review them before sharing.

## Wireshark plugin: webrtc-sdp_in_webex.lua

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
