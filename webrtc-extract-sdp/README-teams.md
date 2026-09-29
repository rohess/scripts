# Microsoft Teams: teams-extract-sdp.py

Part of [webrtc-extract-sdp](README.md), which covers requirements, test data, capture preparation and the options shared by all scripts.

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

## Usage

```
python3 teams-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH] [-p]
python3 teams-extract-sdp.py --bodies FILE [FILE ...] [-o OUTDIR]
```

The common options `-k`, `-o`, `--tshark` and `-p` are described in the [main README](README.md#usage). The default output directory is `<capture>_teams_sdp`, or `teams_sdp_out` with `--bodies`. Specific to this script:

| Option | Description |
|---|---|
| `--bodies FILE…` | Skip tshark and decode bodies exported from Wireshark or DevTools: the join request JSON, a Trouter frame (`3:::{…}`), or base64/gzip data |

Output per call leg (`NN` = leg number):

| File | Content |
|---|---|
| `<prefix>-NN-{offer,answer}.sdp` | SDP exactly as sent (CRLF line endings) |
| `<prefix>-NN-{offer,answer}.json` | Decoded signalling JSON the SDP came from (join request / decoded acceptance body) |
| `<prefix>-NN-sdpK.{sdp,json}` | SDPs found under other JSON keys (role unknown) |
| `<prefix>-ice-checks.tsv` | STUN binding requests using the negotiated ufrags, with USE-CANDIDATE flag |

## Limitations

- Tested with the Teams web client joining a consumer (teams.live.com) meeting. Other clients or tenants may use other callbacks (e.g. `call/mediaAnswer`, renegotiation); they are picked up as long as the SDP sits in a JSON string starting with `v=0`.
- The `.json` files contain the meeting URL, passcode and participant IDs. Review them before sharing.
- Trickled candidates were not seen in the test capture, so only the candidates inside the SDP are shown.

## Wireshark plugin: webrtc-sdp_in_teams.lua

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
