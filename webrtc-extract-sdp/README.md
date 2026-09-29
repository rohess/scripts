# webrtc-extract-sdp

Pull WebRTC **SDP offers and answers** out of a TLS-decrypted packet capture and save them as readable files.

WebRTC leaves signalling to the vendor, so the SDP rarely shows up as "SDP" in Wireshark. Each product needs its own approach. The Python scripts write the SDP to files; the Wireshark plugins in [wireshark/](wireshark/) show the same SDP in the packet tree:

| Product | Script | Wireshark plugin | Signalling transport |
|---|---|---|---|
| [GoTo](README-goto.md) (and other JSON-based signalling) | `goto-extract-sdp.py` | `webrtc-sdp_in_json.lua` | TLS / WebSocket or HTTP/2 / JSON containing SDP text |
| [Google Meet](README-meet.md) | `meet-extract-sdp.py` | `webrtc-sdp_in_meet.lua` | TLS / HTTP/2 / protobuf (no SDP on the wire) |
| [Microsoft Teams](README-teams.md) | `teams-extract-sdp.py` | `webrtc-sdp_in_teams.lua` | Offer: TLS / HTTP/2 / JSON. Answer: TLS / WebSocket (Trouter) / base64+gzip JSON |
| [Cisco Webex](README-webex.md) (web client) | `webex-extract-sdp.py` | `webrtc-sdp_in_webex.lua` | TLS / HTTP/2 / JSON (Locus) / ROAP JSON string containing SDP. Offer and answer in one PUT request/response |
| [Zoom](README-zoom.md) (web client) | `zoom-extract-sdp.py` | `webrtc-sdp_in_zoom.lua` | TLS / WebSocket / Zoom binary records / JSON. Two PeerConnections: data channel with plain SDP, audio with gzip+base64 SDP |

All scripts share the same basic command line (see [Usage](#usage)). How each product transports the SDP, what the scripts print, their limitations and the matching Wireshark plugin are described in the product READMEs linked in the table.

## Requirements

- Python 3.7+ (3.8+ for the Meet, Teams and Webex scripts), standard library only
- `tshark` (Wireshark 4.6 or newer) on your `PATH`, or pass its location with `--tshark`
  - macOS: add Wireshark's CLI tools to the path, or use `/Applications/Wireshark.app/Contents/MacOS/tshark`
  - Debian/Ubuntu: `sudo apt install tshark`
  - Windows: add `C:\Program Files\Wireshark` to `PATH`
- Decryptable TLS: keys embedded in the pcapng, or a separate `SSLKEYLOGFILE` (see [Preparing a capture](#preparing-a-capture))
- Alternatively use the capture scripts from [ssldump](https://github.com/rohess/scripts/tree/main/ssldump) - the one for Windows runs the capture via dumpcap and injects TLS keys afterwards

## Test data

[test-data/](test-data/) contains sample captures with TLS secrets embedded, so they work without a key log:

| File | Use with |
|---|---|
| `goto_audio-signaling.pcapng` | `python3 goto-extract-sdp.py test-data/goto_audio-signaling.pcapng` |
| `meet9_signaling.pcapng` | `python3 meet-extract-sdp.py test-data/meet9_signaling.pcapng` |
| `teams_signaling.pcapng` | `python3 teams-extract-sdp.py test-data/teams_signaling.pcapng` |
| `webex_20260921_204532_-first-20secs-cleaned.pcapng` | `python3 webex-extract-sdp.py test-data/webex_20260921_204532_-first-20secs-cleaned.pcapng` |
| `Zoom4-start.pcapng` | `python3 zoom-extract-sdp.py test-data/Zoom4-start.pcapng` |

Anyone with these files can read the decrypted signalling, so only share captures of test calls.

## Usage

All scripts take the same basic arguments:

```
python3 <product>-extract-sdp.py CAPTURE [-k KEYLOG] [-o OUTDIR] [--tshark PATH] [-p]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file with decryptable TLS |
| `-k`, `--keylog` | TLS key log file (`SSLKEYLOGFILE` format). Not needed if the keys are embedded in the pcapng. |
| `-o`, `--outdir` | Output directory, created if missing (defaults below) |
| `--tshark` | Path to tshark if it isn't on `PATH` |
| `-p`, `--print` | Also print the full SDPs to stdout (all scripts except Meet) |

```
python3 teams-extract-sdp.py call.pcapng                            # keys embedded, output to call_teams_sdp/
python3 webex-extract-sdp.py call.pcapng -k sslkeys.log -o /tmp/wx  # separate key log
python3 zoom-extract-sdp.py call.pcapng -p                          # also print the SDPs
```

Some scripts have one extra option. `--bodies` and `--payloads` replace `CAPTURE` and `-k`: they decode data exported from Wireshark or the browser's DevTools, and tshark isn't needed.

| Script | Extra option | Description |
|---|---|---|
| `goto-extract-sdp.py` | `-Y`, `--filter` | Wireshark display filter that limits which packets are searched |
| `meet-extract-sdp.py` | `--bodies REQ RESP` | Decode an exported `CreateMediaSession` request and response body |
| `teams-extract-sdp.py` | `--bodies FILE…` | Decode an exported join request, Trouter frame or base64/gzip data |
| `webex-extract-sdp.py` | `--bodies FILE…` | Decode exported Locus request/response bodies |
| `zoom-extract-sdp.py` | `--payloads FILE…` | Decode exported (unmasked) WebSocket binary payloads |

### Output

Each script prints a summary of what it found (frames, offer/answer pairing, ICE parameters, candidates, delays) and writes the SDPs plus some supporting files to the output directory:

| Script | Default output directory | With `--bodies` / `--payloads` |
|---|---|---|
| `goto-extract-sdp.py` | `sdp_out` | - |
| `meet-extract-sdp.py` | `<capture>_meet_sdp` | `meet_sdp_out` |
| `teams-extract-sdp.py` | `<capture>_teams_sdp` | `teams_sdp_out` |
| `webex-extract-sdp.py` | `<capture>_webex_sdp` | `webex_sdp_out` |
| `zoom-extract-sdp.py` | `<capture>_zoom_sdp` | `zoom_sdp_out` |

`<capture>` is the capture path without its extension, so by default the output lands next to the capture. File names start with `<prefix>`: the capture file name without directory and extension, or `bodies` / `payloads` in offline mode.

| File | Scripts | Content |
|---|---|---|
| `*.sdp` | GoTo, Teams, Webex, Zoom | One file per offer/answer, exactly as sent (CRLF line endings). GoTo normalises line endings to `\n`. |
| `*.sdp.txt` | Meet | Approximate SDP rendered from protobuf (Meet sends no SDP) |
| `*.json`, `*.ndjson` | Teams, Webex, Zoom | Decoded signalling messages the SDP came from |
| `<prefix>-ice-checks.tsv` | Meet, Teams, Webex, Zoom | STUN connectivity checks that use the negotiated ICE ufrags |

The exact file names and the product-specific extras are listed in each product README.

The output files can contain meeting IDs and passcodes, auth tokens, ICE passwords and TURN credentials. Review them before sharing.

### Wireshark plugins

Copy the plugin to the *Personal Lua Plugins* folder (Help → About Wireshark → Folders), then Analyze → Reload Lua Plugins. All plugins need decrypted TLS; `webrtc-sdp_in_json.lua` also needs WebSocket text dissected as JSON. They pass the SDP to Wireshark's built-in SDP dissector, so `sdp.*` filters work. With tshark, load a plugin with `-X lua_script:wireshark/<plugin>.lua`. Filters, extra protocols and tshark examples are in the product READMEs.

## Preparing a capture

Set `SSLKEYLOGFILE` before starting the browser, then capture as usual. To make the capture self-contained, embed the keys:

```
editcap --inject-secrets tls,sslkeys.log capture.pcapng capture-with-keys.pcapng
```

Anyone with the resulting file can read the decrypted signalling.

## License

MIT  See `LICENSE`.
