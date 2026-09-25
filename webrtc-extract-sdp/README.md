# extract_sdp

Pull WebRTC **SDP offers and answers** out of a TLS-decrypted packet capture and save each one as a clean, readable `.sdp` file.

WebRTC leaves signalling to the vendor, so the SDP rarely shows up as "SDP" in Wireshark. It is usually a JSON string inside a WebSocket or HTTP/2 message, often with escaped `\r\n` line breaks, sometimes JSON-encoded twice, and sometimes nested deep inside a vendor's own message envelope. `extract_sdp.py` finds it anyway, without needing to know the vendor's field names.

```
$ python3 extract_sdp.py goto1_audio-signaling.pcapng
#1   frame 32      t=    0.190s  offer    192.168.102.79:61322 -> 23.239.237.146:443  m=audio,audio,audio,audio,audio ice-ufrag=L//A candidates=0 lines=147
      -> sdp_out/01_frame32_offer.sdp
#2   frame 40      t=    0.210s  answer   23.239.237.146:443 -> 192.168.102.79:61322  m=audio,audio,audio,audio,audio ice-ufrag=tnn4 candidates=0 lines=94
      -> sdp_out/02_frame40_answer.sdp
#3   frame 57      t=    0.871s  offer    192.168.102.79:61322 -> 23.239.237.146:443  m=audio,audio,audio,audio,audio,audio ice-ufrag=L//A candidates=1 lines=167
      -> sdp_out/03_frame57_offer.sdp
#4   frame 66      t=    0.893s  answer   23.239.237.146:443 -> 192.168.102.79:61322  m=audio,audio,audio,audio,audio,audio ice-ufrag=tnn4 candidates=1 lines=108
      -> sdp_out/04_frame66_answer.sdp
```

## Features

- **Vendor-agnostic.** Doesn't depend on a particular JSON structure or on how Wireshark is configured to dissect the payload. Works with WebSocket text frames, HTTP/2 DATA, HTTP/1.1 bodies and plain JSON.
- **Handles real-world wrapping.** Escaped `\r\n`, SDP nested inside vendor envelopes (e.g. GoTo's `body.events[].value`), and JSON that is itself encoded as a JSON string.
- **Labels offers and answers** by pairing each `"sdp"` with its `"type"`, and records frame number, relative time and direction.
- **One file per SDP**, with real line breaks, ready for diffing or for use in training material.
- **Short summary per SDP:** media sections, ICE ufrag, candidate count and line count, so renegotiations and trickle-ICE behaviour are visible at a glance.
- **Standard library only.** No pip packages; all dissection is done by tshark.

## Requirements

- Python 3.7 or newer
- `tshark` (Wireshark 3.x or newer) on your `PATH`
  - macOS: install Wireshark and add its CLI tools to the path (the installer offers this), or call `/Applications/Wireshark.app/Contents/MacOS/tshark` directly.
  - Debian/Ubuntu: `sudo apt install tshark`
  - Windows: included with the Wireshark installer; add `C:\Program Files\Wireshark` to `PATH`.
- A capture whose TLS traffic can be decrypted: either keys embedded in the pcapng, or a separate `SSLKEYLOGFILE`.

## Installation

```
git clone https://github.com/<you>/extract_sdp.git
cd extract_sdp
python3 extract_sdp.py --help
```

## Usage

```
python3 extract_sdp.py CAPTURE [-o OUTDIR] [-k KEYLOG] [-Y FILTER] [-p]
```

| Option | Description |
|---|---|
| `CAPTURE` | pcap or pcapng file |
| `-o`, `--outdir` | Output directory for the `.sdp` files (default: `sdp_out`) |
| `-k`, `--keylog` | TLS key log file (`SSLKEYLOGFILE` format). Not needed if the keys are embedded in the pcapng. |
| `-Y`, `--filter` | Wireshark display filter that limits which packets are searched (default: `websocket \|\| http2 \|\| http \|\| json`) |
| `-p`, `--print` | Also print each full SDP to stdout |

### Examples

```
# Keys embedded in the pcapng
python3 extract_sdp.py call.pcapng

# Separate key log, print the SDPs as well
python3 extract_sdp.py call.pcapng -k sslkeys.log -p

# Only look at traffic to one signalling server
python3 extract_sdp.py call.pcapng -Y 'ip.addr == 23.239.237.146'

# Nothing found with the default filter? Search all decrypted TLS
python3 extract_sdp.py call.pcapng -Y tls
```

### Output files

Files are named `NN_frameFRAME_TYPE.sdp`, for example `03_frame57_offer.sdp`. `TYPE` is `offer`, `answer`, `pranswer`, or `unknown` if the message carried an SDP but no recognisable type. Line endings are normalised to `\n`.

## How it works

1. Runs `tshark -T json -x --no-duplicate-keys` over the capture. The `-x` option includes the bytes of every data source: decrypted TLS, reassembled and unmasked WebSocket payloads, and decompressed (permessage-deflate) data.
2. Walks every string in the dissection tree and also decodes hex byte fields back to text, so the SDP is found whether Wireshark dissected the payload as JSON, as text, or not at all.
3. Parses every JSON object it finds and recursively looks for `"sdp"` string values that start with `v=0`, including JSON nested inside JSON strings. Each one is paired with the nearest `"type"` of `offer`, `answer` or `pranswer`.
4. Falls back to a regular expression for messages that aren't valid JSON on their own.
5. Removes duplicates (the same SDP is often visible in several fields of one frame), keeping the copy that carries a type label.

The frame number reported is the one where Wireshark shows the reassembled message, i.e. the **last** TCP segment of the message. Preceding segments appear in Wireshark as plain TCP.

## Preparing a capture

Set `SSLKEYLOGFILE` before starting the browser or client, then capture as usual. To make the capture self-contained, embed the keys into the pcapng:

```
editcap --inject-secrets tls,sslkeys.log capture.pcapng capture-with-keys.pcapng
```

Wireshark and tshark then decrypt the file without any extra configuration, and it can be shared as a single file. Keep in mind that anyone with the file can read the decrypted signalling.

## Limitations

- **Trickled ICE candidates** that are sent as separate messages (e.g. `{"candidate":"candidate:…"}`) are not part of an SDP body and are not extracted. The `candidates=` count only reflects `a=candidate` lines inside the SDP itself.
- Vendors that send ICE/DTLS parameters as individual JSON fields or protobuf instead of an SDP blob will produce no output. In that case, look up the ICE ufrag from the STUN `USERNAME` attribute (`stun.att.username`) and search the decrypted signalling for it.
- The whole tshark JSON output is held in memory. For very large captures, narrow the search with `-Y`, or cut the capture down to the signalling conversation first.
- If TLS isn't decrypted, nothing is found. Check Statistics → Protocol Hierarchy in Wireshark: you should see `websocket`, `http2` or `json` under TLS, not only "Application Data".

## Viewing SDP in Wireshark itself

Two things are worth knowing when looking at the same messages in the Wireshark GUI:

- Ctrl+F with **Packet details** searches the tree item *labels*, which are truncated at 240 characters. A JSON-wrapped SDP is one long line, so strings like `a=candidate` further in are never found. Search with a display filter instead, which matches the full field value.
- Set Preferences → Protocols → WebSocket → *Dissect websocket text as* → **JSON**, then filter with, for example:

  ```
  json.value.string contains "a=candidate"
  json.value.string == "offer" || json.value.string == "answer"
  ```

The companion Lua plugin `sdp_in_json.lua` passes these JSON strings to Wireshark's built-in SDP dissector, so each SDP line becomes its own tree item and `sdp.*` filters work.

## License

MIT  See `LICENSE`.
