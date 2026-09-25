#!/usr/bin/env python3
"""
meet_sdp_from_pcap.py - pull the Google Meet offer/answer out of a capture and
render it as readable (approximate) SDP.

Pipeline
  1. tshark finds the HTTP/2 stream(s) carrying
     /$rpc/google.rtc.meetings.v1.MediaSessionService/CreateMediaSession
  2. request body (client offer) and response body (server answer) are reassembled,
     gunzipped and base64-decoded as needed
  3. protobuf is decoded (built-in, no protoc needed) and rendered as SDP
  4. bonus: STUN checks using the negotiated ICE ufrags are listed, i.e. the media flow

Requirements
  Python 3.8+, Wireshark/tshark 3.x or 4.x.
  TLS must be decryptable: pass --keylog, or use a pcapng with embedded secrets
  (editcap --inject-secrets tls,keys.log in.pcapng out.pcapng).

Usage
  python3 meet_sdp_from_pcap.py capture.pcapng --keylog sslkeys.log
  python3 meet_sdp_from_pcap.py capture.pcapng -o outdir
  python3 meet_sdp_from_pcap.py --bodies req.bin resp.bin      # skip tshark, use exported bodies

Protobuf field meanings are reverse-engineered from one capture; guesses are marked ';'.
"""
import argparse
import base64
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import zlib

URI_MARK = "CreateMediaSession"

# =====================================================================  tshark
def find_tshark(explicit=None):
    for cand in (explicit, shutil.which("tshark"),
                 "/Applications/Wireshark.app/Contents/MacOS/tshark",
                 r"C:\Program Files\Wireshark\tshark.exe"):
        if cand and os.path.exists(cand):
            return cand
    sys.exit("tshark not found - install Wireshark or pass --tshark /path/to/tshark")


def run_tshark(tshark, pcap, keylog, args, fatal=True):
    cmd = [tshark, "-r", pcap, "-n"]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += args
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        msg = f"tshark failed:\n  {' '.join(cmd)}\n{res.stderr.strip()}"
        if fatal:
            sys.exit(msg)
        print("  (optional step skipped) " + msg.splitlines()[-1])
        return ""
    return res.stdout


def _merge_dupes(pairs):
    """json object_pairs_hook: tshark JSON repeats keys; collect repeats into lists."""
    d = {}
    for k, v in pairs:
        if k in d:
            d[k] = (d[k] if isinstance(d[k], list) and k in _merge_dupes.multi else [d[k]]) + [v]
            _merge_dupes.multi.add(k)
        else:
            d[k] = v
    _merge_dupes.multi.clear()
    return d
_merge_dupes.multi = set()


def walk(obj):
    """Yield every dict nested anywhere in obj."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def first(v):
    return v[0] if isinstance(v, list) else v


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def hex_to_bytes(s):
    return bytes.fromhex(s.replace(":", "").strip())


def extract_bodies(tshark, pcap, keylog):
    """Return list of dicts: {tcp_stream, sid, req_frame, resp_frame, req_chunks, resp_chunks, time}."""
    # pass 1: which TCP streams carry the RPC at all (cheap)
    flt = (f'http2.header.value contains "{URI_MARK}" or '
           f'http2.request.full_uri contains "{URI_MARK}"')
    out = run_tshark(tshark, pcap, keylog, ["-Y", flt, "-T", "fields", "-e", "tcp.stream"])
    tcp_streams = sorted({int(x) for line in out.split() for x in line.split(",") if x.strip()})
    if not tcp_streams:
        sys.exit("No CreateMediaSession found. Is TLS decrypted (--keylog / embedded secrets)?")

    # pass 2: full JSON of all HTTP/2 frames on those TCP streams
    # tshark 4.6 requires commas in sets; -J (not -j) keeps the http2 child nodes
    flt = "http2 and tcp.stream in {" + ",".join(map(str, tcp_streams)) + "}"
    out = run_tshark(tshark, pcap, keylog,
                     ["-2", "-Y", flt, "-T", "json", "-J", "frame tcp http2"])
    packets = json.loads(out or "[]", object_pairs_hook=_merge_dupes)

    sessions = {}            # (tcp_stream, sid) -> record
    req_dir = {}             # (tcp_stream, sid) -> client port
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame_no = int(first(layers.get("frame", {}).get("frame.number", 0)))
        t_rel = float(first(layers.get("frame", {}).get("frame.time_relative", 0)))
        tcp = layers.get("tcp", {})
        tcp_stream = int(first(tcp.get("tcp.stream", -1)))
        sport = int(first(tcp.get("tcp.srcport", 0)))
        for h2 in walk(layers.get("http2", {})):
            if "http2.streamid" not in h2:
                continue
            sid = int(first(h2["http2.streamid"]))
            ftype = str(first(h2.get("http2.type", "")))
            key = (tcp_stream, sid)
            blob = json.dumps(h2)
            if URI_MARK in blob:
                rec = sessions.setdefault(key, dict(tcp_stream=tcp_stream, sid=sid, req_frame=None,
                                                    resp_frame=None, req_chunks=[], resp_chunks=[],
                                                    time=None))
                if ftype == "1" and key not in req_dir:      # HEADERS with :path -> client side
                    req_dir[key] = sport
                    rec["req_frame"], rec["time"] = frame_no, t_rel
            if key not in sessions or ftype != "0":
                continue
            rec = sessions[key]
            datas = [d for d2 in walk(h2) for d in as_list(d2.get("http2.data.data"))]
            if not datas:
                continue
            client_side = req_dir.get(key) == sport if key in req_dir else sport != 443
            side = "req" if client_side else "resp"
            for d in datas:
                rec[f"{side}_chunks"].append(hex_to_bytes(d))
            if side == "resp":
                rec["resp_frame"] = frame_no
            elif rec["req_frame"] is None:
                rec["req_frame"] = frame_no
    return [sessions[k] for k in sorted(sessions, key=lambda k: sessions[k]["req_frame"] or 0)]


def stun_checks(tshark, pcap, keylog, ufrags):
    ufrags = [u for u in ufrags if u]
    if not ufrags:
        return ""
    flt = " or ".join(f'stun.att.username contains "{u}"' for u in ufrags)
    return run_tshark(tshark, pcap, keylog, [
        "-Y", f"({flt}) and stun.type == 0x0001", "-T", "fields", "-E", "separator=\t",
        "-e", "frame.number", "-e", "frame.time_relative", "-e", "ip.src", "-e", "udp.srcport",
        "-e", "tcp.srcport", "-e", "ip.dst", "-e", "udp.dstport", "-e", "tcp.dstport",
        "-e", "stun.att.username", "-e", "stun.att.type"], fatal=False)


# =====================================================================  body decoding
B64_RE = re.compile(rb"^[A-Za-z0-9+/_\-=\s]+$")


def unwrap(b):
    """gunzip / base64 until we have something that parses as protobuf."""
    for _ in range(4):
        b = b.strip() if B64_RE.match(b or b"-") else b
        if b[:2] == b"\x1f\x8b":
            try:
                b = gzip.decompress(b)
            except (OSError, EOFError, zlib.error):
                b = zlib.decompressobj(31).decompress(b)   # tolerate trailing junk
            continue
        if len(b) > 16 and B64_RE.match(b):
            s = b.decode().strip()
            s += "=" * (-len(s) % 4)
            b = base64.urlsafe_b64decode(s) if ("-" in s or "_" in s) else base64.b64decode(s)
            continue
        break
    return b


def body_to_message(chunks):
    """Try the concatenation first, then individual chunks (tshark may report
    both raw per-frame data and the reassembled/decompressed body)."""
    cands = []
    if chunks:
        cands.append(b"".join(chunks))
        cands += sorted(chunks, key=len, reverse=True)
    for c in cands:
        try:
            raw = unwrap(c)
            msg = parse_pb(raw, strict=True)
            if msg:
                return msg, raw
        except Exception:
            continue
    return None, None


# =====================================================================  protobuf (decode_raw)
def _varint(b, i):
    n = shift = 0
    while True:
        if i >= len(b) or shift > 63:
            raise ValueError("bad varint")
        x = b[i]; i += 1
        n |= (x & 0x7F) << shift
        if not x & 0x80:
            return n, i
        shift += 7


def _printable(b):
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if s.isprintable() else None


def parse_pb(b, strict=False):
    """Returns [(field, value)] like protoc --decode_raw. value: int | str | bytes | list."""
    out, i = [], 0
    while i < len(b):
        tag, i = _varint(b, i)
        field, wt = tag >> 3, tag & 7
        if field == 0:
            raise ValueError("field 0")
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 1:
            if i + 8 > len(b): raise ValueError("short fixed64")
            v, i = int.from_bytes(b[i:i + 8], "little"), i + 8
        elif wt == 5:
            if i + 4 > len(b): raise ValueError("short fixed32")
            v, i = int.from_bytes(b[i:i + 4], "little"), i + 4
        elif wt == 2:
            ln, i = _varint(b, i)
            if i + ln > len(b): raise ValueError("short len")
            chunk, i = b[i:i + ln], i + ln
            s = _printable(chunk)
            if s is not None:
                v = s
            else:
                try:
                    v = parse_pb(chunk)
                    if not v and chunk:
                        raise ValueError
                except ValueError:
                    v = chunk
        else:
            raise ValueError(f"wire type {wt}")
        out.append((field, v))
    return out


def fmt_pb(msg, ind=0):
    """protoc --decode_raw style text."""
    L, pad = [], "  " * ind
    for k, v in msg:
        if isinstance(v, list):
            L.append(f"{pad}{k} {{")
            L.extend(fmt_pb(v, ind + 1))
            L.append(f"{pad}}}")
        elif isinstance(v, str):
            L.append(f'{pad}{k}: "' + v.replace("\\", "\\\\").replace('"', '\\"') + '"')
        elif isinstance(v, bytes):
            L.append(f'{pad}{k}: "' + "".join(chr(c) if 32 <= c < 127 and c not in (34, 92)
                                              else f"\\{c:03o}" for c in v) + '"')
        else:
            L.append(f"{pad}{k}: {v}")
    return L


def get(msg, f, default=None):
    for k, v in msg or []:
        if k == f:
            return v
    return default


def getall(msg, f):
    return [v for k, v in msg or [] if k == f]


def varints(b):
    out, n, shift = [], 0, 0
    for x in b:
        n |= (x & 0x7F) << shift
        if x & 0x80:
            shift += 7
        else:
            out.append(n); n = shift = 0
    return out


# =====================================================================  SDP rendering
SETUP = {1: "active", 2: "passive", 3: "actpass"}   # guess, consistent with DTLS roles on the wire
CAND_PROTO = {1: ("udp", ""), 2: ("tcp", " tcptype passive"), 3: ("ssltcp", " ; TLS fallback")}
MEDIA = {1: "audio", 2: "video"}


def render(desc, role, cand_field, codec_field, ext_field, dc_field):
    L = []; add = L.append
    add("v=0")
    add(f"o=- 0 2 IN IP4 127.0.0.1        ; {role}")
    add("s=-")
    add("t=0 0")
    add("a=group:BUNDLE 0 1 2             ; assumed - single transport for everything")
    add("a=msid-semantic: WMS")

    tr, ice = get(desc, 1, []), get(desc, 2, [])
    fp = get(tr, 1, [])
    transport = [
        f"a=ice-ufrag:{get(ice, 3)}",
        f"a=ice-pwd:{get(ice, 4)}",
        f"a=fingerprint:{get(fp, 1)} {get(fp, 2)}",
        f"a=setup:{SETUP.get(get(tr, 2), '?')}            ; proto value {get(tr, 2)} (mapping guessed)",
    ]
    cands = []
    for i, c in enumerate(getall(desc, cand_field) if cand_field else []):
        proto, extra = CAND_PROTO.get(get(c, 1), ("?", ""))
        cands.append(f"a=candidate:{i+1} {get(c, 5, 1)} {proto} {get(c, 4)} "
                     f"{get(c, 2)} {get(c, 3)} typ host{extra}")
    if cands:
        cands.append("a=ice-lite                      ; implied: host cands only, server sends no checks")

    codecs, exts = getall(desc, codec_field), getall(desc, ext_field)
    for mid, kind in ((0, 1), (1, 2)):
        cs = [c for c in codecs if get(c, 3) == kind]
        if not cs:
            continue
        add(f"m={MEDIA[kind]} 9 UDP/TLS/RTP/SAVPF " + " ".join(str(get(c, 1)) for c in cs))
        add("c=IN IP4 0.0.0.0")
        L.extend(transport); L.extend(cands)
        add(f"a=mid:{mid}")
        for e in exts:
            if get(e, 3) != kind:
                continue
            uri = get(e, 2)
            if get(e, 4) == 2:
                uri = "urn:ietf:params:rtp-hdrext:encrypt " + uri
            add(f"a=extmap:{get(e, 1)} {uri}")
        add("a=sendrecv"); add("a=rtcp-mux")
        if kind == 2:
            add("a=rtcp-rsize")
        for c in cs:
            pt, name, clock, ch = get(c, 1), get(c, 2), get(c, 4), get(c, 5)
            add(f"a=rtpmap:{pt} {name}/{clock}" + (f"/{ch}" if kind == 1 and ch and ch > 1 else ""))
            params = [(v if k == "" else f"{k}={v}")
                      for p in getall(c, 6) for k, v in [(get(p, 1, ""), get(p, 2, ""))]]
            if params:
                add(f"a=fmtp:{pt} " + ";".join(params))
            notes = []
            if get(c, 7) is not None:
                notes.append(f"flag 7={get(c, 7)} (2nd codec set - screenshare/alt profile?)")
            if get(c, 8) is not None or get(c, 9) is not None:
                notes.append("fields 8/9 present (probably rtcp-fb set)")
            if notes:
                add(f"; pt {pt}: " + "; ".join(notes))
        add("")

    dcs = getall(desc, dc_field)
    if dcs:
        add("m=application 9 UDP/DTLS/SCTP webrtc-datachannel")
        add("c=IN IP4 0.0.0.0")
        L.extend(transport)
        add("a=mid:2")
        add("a=sctp-port:5000                ; assumed")
        add("; data channels (pre-negotiated, not an SDP concept - listed for reading):")
        for d in dcs:
            attrs = []
            for f, label in ((3, "stream-id"), (5, "maxPacketLifeTime?ms"), (6, "maxRetransmits?"),
                             (2, "f2"), (4, "f4")):
                if get(d, f) is not None:
                    attrs.append(f"{label}={get(d, f)}")
            add(f";   {str(get(d, 1)):<20} " + " ".join(attrs))
        add("")
    return L


def extras(desc, known):
    out = []
    for k, v in desc:
        if k in known:
            continue
        if isinstance(v, bytes):
            out.append(f"; field {k}: bytes {v.hex()}  (as packed varints: {varints(v)})")
        elif isinstance(v, list):
            flat = ", ".join(f"{kk}={vv!r}" for kk, vv in v if not isinstance(vv, list))
            nested = "  [nested]" if any(isinstance(vv, list) for _, vv in v) else ""
            out.append(f"; field {k}: {{{flat}}}{nested}")
        else:
            out.append(f"; field {k}: {v!r}")
    return out


def offer_from_request(msg):
    inner = get(msg, 1)
    if isinstance(inner, list) and isinstance(get(inner, 3), list):
        return get(inner, 3)
    return get(msg, 3) if isinstance(get(msg, 3), list) else msg


def sdp_offer(req_msg, header=""):
    offer = offer_from_request(req_msg)
    L = [f"; ===== CLIENT OFFER {header}====="]
    L += render(offer, "Chrome offer via Meet JS", None, 3, 4, 17)
    L += ["; --- offer fields with no SDP equivalent ---"] + extras(offer, {1, 2, 3, 4, 17})
    return "\n".join(L) + "\n", offer


def sdp_answer(resp_msg, header=""):
    ans = get(resp_msg, 2, [])
    L = [f"; ===== SERVER ANSWER {header}({get(resp_msg, 1)}) ====="]
    L += render(ans, "Meet SFU answer", 3, 4, 5, 12)
    L += ["; --- answer fields with no SDP equivalent ---"] + extras(ans, {1, 2, 3, 4, 5, 12})
    return "\n".join(L) + "\n", ans


# =====================================================================  main
def write(path, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    return path


def process(idx, req_chunks, resp_chunks, outdir, prefix, meta=""):
    written, ufrags = [], []
    req_msg, req_raw = body_to_message(req_chunks)
    resp_msg, resp_raw = body_to_message(resp_chunks)
    tag = f"{prefix}-{idx:02d}"
    if req_msg:
        text, offer = sdp_offer(req_msg, meta)
        ufrags.append(get(get(offer, 2, []), 3))
        written += [write(os.path.join(outdir, f"{tag}-offer.sdp.txt"), text),
                    write(os.path.join(outdir, f"{tag}-offer.pb.txt"), "\n".join(fmt_pb(req_msg)) + "\n"),
                    write(os.path.join(outdir, f"{tag}-offer.bin"), req_raw)]
    else:
        print(f"  [{idx}] could not decode request body ({sum(map(len, req_chunks))} bytes)")
    if resp_msg:
        text, ans = sdp_answer(resp_msg, meta)
        ufrags.append(get(get(ans, 2, []), 3))
        written += [write(os.path.join(outdir, f"{tag}-answer.sdp.txt"), text),
                    write(os.path.join(outdir, f"{tag}-answer.pb.txt"), "\n".join(fmt_pb(resp_msg)) + "\n"),
                    write(os.path.join(outdir, f"{tag}-answer.bin"), resp_raw)]
        print(f"  server ufrag {ufrags[-1]}  candidates:")
        for c in getall(ans, 3):
            print(f"      {CAND_PROTO.get(get(c, 1), ('?',))[0]:<6} {get(c, 2)}:{get(c, 3)}  prio {get(c, 4)}")
    else:
        print(f"  [{idx}] could not decode response body ({sum(map(len, resp_chunks))} bytes)")
    return written, ufrags


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?", help="pcap/pcapng with decryptable TLS")
    ap.add_argument("--keylog", help="SSLKEYLOGFILE (not needed if secrets are embedded)")
    ap.add_argument("-o", "--outdir", help="output directory (default: <pcap>_meet_sdp)")
    ap.add_argument("--tshark", help="path to tshark")
    ap.add_argument("--bodies", nargs=2, metavar=("REQ", "RESP"),
                    help="skip tshark: decode exported request/response bodies (raw, gzip or base64)")
    a = ap.parse_args()

    if a.bodies:
        outdir = a.outdir or "meet_sdp_out"
        os.makedirs(outdir, exist_ok=True)
        req, resp = (open(p, "rb").read() for p in a.bodies)
        written, _ = process(1, [req], [resp], outdir, "bodies")
    else:
        if not a.pcap:
            ap.error("pcap required (or use --bodies)")
        tshark = find_tshark(a.tshark)
        outdir = a.outdir or os.path.splitext(a.pcap)[0] + "_meet_sdp"
        os.makedirs(outdir, exist_ok=True)
        prefix = os.path.splitext(os.path.basename(a.pcap))[0]
        sessions = extract_bodies(tshark, a.pcap, a.keylog)
        print(f"Found {len(sessions)} CreateMediaSession call(s)")
        written, all_ufrags = [], []
        for i, s in enumerate(sessions, 1):
            meta = (f"(tcp.stream {s['tcp_stream']}, h2 stream {s['sid']}, "
                    f"req frame {s['req_frame']}, resp frame {s['resp_frame']}) ")
            print(f"[{i}] t={s['time']:.3f}s  {meta}")
            w, uf = process(i, s["req_chunks"], s["resp_chunks"], outdir, prefix, meta)
            written += w; all_ufrags += uf
        checks = stun_checks(tshark, a.pcap, a.keylog, all_ufrags)
        if checks.strip():
            rows = []
            for ln in checks.strip().splitlines():
                col = ln.split("\t")
                types = col[9].split(",") if len(col) > 9 else []
                col = col[:9] + ["yes" if ("0x0025" in types or "37" in types) else ""]
                rows.append("\t".join(col))
            lines = ["frame\ttime\tsrc\tudp\ttcp\tdst\tudp\ttcp\tusername\tuse-candidate"] + rows
            written.append(write(os.path.join(outdir, f"{prefix}-ice-checks.tsv"), "\n".join(lines) + "\n"))
            first_check = checks.strip().splitlines()[0].split("\t")
            print(f"First ICE check: frame {first_check[0]} at t={float(first_check[1]):.3f}s "
                  f"-> {first_check[5]}:{first_check[6] or first_check[7]}  "
                  f"({len(lines) - 1} checks total)")

    print("Written:")
    for p in written:
        print("  " + p)


if __name__ == "__main__":
    main()
