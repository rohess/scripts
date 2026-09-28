#!/usr/bin/env python3
"""
teams-extract-sdp.py - pull the MS Teams SDP offer/answer out of a TLS-decrypted capture.

Teams does not exchange SDP over one WebSocket. The two halves travel separately:
  offer   HTTP/2 POST to the conversation service (.../conv/<id> via api.flightproxy.skype.com),
          JSON body, SDP in callInvitation.mediaContent.blob
  answer  Trouter WebSocket callback "POST .../call/acceptance/" (socket.io-style "3:::{...}"
          frame). Its "body" is base64(gzip(JSON)), SDP in callAcceptance.mediaContent.blob
Offer and answer are paired via mediaContent.mediaLegId.

Pipeline
  1. tshark finds HTTP/2 streams whose body mentions "mediaContent" (or whose path looks like
     a conversation / call-controller request) and reassembles the bodies
  2. tshark dumps WebSocket payloads; the socket.io prefix is stripped and "body" is decoded
     (plain JSON, base64, gzip - detected automatically)
  3. every JSON string starting with "v=0" is exported as SDP, exactly as sent (CRLF kept)
  4. a per-mid summary shows SDP direction vs. the mediaDescriptions override vs. the answer
  5. bonus: STUN checks using the negotiated ICE ufrags are listed, i.e. the media flow

Requirements
  Python 3.8+, Wireshark/tshark 3.x or 4.x.
  TLS must be decryptable: pass --keylog, or use a pcapng with embedded secrets
  (editcap --inject-secrets tls,keys.log in.pcapng out.pcapng).

Usage
  python3 teams-extract-sdp.py capture.pcapng --keylog sslkeys.log
  python3 teams-extract-sdp.py capture.pcapng -o outdir
  python3 teams-extract-sdp.py --bodies join.json trouter-frame.txt   # skip tshark

The decoded signalling JSON is written next to the SDP. It contains the meeting URL,
passcode and participant IDs - review before sharing.
"""
import argparse
import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zlib

BODY_MARK = "mediaContent"
PATH_HINTS = ("/conv/", "cpconv", "/cc/v1/")
SOCKETIO_PREFIX = re.compile(r"^\d+:[^:]*:[^:]*:")
CALLBACK_RE = re.compile(r"/callAgent/[^/]+/([0-9a-f]{8})/(.+?)/?$")
OFFER_KEYS = ("callInvitation", "offer", "mediaOffer")
ANSWER_KEYS = ("callAcceptance", "mediaAnswer", "answer")


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


def endpoint(layers, side):
    ip = layers.get("ip") or layers.get("ipv6") or {}
    tcp = layers.get("tcp", {})
    addr = first(ip.get(f"ip.{side}") or ip.get(f"ipv6.{side}"))
    return f"{addr}:{first(tcp.get(f'tcp.{side}port'))}"


def http2_bodies(tshark, pcap, keylog):
    """Yield (meta, body_bytes) for every HTTP/2 body on streams that may carry SDP."""
    # pass 1: which TCP streams are interesting at all (cheap)
    flt = " or ".join([f'http2.body.reassembled.data contains "{BODY_MARK}"',
                       f'http2.data.data contains "{BODY_MARK}"'] +
                      [f'http2.request.full_uri contains "{h}"' for h in PATH_HINTS])
    out = run_tshark(tshark, pcap, keylog, ["-2", "-Y", flt, "-T", "fields", "-e", "tcp.stream"])
    tcp_streams = sorted({int(x) for line in out.split() for x in line.split(",") if x.strip()})
    if not tcp_streams:
        return

    # pass 2: full JSON of all HTTP/2 frames on those TCP streams
    # tshark 4.6 requires commas in sets; -J (not -j) keeps the http2 child nodes
    flt = "http2 and tcp.stream in {" + ",".join(map(str, tcp_streams)) + "}"
    out = run_tshark(tshark, pcap, keylog,
                     ["-2", "-Y", flt, "-T", "json", "-J", "frame ip ipv6 tcp http2"])
    packets = json.loads(out or "[]")

    uris, client = {}, {}   # (tcp_stream, sid) -> uri / client port
    pieces = {}             # (tcp_stream, sid, sport) -> [(frame, meta, bytes, complete)]
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        fr = layers.get("frame", {})
        tcp = layers.get("tcp", {})
        tcp_stream = int(first(tcp.get("tcp.stream", -1)))
        sport = int(first(tcp.get("tcp.srcport", 0)))
        meta = dict(frame=int(first(fr.get("frame.number", 0))),
                    time=float(first(fr.get("frame.time_relative", 0))),
                    src=endpoint(layers, "src"), dst=endpoint(layers, "dst"))
        for h2 in walk(layers.get("http2", {})):
            if "http2.streamid" not in h2:
                continue
            key = (tcp_stream, int(first(h2["http2.streamid"])))
            ftype = str(first(h2.get("http2.type", "")))
            if "http2.request.full_uri" in h2:
                uris.setdefault(key, first(h2["http2.request.full_uri"]))
            if ftype == "1":                    # first HEADERS on a stream comes from the client
                client.setdefault(key, sport)
            if ftype != "0":
                continue
            full = [d for n in walk(h2) for d in as_list(n.get("http2.body.reassembled.data"))]
            data = [d for n in walk(h2) for d in as_list(n.get("http2.data.data"))]
            lst = pieces.setdefault(key + (sport,), [])
            for d in full:
                lst.append((meta, hex_to_bytes(d), True))
            if not full:
                for d in data:
                    lst.append((meta, hex_to_bytes(d), False))

    for (tcp_stream, sid, sport), lst in pieces.items():
        key = (tcp_stream, sid)
        is_req = client.get(key, None) == sport if key in client else sport != 443
        base = dict(transport="http2", tcp_stream=tcp_stream, sid=sid,
                    uri=uris.get(key, "?"), direction="request" if is_req else "response")
        # complete bodies as tshark reassembled them, plus the concatenation of the fragments
        # (covers captures where http2 body reassembly is off or incomplete)
        for meta, b, complete in lst:
            yield {**base, **meta}, b
        frags = [b for _, b, complete in lst if not complete]
        if len(frags) > 1:
            meta = [m for m, _, c in lst if not c][-1]
            yield {**base, **meta}, b"".join(frags)


def websocket_messages(tshark, pcap, keylog):
    """Yield (meta, payload_bytes) for every WebSocket payload (unmasked, raw bytes).
    The raw bytes matter: -e websocket.payload.text re-escapes backslashes."""
    out = run_tshark(tshark, pcap, keylog, [
        "-Y", "websocket.payload", "-T", "fields", "-E", "separator=\t",
        "-e", "frame.number", "-e", "frame.time_relative", "-e", "ip.src", "-e", "tcp.srcport",
        "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tcp.stream", "-e", "websocket.payload"])
    for line in out.splitlines():
        col = line.split("\t")
        if len(col) < 8 or not col[7]:
            continue
        meta = dict(transport="websocket", frame=int(col[0]), time=float(col[1]),
                    src=f"{col[2]}:{col[3]}", dst=f"{col[4]}:{col[5]}", tcp_stream=int(col[6]))
        for h in col[7].split(","):
            try:
                yield meta, hex_to_bytes(h)
            except ValueError:
                continue


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
B64_RE = re.compile(r"^[A-Za-z0-9+/_\-=\s]+$")


def gunzip(b):
    try:
        return gzip.decompress(b)
    except (OSError, EOFError, zlib.error):
        return zlib.decompressobj(31).decompress(b)   # tolerate trailing junk


def decode_any(data, depth=0):
    """bytes/str -> parsed JSON, unwrapping socket.io prefix, base64 and gzip as needed."""
    if depth > 4:
        return None
    if isinstance(data, bytes):
        if data[:2] == b"\x1f\x8b":
            try:
                return decode_any(gunzip(data), depth + 1)
            except (OSError, EOFError, zlib.error):
                return None
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
    s = SOCKETIO_PREFIX.sub("", data.strip(), count=1)
    if s[:1] in ("{", "["):
        try:
            return json.loads(s)
        except ValueError:
            return None
    if len(s) > 16 and B64_RE.match(s):
        s = re.sub(r"\s", "", s)
        s += "=" * (-len(s) % 4)
        try:
            raw = base64.urlsafe_b64decode(s) if ("-" in s or "_" in s) else base64.b64decode(s)
        except (binascii.Error, ValueError):
            return None
        return decode_any(raw, depth + 1)
    return None


def find_sdps(obj, path=(), depth=0):
    """Yield (json_path, sdp, parent_dict, root) for every SDP string; decodes nested
    JSON / base64 / gzip strings (e.g. the Trouter "body")."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v.lstrip().startswith("v=0"):
                yield path + (k,), v, obj, None
            else:
                yield from find_sdps(v, path + (k,), depth)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from find_sdps(v, path + (i,), depth)
    elif isinstance(obj, str) and len(obj) > 40 and depth < 3:
        inner = decode_any(obj)
        if isinstance(inner, (dict, list)):
            for p, sdp, parent, root in find_sdps(inner, path + ("<decoded>",), depth + 1):
                yield p, sdp, parent, root if root is not None else inner


def role_of(path):
    keys = [k for k in path if isinstance(k, str)]
    for k in reversed(keys):
        if k in OFFER_KEYS:
            return "offer"
        if k in ANSWER_KEYS:
            return "answer"
    return "sdp"


def dig(d, *keys):
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def extract(meta, payload):
    """Return list of SDP records found in one HTTP body / WebSocket message."""
    obj = decode_any(payload)
    if obj is None:
        return []
    recs = []
    envelope = obj if isinstance(obj, dict) else {}
    cb = CALLBACK_RE.search(str(envelope.get("url", "")))
    for path, sdp, parent, root in find_sdps(obj):
        recs.append(dict(
            meta,
            role=role_of(path),
            json_path=".".join(str(p) for p in path),
            sdp=sdp,
            content_type=parent.get("contentType"),
            media_leg=parent.get("mediaLegId"),
            media_descriptions=dig(parent, "mediaDescriptions", "descriptions") or [],
            callback=cb.group(2) if cb else None,
            method=envelope.get("method"),
            chain_id=dig(envelope, "headers", "X-Microsoft-Skype-Chain-ID"),
            body=root if root is not None else obj))
    return recs


# =====================================================================  SDP summary
def parse_sdp(sdp):
    """-> (session_lines, [section dict])"""
    sess, secs = [], []
    for line in sdp.replace("\r\n", "\n").split("\n"):
        if line.startswith("m="):
            f = line[2:].split()
            secs.append(dict(kind=f[0], port=f[1], proto=f[2], pts=f[3:], lines=[]))
        elif secs:
            secs[-1]["lines"].append(line)
        elif line:
            sess.append(line)
    for s in secs:
        attrs = {}
        for l in s["lines"]:
            if l.startswith("a="):
                k, _, v = l[2:].partition(":")
                attrs.setdefault(k, []).append(v)
        s["attrs"] = attrs
        s["mid"] = first(attrs.get("mid", ["?"]))
        s["label"] = first(attrs.get("label", ["-"]))
        s["dir"] = next((d for d in ("sendrecv", "sendonly", "recvonly", "inactive") if d in attrs),
                        "(sendrecv)")
        s["rtpmap"] = {v.split()[0]: v.split()[1] for v in attrs.get("rtpmap", []) if " " in v}
        s["fmtp"] = {v.split()[0]: v.split(" ", 1)[1] for v in attrs.get("fmtp", []) if " " in v}
        s["ssrc_range"] = first(attrs.get("x-ssrc-range", ["-"]))
    return sess, secs


def attr_all(secs, name):
    return sorted({v for s in secs for v in s["attrs"].get(name, [])})


def codec_summary(sec, verbose):
    out = []
    for pt in sec["pts"]:
        name = sec["rtpmap"].get(pt, "?").split("/")[0]
        fmtp = sec["fmtp"].get(pt, "")
        if name.lower() == "rtx":
            m = re.search(r"apt=(\d+)", fmtp)
            name = f"rtx>{m.group(1)}" if m else name
        elif name.upper() == "H264":
            m = re.search(r"profile-level-id=(\w+)", fmtp, re.I)
            name += f"({m.group(1)})" if m else ""
        out.append(f"{pt}:{name}" if verbose else name)
    if not verbose:   # collapse repeats, keep order
        out = list(dict.fromkeys(out))
    return " ".join(out)


def describe(rec):
    sess, secs = parse_sdp(rec["sdp"])
    lines = [l for l in rec["sdp"].replace("\r\n", "\n").split("\n") if l]
    cands = attr_all(secs, "candidate")
    return (f"{len(secs)} m-lines, {len(lines)} lines, ice-ufrag={','.join(attr_all(secs, 'ice-ufrag'))} "
            f"setup={','.join(attr_all(secs, 'setup'))} candidates={len(cands)}"), secs, cands


def mid_table(offer, answer):
    o_secs = parse_sdp(offer["sdp"])[1] if offer else []
    a_secs = {s["mid"]: s for s in parse_sdp(answer["sdp"])[1]} if answer else {}
    eff = {str(d.get("mid")): d.get("direction") for d in (offer or {}).get("media_descriptions", [])}
    rows = [("mid", "kind", "label", "offer dir", "effective", "answer dir",
             "answer codecs", "offer ssrc-range", "answer ssrc-range")]
    mids = [s["mid"] for s in o_secs] + [m for m in a_secs if m not in {s["mid"] for s in o_secs}]
    o_by = {s["mid"]: s for s in o_secs}
    for mid in mids:
        o, a = o_by.get(mid), a_secs.get(mid)
        ref = o or a
        e = eff.get(mid)
        rows.append((mid, ref["kind"], ref["label"],
                     o["dir"] if o else "-",
                     (e + (" *" if o and e != o["dir"] else "")) if e else "-",
                     a["dir"] if a else "-",
                     codec_summary(a, True) if a else "-",
                     o["ssrc_range"] if o else "-",
                     a["ssrc_range"] if a else "-"))
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return ["  " + "  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]


def notes(rec):
    out = []
    bad = [l for l in rec["sdp"].split("\r\n") if re.match(r"a=extmap:\d+ \w+:\\\\", l)]
    if bad:
        uris = sorted({l.split(" ", 1)[1] for l in bad})
        out.append(f"{len(bad)} extmap lines use backslash URIs as sent on the wire: " + ", ".join(uris))
    if "mediaParameter" in json.dumps(rec["body"]):
        for d in walk(rec["body"]):
            mp = d.get("mediaParameter")
            if isinstance(mp, str):
                out.append(f"mediaParameter: {mp}")
    return out


# =====================================================================  main
def write(path, data, raw=False):
    if isinstance(data, bytes):
        with open(path, "wb") as f:
            f.write(data)
    else:
        with open(path, "w", newline="" if raw else None) as f:
            f.write(data)
    return path


def collect(messages):
    """Dedupe SDPs (same SDP may show up as reassembled body and as fragment concat)."""
    seen, recs = set(), []
    for meta, payload in messages:
        for r in extract(meta, payload):
            key = (r["role"], hashlib.sha1(r["sdp"].encode()).hexdigest())
            if key in seen:
                continue
            seen.add(key)
            recs.append(r)
    return sorted(recs, key=lambda r: (r.get("time", 0), r.get("frame", 0)))


def group_calls(recs):
    """Pair offers and answers by mediaLegId; fall back to order of appearance."""
    calls, by_leg = [], {}
    for r in recs:
        leg, role = r.get("media_leg"), r["role"]
        if leg:
            call = by_leg.get(leg)
        elif role == "answer":
            call = next((c for c in reversed(calls) if "offer" in c and "answer" not in c), None)
        else:
            call = calls[-1] if calls else None
        if call is None or (role != "sdp" and role in call):   # renegotiation starts a new leg
            call = {"other": []}
            calls.append(call)
            if leg:
                by_leg[leg] = call
        if role == "sdp":
            call["other"].append(r)
        else:
            call[role] = r
    return calls


def where(r):
    if r["transport"] == "http2":
        return (f'frame {r["frame"]} t={r["time"]:.3f}s  HTTP/2 {r["direction"]} '
                f'(tcp.stream {r["tcp_stream"]}, h2 stream {r["sid"]})  {r["src"]} -> {r["dst"]}\n'
                f'      {r["uri"]}')
    if r["transport"] == "websocket":
        cb = f' {r["method"] or ""} callback "{r["callback"]}"' if r["callback"] else ""
        return (f'frame {r["frame"]} t={r["time"]:.3f}s  WebSocket{cb} '
                f'(tcp.stream {r["tcp_stream"]})  {r["src"]} -> {r["dst"]}')
    return f'file {r["file"]}'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?", help="pcap/pcapng with decryptable TLS")
    ap.add_argument("-k", "--keylog", help="SSLKEYLOGFILE (not needed if secrets are embedded)")
    ap.add_argument("-o", "--outdir", help="output directory (default: <pcap>_teams_sdp)")
    ap.add_argument("--tshark", help="path to tshark")
    ap.add_argument("--bodies", nargs="+", metavar="FILE",
                    help="skip tshark: decode exported bodies / Trouter frames (JSON, base64, gzip)")
    ap.add_argument("-p", "--print", action="store_true", help="also print full SDPs")
    a = ap.parse_args()

    if a.bodies:
        outdir = a.outdir or "teams_sdp_out"
        prefix = "bodies"
        recs = collect(({"transport": "file", "file": p, "time": i}, open(p, "rb").read())
                       for i, p in enumerate(a.bodies))
    else:
        if not a.pcap:
            ap.error("pcap required (or use --bodies)")
        tshark = find_tshark(a.tshark)
        outdir = a.outdir or os.path.splitext(a.pcap)[0] + "_teams_sdp"
        prefix = os.path.splitext(os.path.basename(a.pcap))[0]
        msgs = list(http2_bodies(tshark, a.pcap, a.keylog))
        msgs += list(websocket_messages(tshark, a.pcap, a.keylog))
        recs = collect(msgs)
    if not recs:
        sys.exit("No SDP found. Is TLS decrypted (--keylog / embedded secrets)? "
                 "Statistics > Protocol Hierarchy should show http2 and websocket under tls.")
    os.makedirs(outdir, exist_ok=True)

    calls = group_calls(recs)
    print(f"Found {len(recs)} SDP(s) in {len(calls)} call leg(s)")
    written, ufrags = [], []
    for i, call in enumerate(calls, 1):
        items = [(k, call[k]) for k in ("offer", "answer") if k in call]
        items += [(f"sdp{k}", r) for k, r in enumerate(call["other"], 1)]
        leg = next((r["media_leg"] for _, r in items if r.get("media_leg")), "-")
        print(f"\n[{i}] mediaLegId {leg}")
        for kind, r in items:
            name = f"{prefix}-{i:02d}-{kind}"
            summary, secs, cands = describe(r)
            print(f'  {r["role"].upper():<6} {where(r)}')
            print(f'      {r["json_path"]}  ({r["content_type"] or "?"})')
            print(f"      {summary}")
            for c in cands:
                print(f"        a=candidate:{c}")
            if r.get("chain_id"):
                print(f'      chain-id {r["chain_id"]}')
            for nt in notes(r):
                print(f"      note: {nt}")
            ufrags += attr_all(secs, "ice-ufrag")
            written += [write(os.path.join(outdir, f"{name}.sdp"), r["sdp"], raw=True),
                        write(os.path.join(outdir, f"{name}.json"),
                              json.dumps(r["body"], indent=2, ensure_ascii=False) + "\n")]
            if a.print:
                print(r["sdp"].replace("\r\n", "\n"))
        if "offer" in call or "answer" in call:
            print("  per-mid (effective = offer's mediaContent.mediaDescriptions, * = overrides SDP):")
            print("\n".join(mid_table(call.get("offer"), call.get("answer"))))
            o, ans = call.get("offer"), call.get("answer")
            if o and ans and o["transport"] != "file":
                print(f'  offer -> answer: {(ans["time"] - o["time"]) * 1000:.0f} ms')

    if not a.bodies:
        checks = stun_checks(tshark, a.pcap, a.keylog, list(dict.fromkeys(ufrags)))
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
            print(f"\nFirst ICE check: frame {first_check[0]} at t={float(first_check[1]):.3f}s "
                  f"-> {first_check[5]}:{first_check[6] or first_check[7]}  "
                  f"({len(lines) - 1} checks total)")

    print("Written:")
    for p in written:
        print("  " + p)


if __name__ == "__main__":
    main()
