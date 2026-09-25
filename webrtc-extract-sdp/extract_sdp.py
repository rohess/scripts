#!/usr/bin/env python3
"""
extract_sdp.py - pull WebRTC SDP offers/answers out of a TLS-decrypted pcap(ng).

Works with keys embedded in the pcapng (DSB) or an external SSLKEYLOGFILE.
Vendor-agnostic: it doesn't rely on a particular JSON field name or on how
Wireshark dissects the payload (WebSocket text, HTTP/2 DATA, JSON, raw bytes).
It walks the whole tshark dissection, decodes hex byte fields, finds JSON
objects that carry an "sdp" string, and pairs them with "type": offer/answer.

Usage:
    python3 extract_sdp.py capture.pcapng
    python3 extract_sdp.py capture.pcapng -o sdp_out -p
    python3 extract_sdp.py capture.pcapng -k keylog.txt -Y 'ip.addr==1.2.3.4'

Requires tshark (Wireshark 3.x or newer) on PATH.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

SDP_TYPES = {"offer", "answer", "pranswer", "rollback"}
HEX_COLON = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){20,}$")
HEX_PLAIN = re.compile(r"^(?:[0-9a-f]{2}){20,}$")
SDP_FIELD = re.compile(r'"sdp"\s*:\s*"((?:[^"\\]|\\.)*)"')
TYPE_FIELD = re.compile(r'"type"\s*:\s*"(offer|answer|pranswer)"')
DEFAULT_FILTER = "websocket || http2 || http || json"


def run_tshark(pcap, keylog, dfilter):
    cmd = ["tshark", "-r", pcap, "-T", "json", "-x", "--no-duplicate-keys",
           "-Y", dfilter]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"tshark failed:\n{p.stderr}")
    return json.loads(p.stdout or "[]")


def walk_strings(node):
    """Yield every string value in the dissection tree."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for x in node:
            yield from walk_strings(x)
    elif isinstance(node, dict):
        for v in node.values():
            yield from walk_strings(v)


def text_views(s):
    """The string itself, plus its decoded form if it is a hex byte dump."""
    yield s
    t = s.lower()
    if HEX_COLON.match(t):
        raw = bytes.fromhex(t.replace(":", ""))
    elif HEX_PLAIN.match(t):
        raw = bytes.fromhex(t)
    else:
        return
    yield raw.decode("utf-8", "replace")


def find_sdps(obj, parent_type=None):
    """Recursively find {"sdp": "..."} in parsed JSON; handles double-encoded JSON."""
    if isinstance(obj, dict):
        t = obj.get("type")
        t = t if isinstance(t, str) and t in SDP_TYPES else parent_type
        sdp = obj.get("sdp")
        if isinstance(sdp, str) and "v=0" in sdp:
            yield t, sdp
        for k, v in obj.items():
            if k != "sdp":
                yield from find_sdps(v, t)
    elif isinstance(obj, list):
        for v in obj:
            yield from find_sdps(v, parent_type)
    elif isinstance(obj, str) and obj.lstrip()[:1] in ("{", "["):
        try:
            yield from find_sdps(json.loads(obj), parent_type)
        except ValueError:
            pass


def extract_from_text(text):
    if "v=0" not in text:
        return
    # A dissected, already-unescaped SDP on its own (e.g. json.value.string)
    if text.lstrip().startswith("v=0") and "\n" in text:
        yield None, text
    # Complete JSON objects embedded anywhere in the text
    dec = json.JSONDecoder()
    found = False
    i = text.find("{")
    while i != -1:
        try:
            obj, end = dec.raw_decode(text, i)
        except ValueError:
            i = text.find("{", i + 1)
            continue
        for t, sdp in find_sdps(obj):
            found = True
            yield t, sdp
        i = text.find("{", end)
    # Fallback for truncated/odd JSON: regex out "sdp":"..." and unescape it
    if not found:
        m_type = TYPE_FIELD.search(text)
        for m in SDP_FIELD.finditer(text):
            try:
                sdp = json.loads(f'"{m.group(1)}"')
            except ValueError:
                continue
            if "v=0" in sdp:
                yield (m_type.group(1) if m_type else None), sdp


def first(d, *keys):
    for k in keys:
        v = d.get(k)
        if v is not None:
            return v[0] if isinstance(v, list) else v
    return None


def summarize(sdp):
    lines = sdp.splitlines()
    media = [l[2:].split()[0] for l in lines if l.startswith("m=")]
    ufrag = next((l.split(":", 1)[1] for l in lines if l.startswith("a=ice-ufrag:")), "-")
    cands = sum(1 for l in lines if l.startswith("a=candidate:"))
    return f"m={','.join(media) or '-'} ice-ufrag={ufrag} candidates={cands} lines={len(lines)}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("-o", "--outdir", default="sdp_out")
    ap.add_argument("-k", "--keylog", help="SSLKEYLOGFILE (not needed if keys are embedded)")
    ap.add_argument("-Y", "--filter", default=DEFAULT_FILTER,
                    help=f"display filter to narrow the search (default: {DEFAULT_FILTER})")
    ap.add_argument("-p", "--print", action="store_true", help="also print full SDPs")
    args = ap.parse_args()

    packets = run_tshark(args.pcap, args.keylog, args.filter)
    os.makedirs(args.outdir, exist_ok=True)

    results = {}  # (frame, sdp_hash) -> record; keeps the best-typed copy
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        fr = layers.get("frame", {})
        ip = layers.get("ip") or layers.get("ipv6") or {}
        l4 = layers.get("tcp") or layers.get("udp") or {}
        meta = {
            "frame": int(first(fr, "frame.number") or 0),
            "time": float(first(fr, "frame.time_relative") or 0.0),
            "src": f'{first(ip, "ip.src", "ipv6.src")}:{first(l4, "tcp.srcport", "udp.srcport")}',
            "dst": f'{first(ip, "ip.dst", "ipv6.dst")}:{first(l4, "tcp.dstport", "udp.dstport")}',
        }
        for s in walk_strings(layers):
            if len(s) < 40:
                continue
            for view in text_views(s):
                for sdp_type, sdp in extract_from_text(view):
                    norm = sdp.replace("\r\n", "\n").strip() + "\n"
                    key = (meta["frame"], hashlib.sha1(norm.encode()).hexdigest())
                    if key not in results or (results[key]["type"] is None and sdp_type):
                        results[key] = {**meta, "type": sdp_type, "sdp": norm}

    if not results:
        print("No SDP found. Check Statistics > Protocol Hierarchy that TLS is decrypted,")
        print("or widen the search with -Y 'tls'.")
        return

    for n, r in enumerate(sorted(results.values(), key=lambda r: r["frame"]), 1):
        t = r["type"] or "unknown"
        fname = os.path.join(args.outdir, f'{n:02d}_frame{r["frame"]}_{t}.sdp')
        with open(fname, "w", newline="\n") as f:
            f.write(r["sdp"])
        print(f'#{n:<3} frame {r["frame"]:<7} t={r["time"]:9.3f}s  {t:<8} '
              f'{r["src"]} -> {r["dst"]}  {summarize(r["sdp"])}')
        print(f"      -> {fname}")
        if args.print:
            print(r["sdp"])


if __name__ == "__main__":
    main()
