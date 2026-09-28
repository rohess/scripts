#!/usr/bin/env python3
"""
zoom-extract-sdp.py - pull the Zoom web client offers/answers out of a TLS-decrypted capture.

The Zoom web client has no SIP and no REST SDP exchange. All signalling runs over WebSockets
to one "RWG" host (e.g. zoomiad20624799165rwg.iad.zoom.us). Every binary WebSocket message
holds one or more Zoom records (batching):
  record := type:u8 len:u16be body[len]
    0x01/0x02  session handshake (C->S / S->C), opaque
    0x03/0x04  ping / pong: u32 counter, u32 timestamp, 00, 37 f9, channel, 00
    0x05       data: u16 seq, 00, 37 f9, channel, flags, subtype (0x0d JSON, 0x0a ACK), ...
               JSON {"evt": <int>, "seq": <int>, "body": {...}} follows the sub-header
The browser builds two RTCPeerConnections, negotiated on two different WebSockets:
  PC-DC     data channel only  /webclient/<meeting>       evt 24321 offer.sdp / evt 24322 answer.sdp
  PC-AUDIO  audio              /wc/media/<meeting>?mode=16  evt 32769 body.type 1 offer / 2 answer,
                                                            SDP gzip+base64 ("sdpEncoding": 1)
The media server is ICE-lite; the offers carry no candidates, so the server learns the
client address as peer-reflexive from the ICE checks.

Pipeline
  1. tshark finds the WebSocket upgrades to /webclient/ and /wc/media/ and dumps the unmasked
     payload of every WebSocket message on those connections
  2. the Zoom records are parsed; JSON is located after the sub-header and decoded
  3. every SDP is exported exactly as sent (CRLF kept), gzip+base64 decoded where needed
  4. per-mid summary of offer vs. answer, plus notes on Zoom-specific SDP
  5. STUN checks using the negotiated ICE ufrags are mapped to their PeerConnection
  6. setup timeline: WebSockets, ICE servers, offers/answers, ICE, DTLS, meeting join, first RTP

Requirements
  Python 3.7+, Wireshark/tshark 3.x or 4.x.
  TLS must be decryptable: pass --keylog, or use a pcapng with embedded secrets
  (editcap --inject-secrets tls,keys.log in.pcapng out.pcapng).

Usage
  python3 zoom-extract-sdp.py capture.pcapng --keylog sslkeys.log
  python3 zoom-extract-sdp.py capture.pcapng -o outdir
  python3 zoom-extract-sdp.py --payloads msg1.bin msg2.bin   # skip tshark

The decoded messages (NDJSON) contain the meeting number, passcode, auth tokens, display
name, ICE passwords and TURN credentials - review before sharing.
"""
import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import zlib
from urllib.parse import parse_qs, urlsplit

WS_PATHS = ("/webclient/", "/wc/media/")
MAGIC = b"\x37\xf9"
REC_TYPES = {1: "handshake", 2: "handshake-reply", 3: "ping", 4: "pong", 5: "data"}
CHANNELS = {0x09: "main", 0x0a: "media"}

EVT_NAMES = {
    0: "welcome", 4098: "join response", 4128: "meeting token", 4130: "media SDK config",
    4167: "client telemetry", 4301: "join meeting", 4305: "request", 4309: "request",
    4310: "token response", 7938: "meeting state", 8015: "meeting state", 8024: "meeting state",
    8193: "audio mute", 8203: "audio on", 12307: "video on", 12308: "see myself",
    24321: "PC-DC offer", 24322: "PC-DC answer", 32769: "PC-AUDIO negotiation",
    32770: "link quality", 32776: "SSRC announcement",
}
AUDIO_TYPES = {1: "offer", 2: "answer", 3: "confirm", 4: "pre-offer"}


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
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if res.returncode != 0:
        msg = f"tshark failed:\n  {' '.join(cmd)}\n{res.stderr.strip()}"
        if fatal:
            sys.exit(msg)
        print("  (optional step skipped) " + msg.splitlines()[-1])
        return ""
    return res.stdout


def fields(tshark, pcap, keylog, flt, names, fatal=True):
    """-> list of dicts, one per packet; multiple occurrences joined by ','."""
    args = ["-Y", flt, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
            "-E", "aggregator=,"]
    for n in names:
        args += ["-e", n]
    out = run_tshark(tshark, pcap, keylog, args, fatal)
    rows = []
    for line in out.splitlines():
        col = (line.split("\t") + [""] * len(names))[:len(names)]
        rows.append(dict(zip(names, col)))
    return rows


def ws_connections(tshark, pcap, keylog):
    """tcp.stream -> dict(path, mode, host, upgrade_frame, upgrade_time, client_port)."""
    flt = " or ".join(f'http.request.uri contains "{p}"' for p in WS_PATHS) + " or http.response.code == 101"
    conns = {}
    for r in fields(tshark, pcap, keylog, flt,
                    ["frame.number", "frame.time_relative", "tcp.stream", "tcp.srcport",
                     "http.host", "http.request.uri", "http.response.code", "http.request.method"]):
        st = int(r["tcp.stream"])
        if r["http.request.method"]:   # responses carry http.request.uri too
            u = urlsplit(r["http.request.uri"])
            if not any(u.path.startswith(p) for p in WS_PATHS):
                continue
            conns[st] = dict(path=u.path, mode=(parse_qs(u.query).get("mode") or [None])[0],
                             host=r["http.host"], uri=r["http.request.uri"],
                             client_port=r["tcp.srcport"], request_frame=int(r["frame.number"]))
        elif r["http.response.code"] == "101" and st in conns:
            conns[st].update(upgrade_frame=int(r["frame.number"]),
                             upgrade_time=float(r["frame.time_relative"]))
    return conns


def ws_messages(tshark, pcap, keylog, conns):
    """Yield (meta, opcode, payload bytes) for every WebSocket message on the Zoom connections."""
    flt = "websocket and tcp.stream in {" + ",".join(map(str, sorted(conns))) + "}"
    for r in fields(tshark, pcap, keylog, flt,
                    ["frame.number", "frame.time_relative", "tcp.stream", "ip.src", "tcp.srcport",
                     "ip.dst", "tcp.dstport", "websocket.opcode", "websocket.payload"]):
        st = int(r["tcp.stream"])
        c = conns[st]
        meta = dict(frame=int(r["frame.number"]), time=float(r["frame.time_relative"]), tcp_stream=st,
                    src=f'{r["ip.src"]}:{r["tcp.srcport"]}', dst=f'{r["ip.dst"]}:{r["tcp.dstport"]}',
                    dir="C->S" if r["tcp.srcport"] == c["client_port"] else "S->C",
                    ws=c["path"].rstrip("/").split("/")[-2] if c["path"].startswith("/wc/") else "webclient",
                    mode=c["mode"])
        for op, h in zip(r["websocket.opcode"].split(","), r["websocket.payload"].split(",")):
            if h:
                yield meta, int(op), bytes.fromhex(h.replace(":", ""))


def stun_packets(tshark, pcap, keylog):
    rows = []
    for r in fields(tshark, pcap, keylog, "stun",
                    ["frame.number", "frame.time_relative", "ip.src", "udp.srcport", "tcp.srcport",
                     "ip.dst", "udp.dstport", "tcp.dstport", "stun.type", "stun.id",
                     "stun.att.username", "stun.att.ipv4", "stun.att.port", "stun.att.type"],
                    fatal=False):
        rows.append(dict(
            frame=int(r["frame.number"]), time=float(r["frame.time_relative"]),
            src=r["ip.src"], dst=r["ip.dst"],
            sport=r["udp.srcport"] or r["tcp.srcport"], dport=r["udp.dstport"] or r["tcp.dstport"],
            proto="udp" if r["udp.srcport"] else "tcp", type=r["stun.type"].split(",")[0],
            id=r["stun.id"].split(",")[0], username=r["stun.att.username"].split(",")[0],
            mapped_ip=r["stun.att.ipv4"].split(",")[0], mapped_port=r["stun.att.port"].split(",")[0],
            use_candidate=any(t in ("0x0025", "37") for t in r["stun.att.type"].split(","))))
    return rows


def media_packets(tshark, pcap, keylog, ports):
    """DTLS and SRTP/SRTCP on the ICE 5-tuples (client ports), for the timeline. RTP vs. RTCP
    is told apart by the first bytes (RFC 7983 / RFC 5761), since Wireshark shows Zoom's
    SRTP/SRTCP as plain data or misdissects it."""
    flt = "udp.port in {" + ",".join(sorted(ports)) + "}"
    names = ["frame.number", "frame.time_relative", "udp.srcport", "udp.dstport"]
    rows = []
    for r in fields(tshark, pcap, keylog, flt + " and dtls",
                    names + ["dtls.record.content_type", "dtls.handshake.type"], fatal=False):
        rows.append(dict(frame=int(r["frame.number"]), time=float(r["frame.time_relative"]),
                         sport=r["udp.srcport"], dport=r["udp.dstport"], kind="dtls",
                         content=r["dtls.record.content_type"].split(","),
                         hs=r["dtls.handshake.type"].split(",")))
    for r in fields(tshark, pcap, keylog, flt + " and not dtls and not stun",
                    names + ["udp.payload"], fatal=False):
        b = bytes.fromhex(r["udp.payload"][:6].replace(":", "") or "00")
        if len(b) < 2 or not 128 <= b[0] <= 191:
            continue
        rows.append(dict(frame=int(r["frame.number"]), time=float(r["frame.time_relative"]),
                         sport=r["udp.srcport"], dport=r["udp.dstport"],
                         kind="rtcp" if 192 <= b[1] <= 223 else "rtp", content=[], hs=[]))
    return sorted(rows, key=lambda p: p["frame"])


# =====================================================================  Zoom records
def zoom_records(payload):
    """Split a WebSocket payload into Zoom records. Returns [] if it isn't Zoom framing."""
    recs, p = [], 0
    while p + 3 <= len(payload):
        rtype, ln = payload[p], int.from_bytes(payload[p + 1:p + 3], "big")
        body = payload[p:p + 3 + ln]
        if rtype not in REC_TYPES or len(body) != 3 + ln:
            return []
        rec = dict(type=REC_TYPES[rtype], raw=body)
        if rtype in (3, 4) and body[12:14] == MAGIC:
            rec.update(counter=int.from_bytes(body[3:7], "big"), ts=int.from_bytes(body[7:11], "big"),
                       channel=CHANNELS.get(body[14], hex(body[14])))
        elif rtype == 5 and body[6:8] == MAGIC:
            rec.update(rec_seq=int.from_bytes(body[3:5], "big"),
                       channel=CHANNELS.get(body[8], hex(body[8])))
            i = body.find(b'{"', 9)
            if i >= 0:
                try:
                    rec["json"], _ = json.JSONDecoder().raw_decode(body[i:].decode("utf-8", "replace"))
                except ValueError:
                    pass
            elif body[10:11] == b"\x0a" or body[16:17] == b"\x0a":
                rec["type"] = "ack"
        recs.append(rec)
        p += 3 + ln
    return recs


def decode_sdp(s, encoding=None):
    """SDP string as sent, or gzip+base64 ("sdpEncoding": 1) -> (sdp, how)."""
    if not isinstance(s, str) or not s:
        return None, None
    if s.startswith("v=0"):
        return s, "plain"
    if encoding == 1 or s.startswith("H4sI"):
        try:
            raw = zlib.decompressobj(31).decompress(base64.b64decode(s + "=" * (-len(s) % 4)))
            return raw.decode("utf-8"), "gzip+base64"
        except (ValueError, zlib.error, UnicodeDecodeError):
            return None, None
    return None, None


def sdp_messages(msgs):
    """Yield one record per SDP-carrying message (and PC-AUDIO pre-offer/confirm)."""
    for m in msgs:
        j = m.get("json")
        if not isinstance(j, dict):
            continue
        evt = j.get("evt")
        if evt in (24321, 24322):
            role = "offer" if evt == 24321 else "answer"
            env = j.get(role) if isinstance(j.get(role), dict) else {}
            sdp, how = decode_sdp(env.get("sdp"))
            yield dict(m, pc="dc", role=role, sdp=sdp, how=how, key=("dc", m["tcp_stream"]),
                       path=f"{role}.sdp", env=env)
        elif evt == 32769 and isinstance(j.get("body"), dict):
            b = j["body"]
            role = AUDIO_TYPES.get(b.get("type"), f'type {b.get("type")}')
            sdp, how = decode_sdp(b.get("sdp"), b.get("sdpEncoding"))
            yield dict(m, pc="audio", role=role, sdp=sdp, how=how,
                       key=("audio", m["tcp_stream"], b.get("peerID"), b.get("msgID")),
                       path="body.sdp", env=b)


def negotiations(recs):
    """Group into offer/answer exchanges. PC-DC by order on its WebSocket, PC-AUDIO by
    connection + peerID + msgID (the answer has no sessionID/confID)."""
    out = []
    for r in recs:
        opening = r["role"] in ("pre-offer", "offer")
        cur = next((n for n in reversed(out) if n["key"] == r["key"] and r["role"] not in n
                    and not (opening and "answer" in n)), None)
        if cur is None:
            cur = dict(key=r["key"], pc=r["pc"])
            out.append(cur)
        cur[r["role"]] = r
    return out


# =====================================================================  SDP summary
def first(v):
    return v[0] if isinstance(v, list) else v


def parse_sdp(sdp):
    """-> (session attrs dict, [section dict], session lines)"""
    sess, secs, slines = {}, [], []
    for line in sdp.replace("\r\n", "\n").split("\n"):
        if line.startswith("m="):
            f = line[2:].split()
            secs.append(dict(kind=f[0], port=f[1], proto=f[2], pts=f[3:], lines=[]))
        elif secs:
            secs[-1]["lines"].append(line)
        else:
            slines.append(line)
            if line.startswith("a="):
                k, _, v = line[2:].partition(":")
                sess.setdefault(k, []).append(v)
    for s in secs:
        attrs = {}
        for l in s["lines"]:
            if l.startswith("a="):
                k, _, v = l[2:].partition(":")
                attrs.setdefault(k, []).append(v)
        s["attrs"] = attrs
        s["mid"] = first(attrs.get("mid", ["?"]))
        s["dir"] = next((d for d in ("sendrecv", "sendonly", "recvonly", "inactive") if d in attrs),
                        "(sendrecv)")
        s["rtpmap"] = {v.split()[0]: v.split()[1] for v in attrs.get("rtpmap", []) if " " in v}
        s["fmtp"] = {v.split()[0]: v.split(" ", 1)[1] for v in attrs.get("fmtp", []) if " " in v}
        s["ssrcs"] = list(dict.fromkeys(v.split()[0] for v in attrs.get("ssrc", [])))
        s["fb"] = {v.split()[0]: [] for v in attrs.get("rtcp-fb", [])}
        for v in attrs.get("rtcp-fb", []):
            s["fb"][v.split()[0]].append(v.split(" ", 1)[1] if " " in v else "")
    return sess, secs, slines


def attr_all(secs, name, sess=None):
    vals = list((sess or {}).get(name, [])) + [v for s in secs for v in s["attrs"].get(name, [])]
    return list(dict.fromkeys(vals))


def codec_summary(sec):
    if sec["kind"] == "application":
        return " ".join(sec["pts"])
    out = []
    for pt in sec["pts"]:
        name = sec["rtpmap"].get(pt, "?").split("/")[0]
        fmtp = sec["fmtp"].get(pt, "")
        if name.lower() in ("rtx", "red") and re.match(r"^\d+/\d+", fmtp):
            name += ">" + fmtp.split("/")[0]
        elif name.lower() == "rtx":
            m = re.search(r"apt=(\d+)", fmtp)
            name = f"rtx>{m.group(1)}" if m else name
        out.append(f"{pt}:{name}")
    return " ".join(out)


def opus_profile(sec):
    """Short Opus fmtp summary, e.g. 'fb 96k no-fec'."""
    pt = next((p for p in sec["pts"] if sec["rtpmap"].get(p, "").lower().startswith("opus")), None)
    if pt is None:
        return "-"
    f = dict(kv.split("=", 1) for kv in sec["fmtp"].get(pt, "").split(";") if "=" in kv)
    parts = []
    rate = f.get("maxplaybackrate")
    if rate:
        parts.append({"8000": "nb", "16000": "wb", "24000": "swb", "48000": "fb"}.get(rate, rate))
    if f.get("maxaveragebitrate"):
        parts.append(f'{int(f["maxaveragebitrate"]) // 1000}k')
    if f.get("stereo") == "1":
        parts.append("stereo")
    parts.append("fec" if f.get("useinbandfec") == "1" else "no-fec")
    return " ".join(parts)


def describe(sdp):
    sess, secs, _ = parse_sdp(sdp)
    lines = [l for l in sdp.replace("\r\n", "\n").split("\n") if l]
    cands = attr_all(secs, "candidate", sess)
    return (f"{len(secs)} m-lines, {len(lines)} lines, "
            f"ice-ufrag={','.join(attr_all(secs, 'ice-ufrag', sess))} "
            f"setup={','.join(attr_all(secs, 'setup', sess))}"
            f"{' ice-lite' if 'ice-lite' in sess else ''} candidates={len(cands)}"), sess, secs, cands


def mid_table(offer_sdp, answer_sdp):
    o_secs = parse_sdp(offer_sdp)[1] if offer_sdp else []
    a_by = {s["mid"]: s for s in parse_sdp(answer_sdp)[1]} if answer_sdp else {}
    o_by = {s["mid"]: s for s in o_secs}
    rows = [("mid", "kind", "offer dir", "offer ssrc", "offer opus", "answer dir", "answer ssrc",
             "answer codecs")]
    for mid in [s["mid"] for s in o_secs] + [m for m in a_by if m not in o_by]:
        o, a = o_by.get(mid), a_by.get(mid)
        rows.append((mid, (o or a)["kind"], o["dir"] if o else "-",
                     ",".join(o["ssrcs"]) or "-" if o else "-", opus_profile(o) if o else "-",
                     a["dir"] if a else "-", ",".join(a["ssrcs"]) or "-" if a else "-",
                     codec_summary(a) if a else "-"))
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return ["  " + "  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]


def notes(offer_sdp, answer_sdp):
    out = []
    if offer_sdp:
        sess, secs, slines = parse_sdp(offer_sdp)
        if not attr_all(secs, "candidate", sess):
            out.append("offer has no candidates (and none are trickled) - the ICE-lite server learns "
                       "the client address as peer-reflexive from the ICE checks")
        t = next((l[2:] for l in slines if l.startswith("t=")), "0 0")
        if t.split()[0] != "0":
            out.append(f"offer has t={t} (browsers send t=0 0) - SDP munged by the Zoom client")
    if answer_sdp:
        sess, secs, _ = parse_sdp(answer_sdp)
        cands = attr_all(secs, "candidate", sess)
        if "ice-lite" in sess:
            out.append("answer is ice-lite - the browser is ICE controlling")
        same = {}
        for c in cands:
            f = c.split()
            if len(f) > 5:
                same.setdefault((f[4], f[5]), set()).add(f[2].lower())
        dual = [f"{ip}:{port}" for (ip, port), p in same.items() if len(p) > 1 and ":" not in ip]
        if dual:
            out.append("answer uses the same port on UDP and TCP: " + ", ".join(dual))
        if offer_sdp:
            o_by = {s["mid"]: s for s in parse_sdp(offer_sdp)[1]}
            kept = {v.split("/")[0].lower() for s in secs for v in s["rtpmap"].values()}
            dropped = {v.split("/")[0] for o in o_by.values() for v in o["rtpmap"].values()
                       if v.split("/")[0].lower() not in kept}
            added = set()
            for s in secs:
                o = o_by.get(s["mid"])
                if not o or s["kind"] == "application":
                    continue
                for pt, fbs in s["fb"].items():
                    for fb in fbs:
                        if fb not in o["fb"].get(pt, []):
                            added.add(f"{s['rtpmap'].get(pt, pt).split('/')[0]} {fb}")
            if dropped:
                out.append("answer drops codecs: " + ", ".join(sorted(dropped)))
            if added:
                out.append("answer adds rtcp-fb not in the offer: " + ", ".join(sorted(added)))
    return out


# =====================================================================  main
def write(path, data, raw=False):
    with open(path, "w", newline="" if raw else None) as f:
        f.write(data)
    return path


def where(r):
    if "file" in r:
        return f'file {r["file"]}'
    ws = r["ws"] + (f' mode={r["mode"]}' if r.get("mode") else "")
    return (f'frame {r["frame"]} t={r["time"]:.3f}s  evt {r["json"].get("evt")} {r["dir"]} '
            f'({ws}, tcp.stream {r["tcp_stream"]})  {r["src"]} -> {r["dst"]}')


def ms(a, b):
    return f"{(b - a) * 1000:.0f} ms"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?", help="pcap/pcapng with decryptable TLS")
    ap.add_argument("-k", "--keylog", help="SSLKEYLOGFILE (not needed if secrets are embedded)")
    ap.add_argument("-o", "--outdir", help="output directory (default: <pcap>_zoom_sdp)")
    ap.add_argument("--tshark", help="path to tshark")
    ap.add_argument("--payloads", nargs="+", metavar="FILE",
                    help="skip tshark: decode unmasked WebSocket binary payloads exported from "
                         "Wireshark (File > Export Packet Bytes) or DevTools")
    ap.add_argument("-p", "--print", action="store_true", help="also print full SDPs")
    a = ap.parse_args()

    stun, media, conns, tshark = [], [], {}, None
    msgs = []
    if a.payloads:
        outdir = a.outdir or "zoom_sdp_out"
        prefix = "payloads"
        for i, p in enumerate(a.payloads):
            meta = dict(file=p, frame=i, time=float(i), tcp_stream=0, dir="?", ws="?", mode=None)
            for rec in zoom_records(open(p, "rb").read()):
                msgs.append(dict(meta, **rec))
    else:
        if not a.pcap:
            ap.error("pcap required (or use --payloads)")
        tshark = find_tshark(a.tshark)
        outdir = a.outdir or os.path.splitext(a.pcap)[0] + "_zoom_sdp"
        prefix = os.path.splitext(os.path.basename(a.pcap))[0]
        conns = ws_connections(tshark, a.pcap, a.keylog)
        if not conns:
            sys.exit("No Zoom WebSocket (/webclient/, /wc/media/) found. Is TLS decrypted "
                     "(--keylog / embedded secrets)? Statistics > Protocol Hierarchy should show "
                     "http and websocket under tls.")
        for meta, op, payload in ws_messages(tshark, a.pcap, a.keylog, conns):
            if op == 1:
                try:
                    msgs.append(dict(meta, type="text", json=json.loads(payload.decode("utf-8"))))
                except (UnicodeDecodeError, ValueError):
                    pass
            elif op == 2:
                for rec in zoom_records(payload):
                    msgs.append(dict(meta, **rec))
        stun = stun_packets(tshark, a.pcap, a.keylog)

    recs = list(sdp_messages(msgs))
    if not any(r["sdp"] for r in recs):
        sys.exit("No Zoom SDP found (evt 24321/24322/32769). Is TLS decrypted "
                 "(--keylog / embedded secrets)?")
    os.makedirs(outdir, exist_ok=True)
    written = []

    if conns:
        print("Zoom WebSockets")
        for st, c in sorted(conns.items()):
            n = sum(1 for m in msgs if m["tcp_stream"] == st)
            print(f'  tcp.stream {st:<4} {c["host"]}  {c["path"]}'
                  + (f'?mode={c["mode"]}' if c["mode"] else "")
                  + (f'  101 in frame {c["upgrade_frame"]} t={c["upgrade_time"]:.3f}s' if "upgrade_frame" in c else "")
                  + f"  {n} message(s)")

    # ICE servers from evt 4130 (early) and evt 4098 (join response)
    for m in msgs:
        body = (m.get("json") or {}).get("body") if isinstance(m.get("json"), dict) else None
        cfg = body.get("mediasdkConfig") if isinstance(body, dict) else None
        if isinstance(cfg, dict) and (cfg.get("iceServers") or cfg.get("stunServers")):
            print(f'\nICE servers in frame {m["frame"]} (evt {m["json"]["evt"]} '
                  f'{EVT_NAMES.get(m["json"]["evt"], "")})')
            for s in cfg.get("iceServers") or []:
                print(f'  {s.get("urls")}  username {s.get("username")}  credential {s.get("credential")}')
            for s in cfg.get("stunServers") or []:
                print(f"  {s.get('urls') if isinstance(s, dict) else s}")

    negs = negotiations(recs)
    print(f"\nFound {sum(1 for r in recs if r['sdp'])} SDP(s) in {len(negs)} negotiation(s)")
    ufrag_pc = {}
    for i, n in enumerate(negs, 1):
        pc = "PC-DC (data channel)" if n["pc"] == "dc" else "PC-AUDIO"
        key = n["key"]
        ids = f"  peerID {key[2]} msgID {key[3]}" if n["pc"] == "audio" else ""
        print(f"\n[{i}] {pc}{ids}")
        for role in ("pre-offer", "offer", "answer", "confirm"):
            r = n.get(role)
            if not r:
                continue
            print(f"  {role.upper():<9} {where(r)}")
            extra = {k: v for k, v in r["env"].items() if k not in ("sdp", "featureToggles")}
            if extra:
                print("      " + r["path"].split(".")[0] + ": " + "  ".join(f"{k}={v}" for k, v in extra.items()))
            if isinstance(r["env"].get("featureToggles"), list):
                ft = [f'{t.get("key")}={json.dumps(t.get("value"))}' for t in r["env"]["featureToggles"]
                      if isinstance(t, dict)]
                print("      featureToggles: " + ", ".join(ft))
            if not r["sdp"]:
                continue
            summary, sess, secs, cands = describe(r["sdp"])
            print(f"      {r['path']} ({r['how']})  {summary}")
            for c in cands:
                print(f"        a=candidate:{c}")
            for u in attr_all(secs, "ice-ufrag", sess):
                ufrag_pc[u] = (i, n["pc"])
            name = f"{prefix}-{i:02d}-{n['pc']}-{role}.sdp"
            written.append(write(os.path.join(outdir, name), r["sdp"], raw=True))
            if a.print:
                print(r["sdp"].replace("\r\n", "\n"))
        o, ans = n.get("offer"), n.get("answer")
        if o and ans and "file" not in o:
            print(f"  offer -> answer: {ms(o['time'], ans['time'])}")
        if (o and o["sdp"]) or (ans and ans["sdp"]):
            osdp, asdp = o and o["sdp"], ans and ans["sdp"]
            print("  per-mid:")
            print("\n".join(mid_table(osdp, asdp)))
            for nt in notes(osdp, asdp):
                print(f"  note: {nt}")

    fps = {}
    for n in negs:
        if n.get("answer") and n["answer"]["sdp"]:
            s, secs, _ = parse_sdp(n["answer"]["sdp"])
            for fp in attr_all(secs, "fingerprint", s):
                fps.setdefault(fp, set()).add(n["pc"])
    for fp, pcs in fps.items():
        if len(pcs) > 1:
            print(f"\nnote: both PeerConnections' answers use the same DTLS fingerprint {fp[:30]}... "
                  "(one server certificate)")

    ssrcs = [m for m in msgs if isinstance(m.get("json"), dict) and m["json"].get("evt") == 32776]
    if ssrcs:
        b = ssrcs[0]["json"].get("body", {})
        print(f"\nSSRC announcement (evt 32776, frame {ssrcs[0]['frame']}): "
              + ", ".join(f"{k}={v} (0x{int(v):08X})" for k, v in b.items() if isinstance(v, int)))

    # decoded Zoom messages
    lines = []
    for m in msgs:
        row = {k: m.get(k) for k in ("frame", "time", "dir", "tcp_stream", "ws", "mode", "type",
                                     "channel", "rec_seq", "counter", "ts") if m.get(k) is not None}
        if isinstance(m.get("json"), dict):
            row["evt"] = m["json"].get("evt")
            row["name"] = EVT_NAMES.get(row["evt"])
            row["json"] = m["json"]
        lines.append(json.dumps(row, ensure_ascii=False))
    written.append(write(os.path.join(outdir, f"{prefix}-messages.ndjson"), "\n".join(lines) + "\n"))

    # ICE checks with the negotiated ufrags -> PC
    def check_pc(username):
        for u, v in ufrag_pc.items():
            if u in username.split(":"):
                return v
        return None

    checks = [dict(c, pc=check_pc(c["username"])) for c in stun if c["type"] == "0x0001" and c["username"]]
    checks = [c for c in checks if c["pc"]]
    first_ice = {}
    if checks:
        resp = {r["id"]: r for r in stun if r["type"] == "0x0101"}
        tsv = ["frame\ttime\tpc\tinitiator\tproto\tsrc\tsport\tdst\tdport\tusername\tuse-candidate\t"
               "resp_frame\tmapped"]
        print("\nICE checks")
        for (i, pc) in dict.fromkeys(c["pc"] for c in checks):
            cs = [c for c in checks if c["pc"] == (i, pc)]
            # the offerer's ufrag comes second in client->server checks
            offer_ufrag = next((u for u, v in ufrag_pc.items() if v == (i, pc)
                                and negs[i - 1].get("offer") and negs[i - 1]["offer"]["sdp"]
                                and u in negs[i - 1]["offer"]["sdp"]), None)
            label = "PC-DC" if pc == "dc" else "PC-AUDIO"
            print(f"  [{i}] {label}")
            for dst in dict.fromkeys((c["src"], c["sport"], c["dst"], c["dport"], c["proto"]) for c in cs):
                d = [c for c in cs if (c["src"], c["sport"], c["dst"], c["dport"], c["proto"]) == dst]
                client = offer_ufrag is None or d[0]["username"].endswith(":" + offer_ufrag)
                ok = [resp[c["id"]] for c in d if c["id"] in resp]
                mapped = sorted({f'{r["mapped_ip"]}:{r["mapped_port"]}' for r in ok if r["mapped_ip"]})
                nom = sum(1 for c in d if c["use_candidate"])
                who = "client" if client else "server"
                print(f"    {who} {dst[0]}:{dst[1]} -> {dst[2]}:{dst[3]}/{dst[4]}  {len(d)} request(s), "
                      f"{len(ok)} answered, {nom} USE-CANDIDATE"
                      + (f", mapped (prflx) {', '.join(mapped)}" if mapped and client else "")
                      + f"  first frame {d[0]['frame']} t={d[0]['time']:.3f}s")
                if client and ok:
                    first_ice.setdefault((i, pc), (d[0], ok[0]))
                for c in d:
                    rsp = resp.get(c["id"])
                    tsv.append("\t".join(map(str, (
                        c["frame"], f'{c["time"]:.6f}', label, who, c["proto"], c["src"], c["sport"],
                        c["dst"], c["dport"], c["username"], "yes" if c["use_candidate"] else "",
                        rsp["frame"] if rsp else "",
                        f'{rsp["mapped_ip"]}:{rsp["mapped_port"]}' if rsp and rsp["mapped_ip"] else ""))))
            if not any(not (offer_ufrag is None or c["username"].endswith(":" + offer_ufrag)) for c in cs):
                print("    no server-initiated checks (pure ICE-lite behaviour)")
        written.append(write(os.path.join(outdir, f"{prefix}-ice-checks.tsv"), "\n".join(tsv) + "\n"))
        if tshark and first_ice:
            media = media_packets(tshark, a.pcap, a.keylog, {q["sport"] for q, _ in first_ice.values()})

    # setup timeline
    tl = []
    for st, c in sorted(conns.items()):
        if "upgrade_time" in c:
            tl.append((c["upgrade_time"], c["upgrade_frame"], "WebSocket 101 " + c["path"].rsplit("/", 2)[-2]
                       + (f' mode={c["mode"]}' if c["mode"] else "")))
    seen = set()
    for m in msgs:
        j = m.get("json")
        evt = j.get("evt") if isinstance(j, dict) else None
        if evt in (4130, 4301, 4098, 32776, 8203) and evt not in seen and "file" not in m:
            seen.add(evt)
            tl.append((m["time"], m["frame"], f"evt {evt} {EVT_NAMES.get(evt, '')}"))
    for i, n in enumerate(negs, 1):
        label = "PC-DC" if n["pc"] == "dc" else "PC-AUDIO"
        for role in ("offer", "answer"):
            r = n.get(role)
            if r and "file" not in r:
                tl.append((r["time"], r["frame"], f"{label} {role}"))
        fi = first_ice.get((i, n["pc"]))
        if fi:
            q, rsp = fi
            tl.append((q["time"], q["frame"], f"{label} first ICE check -> {q['dst']}:{q['dport']}"))
            tl.append((rsp["time"], rsp["frame"], f"{label} ICE success, mapped "
                       f"{rsp['mapped_ip']}:{rsp['mapped_port']}"))
            ports = {q["sport"], q["dport"]}
            flow = [p for p in media if {p["sport"], p["dport"]} == ports]
            ch = next((p for p in flow if "1" in p["hs"]), None)
            app = next((p for p in flow if p["kind"] == "dtls" and "23" in p["content"]), None)
            rtcp = next((p for p in flow if p["kind"] in ("srtcp", "rtcp")), None)
            rtp = next((p for p in flow if p["kind"] == "rtp"), None)
            ccs = next((p for p in flow if p["sport"] == q["dport"] and "20" in p["content"]), None)
            if ch:
                tl.append((ch["time"], ch["frame"], f"{label} DTLS ClientHello"))
            if ccs:
                tl.append((ccs["time"], ccs["frame"], f"{label} DTLS server ChangeCipherSpec/Finished"))
            if app:
                tl.append((app["time"], app["frame"], f"{label} first DTLS application data (SCTP)"))
            for p, what in ((rtcp, "SRTCP"), (rtp, "SRTP")):
                if p:
                    d = "C->S" if p["sport"] == q["sport"] else "S->C"
                    tl.append((p["time"], p["frame"], f"{label} first {what} ({d})"))
    if len(tl) > 1:
        tl.sort(key=lambda x: (x[0], x[1]))
        print("\nSetup timeline")
        t0 = tl[0][0]
        for t, f, what in tl:
            print(f"  t={t:8.3f}s  +{(t - t0) * 1000:7.0f} ms  frame {f:<6} {what}")
        join = next((x for x in tl if x[2].startswith("evt 4301")), None)
        warm = [x for x in tl if "ICE success" in x[2] or "ChangeCipherSpec" in x[2]]
        if join and warm:
            print(f"  media pre-warmed: ICE/DTLS up {join[0] - warm[-1][0]:.1f} s before the meeting "
                  "join request (evt 4301)")

    print("\nWritten:")
    for p in written:
        print("  " + p)


if __name__ == "__main__":
    main()
