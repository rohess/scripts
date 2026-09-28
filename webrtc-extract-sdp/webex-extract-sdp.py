#!/usr/bin/env python3
"""
webex-extract-sdp.py - pull the Cisco Webex ROAP offer/answer out of a TLS-decrypted capture.

The Webex web client sends SDP inside ROAP messages (Webex's offer/answer envelope), which
travel in Locus REST calls over HTTP/2. The ROAP message is a JSON document encoded as a
string inside the JSON body:
  join    POST /locus/api/v1/loci/call         localMedias[0].localSdp = TURN_DISCOVERY_REQUEST
          200 response                         mediaConnections[0].remoteSdp = TURN_DISCOVERY_RESPONSE
                                               (TURN URLs and credentials in roapMessage.headers)
  offer   PUT  /locus/api/v1/loci/<locus>/participant/<id>/media
                                               localMedias[0].localSdp = OFFER, sdps[0] = SDP
          200 response ("includeAnswerInHttpResponse")
                                               mediaConnections[0].remoteSdp = ANSWER
                                               mediaConnections[0].localSdp  = echo of the OFFER
The join and offer bodies also carry the client's media reachability report
(clientMediaPreferences.reachability), measured with STUN against the clusters that
Calliope (POST /calliope/api/discovery/v1/clusters) returned.

Pipeline
  1. tshark finds HTTP/2 streams that carry ROAP / Locus / Calliope bodies and reassembles them
  2. localSdp / remoteSdp strings are JSON-decoded a second time -> roapMessage
  3. every SDP in roapMessage.sdps is exported exactly as sent (CRLF kept)
  4. per-mid summary of offer vs. answer, plus notes on Webex-specific SDP
  5. reachability: the client's report, and the STUN probes (no USERNAME) matched to clusters
  6. STUN checks using the negotiated ICE ufrags are listed, i.e. the media flow

Requirements
  Python 3.8+, Wireshark/tshark 3.x or 4.x.
  TLS must be decryptable: pass --keylog, or use a pcapng with embedded secrets
  (editcap --inject-secrets tls,keys.log in.pcapng out.pcapng).

Usage
  python3 webex-extract-sdp.py capture.pcapng --keylog sslkeys.log
  python3 webex-extract-sdp.py capture.pcapng -o outdir
  python3 webex-extract-sdp.py --bodies request.json response.json   # skip tshark

The decoded Locus JSON is written next to the SDP. It contains meeting, locus and participant
IDs, tokens, ICE passwords and TURN credentials - review before sharing.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zlib

BODY_MARKS = ("roapMessage", "localSdp", "remoteSdp", "reachability")
PATH_HINTS = ("/locus/api/v1/loci", "/calliope/api/discovery")
SDP_KEYS = ("localSdp", "remoteSdp")
PAIRS = {"OFFER": "ANSWER", "TURN_DISCOVERY_REQUEST": "TURN_DISCOVERY_RESPONSE"}
REACH_PORTS = ("5004", "9000")
ROUND_GAP = 2.0   # seconds between STUN probes that start a new reachability round


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


def decode_body(b):
    """bytes -> parsed JSON (gunzips if needed), or None."""
    if b[:2] == b"\x1f\x8b":
        try:
            b = zlib.decompressobj(31).decompress(b)   # tolerate trailing junk
        except zlib.error:
            return None
    try:
        return json.loads(b.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def http2_bodies(tshark, pcap, keylog):
    """Yield (meta, parsed_json) for every JSON body on HTTP/2 streams that may carry ROAP."""
    # pass 1: which TCP streams are interesting at all (cheap)
    flt = " or ".join([f'http2.data.data contains "{m}"' for m in BODY_MARKS] +
                      [f'http2.request.full_uri contains "{h}"' for h in PATH_HINTS])
    out = run_tshark(tshark, pcap, keylog, ["-2", "-Y", flt, "-T", "fields", "-e", "tcp.stream"])
    tcp_streams = sorted({int(x) for line in out.split() for x in line.split(",") if x.strip()})
    if not tcp_streams:
        return

    # pass 2: full JSON of all HTTP/2 frames on those TCP streams
    # tshark 4.6 requires commas in sets; -J (not -j) keeps the http2 child nodes;
    # --no-duplicate-keys keeps every http2.stream / http2.header of a frame
    flt = "http2 and tcp.stream in {" + ",".join(map(str, tcp_streams)) + "}"
    out = run_tshark(tshark, pcap, keylog,
                     ["-2", "-Y", flt, "-T", "json", "--no-duplicate-keys",
                      "-J", "frame ip ipv6 tcp http2"])
    packets = json.loads(out or "[]")

    req = {}      # (tcp_stream, sid) -> dict(method, uri, client_port)
    status = {}   # (tcp_stream, sid) -> response status
    pieces = {}   # (tcp_stream, sid, sport) -> [(meta, bytes, complete)]
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
            # -T json has no http2.headers.*; pseudo-headers are http2.header name/value pairs
            hdrs = {first(n.get("http2.header.name")): first(n.get("http2.header.value"))
                    for n in walk(h2) if "http2.header.name" in n}
            if ":method" in hdrs and key not in req:
                req[key] = dict(method=hdrs[":method"], client_port=sport,
                                uri=first(h2.get("http2.request.full_uri", hdrs.get(":path", "?"))))
            if ":status" in hdrs:
                status.setdefault(key, hdrs[":status"])
            if ftype != "0":
                continue
            lst = pieces.setdefault(key + (sport,), [])
            for n in walk(h2):
                for d in as_list(n.get("http2.body.reassembled.data")):
                    lst.append((meta, hex_to_bytes(d), True))
                for d in as_list(n.get("http2.data.data")):
                    lst.append((meta, hex_to_bytes(d), False))

    for (tcp_stream, sid, sport), lst in pieces.items():
        key = (tcp_stream, sid)
        r = req.get(key, {})
        is_req = r.get("client_port") == sport if r else sport != 443
        base = dict(transport="http2", tcp_stream=tcp_stream, sid=sid, uri=r.get("uri", "?"),
                    method=r.get("method", "?"), status=status.get(key),
                    direction="request" if is_req else "response")
        # tshark shows the decompressed body as http2.data.data in the frame that completes
        # the body; the reassembled (maybe gzip) body and the concatenated fragments are
        # fallbacks for other preference settings
        frags = [b for _, b, c in lst if not c]
        cands = [(m, b) for m, b, _ in lst] + ([(lst[-1][0], b"".join(frags))] if len(frags) > 1 else [])
        for meta, b in sorted(cands, key=lambda mb: (-len(mb[1]) if mb[1][:1] == b"{" else 0)):
            obj = decode_body(b)
            if isinstance(obj, dict):
                yield {**base, **meta}, obj
                break


def stun_packets(tshark, pcap, keylog):
    out = run_tshark(tshark, pcap, keylog, [
        "-Y", "stun", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "frame.number", "-e", "frame.time_relative", "-e", "ip.src", "-e", "udp.srcport",
        "-e", "tcp.srcport", "-e", "ip.dst", "-e", "udp.dstport", "-e", "tcp.dstport",
        "-e", "stun.type", "-e", "stun.id", "-e", "stun.att.username",
        "-e", "stun.att.ipv4", "-e", "stun.att.port"], fatal=False)
    rows = []
    names = ("frame", "time", "src", "sport_u", "sport_t", "dst", "dport_u", "dport_t",
             "type", "id", "username", "mapped_ip", "mapped_port")
    for line in out.splitlines():
        col = (line.split("\t") + [""] * len(names))[:len(names)]
        r = dict(zip(names, col))
        r["frame"], r["time"] = int(r["frame"]), float(r["time"])
        r["sport"], r["dport"] = r["sport_u"] or r["sport_t"], r["dport_u"] or r["dport_t"]
        r["proto"] = "udp" if r["sport_u"] else "tcp"
        rows.append(r)
    # attribute types need all occurrences (USE-CANDIDATE)
    out = run_tshark(tshark, pcap, keylog, [
        "-Y", "stun.att.username", "-T", "fields", "-e", "frame.number", "-e", "stun.att.type"],
        fatal=False)
    atypes = {}
    for line in out.splitlines():
        fr, _, types = line.partition("\t")
        atypes[int(fr)] = types.split(",")
    for r in rows:
        r["use_candidate"] = any(t in ("0x0025", "37") for t in atypes.get(r["frame"], []))
    return rows


# =====================================================================  ROAP
def roap_messages(meta, body):
    """Yield one record per localSdp/remoteSdp string in a Locus body (with or without ROAP)."""
    def paths(obj, path=()):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in SDP_KEYS and isinstance(v, str):
                    yield path + (k,), v
                else:
                    yield from paths(v, path + (k,))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from paths(v, path + (i,))

    for path, s in paths(body):
        try:
            env = json.loads(s)
        except ValueError:
            continue
        if not isinstance(env, dict):
            continue
        roap = env.get("roapMessage") if isinstance(env.get("roapMessage"), dict) else None
        # the client's own message comes back in the response as mediaConnections[].localSdp
        echo = meta.get("direction") == "response" and path[-1] == "localSdp"
        parent = body
        for p in path[:-1]:
            parent = parent[p]
        jpath = "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in path).lstrip(".")
        yield dict(meta, json_path=jpath, envelope=env, roap=roap,
                   echo=echo, parent=parent,
                   mtype=roap.get("messageType", "?") if roap else None,
                   seq=roap.get("seq") if roap else None,
                   sdps=[x for x in (roap or {}).get("sdps", []) if isinstance(x, str)])


def decoded_body(body):
    """Copy of body with every localSdp/remoteSdp string replaced by its parsed JSON."""
    if isinstance(body, dict):
        out = {}
        for k, v in body.items():
            if k in SDP_KEYS and isinstance(v, str):
                try:
                    v = json.loads(v)
                except ValueError:
                    pass
            out[k] = decoded_body(v)
        return out
    if isinstance(body, list):
        return [decoded_body(v) for v in body]
    return body


def turn_info(roap):
    urls, user, pwd = [], None, None
    for h in (roap or {}).get("headers", []):
        k, _, v = str(h).partition("=")
        if k == "x-cisco-turn-url":
            urls.append(v)
        elif k == "x-cisco-turn-username":
            user = v
        elif k == "x-cisco-turn-password":
            pwd = v
    return urls, user, pwd


# =====================================================================  SDP summary
def parse_sdp(sdp):
    """-> (session attrs dict, [section dict])"""
    sess, secs = {}, []
    for line in sdp.replace("\r\n", "\n").split("\n"):
        if line.startswith("m="):
            f = line[2:].split()
            secs.append(dict(kind=f[0], port=f[1], proto=f[2], pts=f[3:], lines=[]))
        elif secs:
            secs[-1]["lines"].append(line)
        elif line.startswith("a="):
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
        s["content"] = first(attrs.get("content", ["-"]))
        s["dir"] = next((d for d in ("sendrecv", "sendonly", "recvonly", "inactive") if d in attrs),
                        "(sendrecv)")
        s["tias"] = next((l[7:] for l in s["lines"] if l.startswith("b=TIAS:")), None)
        s["csi"] = ",".join(m.group(1) for v in attrs.get("jmp-source", [])
                            for m in [re.search(r"csi=(\d+)", v)] if m) or "-"
        s["rtpmap"] = {v.split()[0]: v.split()[1] for v in attrs.get("rtpmap", []) if " " in v}
        s["fmtp"] = {v.split()[0]: v.split(" ", 1)[1] for v in attrs.get("fmtp", []) if " " in v}
        s["max_msg"] = first(attrs.get("max-message-size", [None]))
    return sess, secs


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
        if name.lower() == "rtx":
            m = re.search(r"apt=(\d+)", fmtp)
            name = f"rtx>{m.group(1)}" if m else name
        elif name.upper() == "H264":
            m = re.search(r"profile-level-id=(\w+)", fmtp, re.I)
            p = re.search(r"packetization-mode=(\d)", fmtp)
            name += (f"({m.group(1)}" if m else "(") + (f",pm{p.group(1)})" if p else ")")
        out.append(f"{pt}:{name}")
    return " ".join(out)


def describe(sdp):
    sess, secs = parse_sdp(sdp)
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
    rows = [("mid", "kind", "content", "offer csi", "offer dir", "answer dir", "answer proto",
             "answer TIAS", "answer codecs")]
    for mid in [s["mid"] for s in o_secs] + [m for m in a_by if m not in o_by]:
        o, a = o_by.get(mid), a_by.get(mid)
        ref = o or a
        content = o["content"] if o and o["content"] != "-" else (a or o)["content"]
        rows.append((mid, ref["kind"], content, o["csi"] if o else "-",
                     o["dir"] if o else "-", a["dir"] if a else "-",
                     a["proto"] if a else "-", a["tias"] or "-" if a else "-",
                     codec_summary(a) if a else "-"))
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return ["  " + "  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]


def notes(offer_sdp, answer_sdp, roaps):
    out = []
    if offer_sdp:
        _, secs = parse_sdp(offer_sdp)
        cands = attr_all(secs, "candidate")
        if cands and all(" 0.0.0.0 9 " in c for c in cands):
            out.append("offer has only placeholder candidates (0.0.0.0:9) - the media server "
                       "learns the client address as peer-reflexive from the ICE checks")
        sims = attr_all(secs, "ssrc-group")
        sims = [g for g in sims if g.startswith("SIM ")]
        if sims:
            out.append("offer simulcast via ssrc-group " + "; ".join(sims))
        maxfs = [v for v in attr_all(secs, "ssrc") if "max-fs=" in v]
        if maxfs:
            caps = [v.split()[0] + " " + re.search(r"max-fs=\d+", v).group(0) for v in maxfs]
            out.append("per-SSRC frame-size caps: " + ", ".join(caps))
    if answer_sdp:
        sess, secs = parse_sdp(answer_sdp)
        cands = attr_all(secs, "candidate", sess)
        if "ice-lite" in sess:
            out.append("answer is ice-lite - the browser is ICE controlling")
        o_proto = {s["mid"]: s["proto"] for s in parse_sdp(offer_sdp)[1]} if offer_sdp else {}
        odd = sorted({f'{o_proto[s["mid"]]} -> {s["proto"]}' for s in secs
                      if s["mid"] in o_proto and s["proto"] != o_proto[s["mid"]]})
        if odd:
            out.append("answer transport profile differs from offer: " + ", ".join(odd))
        xtls = [c for c in cands if c.split()[2:3] == ["xTLS"]]
        if xtls:
            out.append(f"answer has {len(xtls)} xTLS candidate(s) - Webex-specific transport "
                       "(TLS on 443), ignored by browser ICE")
        fqdn = sorted({c.split()[4] for c in cands if len(c.split()) > 4 and
                       re.search(r"[a-z]", c.split()[4], re.I) and ":" not in c.split()[4]})
        if fqdn:
            out.append("answer has FQDN candidates: " + ", ".join(fqdn))
        found = {}
        for c in cands:
            f = c.split()
            if len(f) > 5:
                found.setdefault(f[0], set()).add(f"{f[4]}:{f[5]}/{f[2]}")
        dup = [k for k, v in found.items() if len(v) > 1]
        if dup:
            out.append("answer reuses candidate foundations for different addresses: " + ", ".join(dup))
        if offer_sdp:
            o_mm = {s["mid"]: s["max_msg"] for s in parse_sdp(offer_sdp)[1] if s["max_msg"]}
            for s in secs:
                if s["max_msg"] and o_mm.get(s["mid"]) and o_mm[s["mid"]] != s["max_msg"]:
                    out.append(f'mid {s["mid"]} max-message-size: offer {o_mm[s["mid"]]}, '
                               f'answer {s["max_msg"]}')
    hdrs = {h for r in roaps for h in (r["roap"] or {}).get("headers", [])}
    if "noOkInTransaction" in hdrs:
        out.append("noOkInTransaction - no ROAP OK follows the answer")
    return out


# =====================================================================  reachability
def calliope_clusters(bodies):
    """ip:port -> cluster from the Calliope discovery response."""
    m = {}
    for meta, body in bodies:
        cl = body.get("clusters")
        if not isinstance(cl, dict):
            continue
        for name, tests in cl.items():
            for proto, urls in (tests or {}).items():
                for u in as_list(urls):
                    hp = str(u).split(":", 1)[-1]
                    m.setdefault(hp, name)
    return m


def reachability_report(bodies):
    """(frames, report) of the last clientMediaPreferences.reachability sent."""
    frames, rep = [], None
    for meta, body in bodies:
        r = (body.get("clientMediaPreferences") or {}).get("reachability") \
            if isinstance(body.get("clientMediaPreferences"), dict) else None
        if isinstance(r, dict):
            frames.append(meta.get("frame"))
            rep = r
    return frames, rep


def reachability_probes(stun, clusters):
    """STUN binding requests without USERNAME (reachability, not ICE) -> rounds of probes."""
    reqs, resps = {}, {}
    for r in stun:
        if r["username"]:
            continue
        if r["type"] == "0x0001" and (r["dport"] in REACH_PORTS or f'{r["dst"]}:{r["dport"]}' in clusters):
            reqs.setdefault(r["id"], []).append(r)
        elif r["type"] == "0x0101":
            resps.setdefault(r["id"], r)
    probes = []
    for tid, rs in reqs.items():
        q, a = rs[0], resps.get(tid)
        probes.append(dict(frame=q["frame"], time=q["time"], sport=q["sport"], dst=q["dst"],
                           dport=q["dport"], cluster=clusters.get(f'{q["dst"]}:{q["dport"]}', "?"),
                           sent=len(rs), resp_frame=a["frame"] if a else None,
                           rtt=(a["time"] - q["time"]) * 1000 if a else None,
                           mapped=f'{a["mapped_ip"]}:{a["mapped_port"]}' if a and a["mapped_ip"] else ""))
    probes.sort(key=lambda p: p["time"])
    rounds = []
    for p in probes:
        if not rounds or p["time"] - rounds[-1][-1]["time"] > ROUND_GAP:
            rounds.append([])
        rounds[-1].append(p)
    return rounds


def reach_table(report, rounds, selected):
    tests = (report or {}).get("result", {}).get("tests", {}) or {}
    names = list(tests) + sorted({p["cluster"] for r in rounds for p in r} - set(tests))

    def ms(t):
        if not isinstance(t, dict):
            return "-"
        if str(t.get("reachable")) != "true":
            return "no"
        return f'{t.get("latencyInMilliseconds", "?")} ms'

    def best(rnd, name):
        v = [p["rtt"] for p in rnd if p["cluster"] == name and p["rtt"] is not None]
        return f"{min(v):.0f} ms" if v else "-"

    rows = [("cluster", "rep. udp", "rep. tcp", "rep. xtls")
            + tuple(f"STUN r{i}" for i in range(1, len(rounds) + 1)) + ("",)]
    for n in sorted(names, key=lambda n: min([p["rtt"] for r in rounds for p in r
                                              if p["cluster"] == n and p["rtt"] is not None] or [1e9])):
        t = tests.get(n, {})
        sel = "<- media" if selected and n.startswith(selected) else ""
        rows.append((n, ms(t.get("udp")), ms(t.get("tcp")), ms(t.get("xtls")))
                    + tuple(best(r, n) for r in rounds) + (sel,))
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return ["  " + "  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]


# =====================================================================  main
def write(path, data, raw=False):
    with open(path, "w", newline="" if raw else None) as f:
        f.write(data)
    return path


def where(r):
    if r["transport"] == "http2":
        what = (f'{r["method"]} request' if r["direction"] == "request"
                else f'{r["status"] or ""} response'.strip())
        return (f'frame {r["frame"]} t={r["time"]:.3f}s  HTTP/2 {what} '
                f'(tcp.stream {r["tcp_stream"]}, h2 stream {r["sid"]})  {r["src"]} -> {r["dst"]}\n'
                f'      {r["uri"]}')
    return f'file {r["file"]}'


def group_transactions(recs):
    """ROAP transactions by seq. Echoes are attached to the original message."""
    txs = {}
    for r in recs:
        if r["roap"] is None:
            continue
        tx = txs.setdefault(r["seq"], {"msgs": [], "echoes": []})
        (tx["echoes"] if r["echo"] else tx["msgs"]).append(r)
    return [(seq, txs[seq]) for seq in sorted(txs, key=lambda s: (s is None, s if s is not None else 0))]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?", help="pcap/pcapng with decryptable TLS")
    ap.add_argument("-k", "--keylog", help="SSLKEYLOGFILE (not needed if secrets are embedded)")
    ap.add_argument("-o", "--outdir", help="output directory (default: <pcap>_webex_sdp)")
    ap.add_argument("--tshark", help="path to tshark")
    ap.add_argument("--bodies", nargs="+", metavar="FILE",
                    help="skip tshark: decode Locus request/response bodies exported from "
                         "Wireshark or DevTools (JSON, optionally gzip)")
    ap.add_argument("-p", "--print", action="store_true", help="also print full SDPs")
    a = ap.parse_args()

    stun = []
    if a.bodies:
        outdir = a.outdir or "webex_sdp_out"
        prefix = "bodies"
        bodies = []
        for i, p in enumerate(a.bodies):
            obj = decode_body(open(p, "rb").read())
            if isinstance(obj, dict):
                d = "response" if "mediaConnections" in obj else "request"
                bodies.append((dict(transport="file", file=p, frame=i, time=float(i), direction=d), obj))
    else:
        if not a.pcap:
            ap.error("pcap required (or use --bodies)")
        tshark = find_tshark(a.tshark)
        outdir = a.outdir or os.path.splitext(a.pcap)[0] + "_webex_sdp"
        prefix = os.path.splitext(os.path.basename(a.pcap))[0]
        bodies = sorted(http2_bodies(tshark, a.pcap, a.keylog), key=lambda mb: mb[0]["frame"])
        stun = stun_packets(tshark, a.pcap, a.keylog)
    recs = [r for meta, body in bodies for r in roap_messages(meta, body)]
    if not any(r["roap"] for r in recs):
        sys.exit("No ROAP message found. Is TLS decrypted (--keylog / embedded secrets)? "
                 "Statistics > Protocol Hierarchy should show http2 under tls.")
    os.makedirs(outdir, exist_ok=True)
    written = []

    txs = group_transactions(recs)
    n = sum(len(tx["msgs"]) for _, tx in txs)
    print(f"Found {n} ROAP message(s) in {len(txs)} transaction(s)")
    ufrags, selected, offer_answer = [], None, []
    for seq, tx in txs:
        types = [m["mtype"] for m in tx["msgs"]]
        print(f"\n[seq {seq}] {' / '.join(types)}")
        offer = answer = None
        for r in tx["msgs"]:
            roap = r["roap"]
            extra = {k: v for k, v in roap.items() if k not in ("messageType", "seq", "sdps", "headers")}
            print(f'  {r["mtype"]:<23} {where(r)}')
            print(f'      {r["json_path"]}  ' + "  ".join(f"{k}={v}" for k, v in extra.items()))
            if roap.get("headers"):
                hdrs = [h for h in roap["headers"] if not str(h).startswith("x-cisco-turn-")]
                if hdrs:
                    print(f'      headers: {", ".join(map(str, hdrs))}')
            urls, user, pwd = turn_info(roap)
            for u in urls:
                print(f"      TURN url      {u}")
            if user or pwd:
                print(f"      TURN username {user}  password {pwd}")
            mc = r["parent"].get("mediaAgentCluster")
            if mc:
                selected = mc
                print(f"      media agent   {mc} ({r['parent'].get('mediaAgentAlias', '?')})")
            for k, sdp in enumerate(r["sdps"], 1):
                summary, sess, secs, cands = describe(sdp)
                print(f"      {summary}")
                for c in cands:
                    print(f"        a=candidate:{c}")
                ufrags += attr_all(secs, "ice-ufrag", sess)
                suffix = f"-{k}" if len(r["sdps"]) > 1 else ""
                name = f"{prefix}-seq{seq}-{r['mtype'].lower()}{suffix}.sdp"
                written.append(write(os.path.join(outdir, name), sdp, raw=True))
                if a.print:
                    print(sdp.replace("\r\n", "\n"))
            for e in tx["echoes"]:
                if e["mtype"] == r["mtype"]:
                    same = "identical" if e["sdps"] == r["sdps"] else "DIFFERENT SDP"
                    src = e["file"] if e["transport"] == "file" else f'frame {e["frame"]}'
                    print(f'      echoed in {src} {e["json_path"]} ({same})')
            if r["mtype"] == "OFFER" and r["sdps"]:
                offer = r
            elif r["mtype"] == "ANSWER" and r["sdps"]:
                answer = r
        for q in tx["msgs"]:
            resp = next((m for m in tx["msgs"] if m["mtype"] == PAIRS.get(q["mtype"])), None)
            if resp and q["transport"] != "file":
                print(f'  {q["mtype"].lower()} -> {resp["mtype"].lower()}: '
                      f'{(resp["time"] - q["time"]) * 1000:.0f} ms')
        if offer or answer:
            offer_answer.append((offer, answer))
            print("  per-mid:")
            print("\n".join(mid_table(offer and offer["sdps"][0], answer and answer["sdps"][0])))
            for nt in notes(offer and offer["sdps"][0], answer and answer["sdps"][0], tx["msgs"]):
                print(f"  note: {nt}")

    plain = [r for r in recs if r["roap"] is None]
    if plain:
        print("\nLocus media updates without ROAP:")
        for r in plain:
            state = ", ".join(f"{k}={v}" for k, v in r["envelope"].items() if not isinstance(v, (dict, list)))
            print(f'  frame {r["frame"]} t={r["time"]:.3f}s {r["direction"]:<8} {r["json_path"]}: {state}')

    # decoded Locus bodies (nested ROAP strings expanded)
    for meta, body in bodies:
        if any(r["frame"] == meta["frame"] for r in recs) or "reachability" in json.dumps(body)[:100000]:
            name = f'{prefix}-locus-{meta["frame"]}-{meta["direction"]}.json'
            written.append(write(os.path.join(outdir, name),
                                 json.dumps(decoded_body(body), indent=2, ensure_ascii=False) + "\n"))

    # reachability
    clusters = calliope_clusters(bodies)
    rep_frames, report = reachability_report(bodies)
    rounds = reachability_probes(stun, clusters) if stun else []
    if report or rounds:
        print("\nReachability")
        if clusters:
            f = next(m["frame"] for m, b in bodies if isinstance(b.get("clusters"), dict))
            print(f"  Calliope cluster list in frame {f}: {len(set(clusters.values()))} clusters, "
                  f"{len(clusters)} STUN targets")
        if report:
            dur = report.get("result", {}).get("metrics", {}).get("total-duration-ms")
            print(f"  client report (clientMediaPreferences.reachability) sent in frame(s) "
                  f"{', '.join(map(str, rep_frames))}" + (f", test duration {dur:.0f} ms" if dur else ""))
        for i, rnd in enumerate(rounds, 1):
            lost = sum(1 for p in rnd if p["rtt"] is None)
            sent = sum(p["sent"] for p in rnd)
            print(f"  STUN round {i}: frames {rnd[0]['frame']}-{max(p['resp_frame'] or p['frame'] for p in rnd)}, "
                  f"t={rnd[0]['time']:.3f}s, {len(rnd)} targets, {sent} requests "
                  f"({sent - len(rnd)} retransmits), {lost} unanswered")
        print("  rep. = reported by the client, STUN rN = fastest measured binding RTT per cluster and round")
        print("\n".join(reach_table(report, rounds, selected and selected.split(".")[0])))
        if rounds:
            lines = ["round\tframe\ttime\tsrc_port\tdst\tdst_port\tcluster\trequests\tresp_frame\trtt_ms\tmapped"]
            for i, rnd in enumerate(rounds, 1):
                for p in rnd:
                    lines.append("\t".join(map(str, (
                        i, p["frame"], f'{p["time"]:.6f}', p["sport"], p["dst"], p["dport"], p["cluster"],
                        p["sent"], p["resp_frame"] or "", f'{p["rtt"]:.1f}' if p["rtt"] is not None else "",
                        p["mapped"]))))
            written.append(write(os.path.join(outdir, f"{prefix}-reachability.tsv"), "\n".join(lines) + "\n"))

    # ICE checks with the negotiated ufrags
    ufrags = [u for u in dict.fromkeys(ufrags) if u]
    checks = [r for r in stun if r["type"] == "0x0001" and r["username"]
              and any(u in r["username"] for u in ufrags)]
    if checks:
        resp = {r["id"]: r for r in stun if r["type"] == "0x0101"}
        lines = ["frame\ttime\tproto\tsrc\tsport\tdst\tdport\tusername\tuse-candidate\tresp_frame\tmapped"]
        for c in checks:
            rsp = resp.get(c["id"])
            lines.append("\t".join(map(str, (
                c["frame"], f'{c["time"]:.6f}', c["proto"], c["src"], c["sport"], c["dst"], c["dport"],
                c["username"], "yes" if c["use_candidate"] else "", rsp["frame"] if rsp else "",
                f'{rsp["mapped_ip"]}:{rsp["mapped_port"]}' if rsp and rsp["mapped_ip"] else ""))))
        written.append(write(os.path.join(outdir, f"{prefix}-ice-checks.tsv"), "\n".join(lines) + "\n"))
        c0 = checks[0]
        print(f"\nFirst ICE check: frame {c0['frame']} at t={c0['time']:.3f}s "
              f"{c0['src']}:{c0['sport']} -> {c0['dst']}:{c0['dport']}/{c0['proto']}  ({len(checks)} checks total)")
        for dst in dict.fromkeys((c["dst"], c["dport"]) for c in checks):
            cs = [c for c in checks if (c["dst"], c["dport"]) == dst]
            mapped = {f'{resp[c["id"]]["mapped_ip"]}:{resp[c["id"]]["mapped_port"]}'
                      for c in cs if c["id"] in resp}
            nom = sum(1 for c in cs if c["use_candidate"])
            print(f"  -> {dst[0]}:{dst[1]}  {len(cs)} checks, {nom} with USE-CANDIDATE, "
                  f"mapped (prflx) {', '.join(sorted(mapped)) or '-'}")
        for offer, answer in offer_answer:
            if answer and answer["transport"] != "file":
                print(f"  answer -> first ICE check: {(c0['time'] - answer['time']) * 1000:.0f} ms")
                break

    print("\nWritten:")
    for p in written:
        print("  " + p)


if __name__ == "__main__":
    main()
