-- webrtc-sdp_in_webex.lua
-- Wireshark postdissector for Cisco Webex (web client) media signalling. SDP travels
-- inside ROAP messages (Webex's offer/answer envelope) in Locus REST calls over HTTP/2.
-- The ROAP message is JSON encoded as a string inside the JSON body:
--   join   POST /locus/api/v1/loci/call   localMedias[0].localSdp    TURN_DISCOVERY_REQUEST
--          200 response                   mediaConnections[0].remoteSdp  TURN_DISCOVERY_RESPONSE
--   offer  PUT .../participant/<id>/media  localMedias[0].localSdp    OFFER  (sdps[0] = SDP)
--          200 response                   mediaConnections[0].remoteSdp  ANSWER
--                                         mediaConnections[0].localSdp   echo of the OFFER
-- This plugin decodes those strings (same logic as webex-extract-sdp.py) and dissects
-- the SDP with the built-in SDP dissector, so every line becomes its own tree item and
-- sdp.* filters work. Offer and answer are linked via the ROAP seq.
--
-- It also shows the TURN servers/credentials from TURN discovery, the client's media
-- reachability report, the Calliope cluster list, annotates Mercury WebSocket events
-- (webex_mercury.*) and labels STUN reachability probes and ICE checks (webex_stun.*).
--
-- Requires decrypted TLS (key log file or pcapng with embedded secrets) and
-- the default HTTP/2 preferences (body reassembly and decompression).
--
-- Install: copy to the "Personal Lua Plugins" folder
--   (Help > About Wireshark > Folders), then Analyze > Reload Lua Plugins.
--
-- Filters:  sdp_in_webex                         sdp_in_webex.roap.type == "ANSWER"
--           sdp_in_webex.turn.url                sdp_in_webex.reach.udp_ms < 100
--           webex_mercury.event == "locus.difference"
--           webex_stun.kind == "reachability"    webex_stun.cluster contains "wamsm"

local webex   = Proto("sdp_in_webex", "SDP from Cisco Webex ROAP (Locus)")
local mercury = Proto("webex_mercury", "Cisco Webex Mercury (WebSocket events)")
local wstun   = Proto("webex_stun", "Cisco Webex STUN reachability / ICE")

local frametype = frametype or {}
local unpack = table.unpack or unpack

local pf = {
    rtype       = ProtoField.string("sdp_in_webex.roap.type", "ROAP messageType"),
    seq         = ProtoField.uint32("sdp_in_webex.roap.seq", "ROAP seq"),
    version     = ProtoField.string("sdp_in_webex.roap.version", "ROAP version"),
    tiebreaker  = ProtoField.uint32("sdp_in_webex.roap.tiebreaker", "ROAP tieBreaker"),
    header      = ProtoField.string("sdp_in_webex.roap.header", "ROAP header"),
    echo        = ProtoField.bool("sdp_in_webex.roap.echo", "Echo of the client's message"),
    echo_of     = ProtoField.framenum("sdp_in_webex.roap.echo_of", "Echo of", base.NONE, frametype.REQUEST),
    req_in      = ProtoField.framenum("sdp_in_webex.roap.request_in", "ROAP request in", base.NONE,
                                      frametype.REQUEST),
    resp_in     = ProtoField.framenum("sdp_in_webex.roap.response_in", "ROAP response in", base.NONE,
                                      frametype.RESPONSE),
    delay       = ProtoField.double("sdp_in_webex.roap.delay_ms", "Request to response (ms)"),
    path        = ProtoField.string("sdp_in_webex.json_path", "JSON path"),
    direction   = ProtoField.string("sdp_in_webex.direction", "HTTP direction"),
    locus       = ProtoField.string("sdp_in_webex.locus_id", "Locus id"),
    participant = ProtoField.string("sdp_in_webex.participant_id", "Participant id"),
    audio_muted = ProtoField.bool("sdp_in_webex.audio_muted", "audioMuted"),
    video_muted = ProtoField.bool("sdp_in_webex.video_muted", "videoMuted"),
    turn_url    = ProtoField.string("sdp_in_webex.turn.url", "TURN url"),
    turn_user   = ProtoField.string("sdp_in_webex.turn.username", "TURN username"),
    turn_pwd    = ProtoField.string("sdp_in_webex.turn.password", "TURN password"),
    agent       = ProtoField.string("sdp_in_webex.media_agent_cluster", "Media agent cluster"),
    ice_ufrag   = ProtoField.string("sdp_in_webex.ice_ufrag", "ICE ufrag"),
    ice_pwd     = ProtoField.string("sdp_in_webex.ice_pwd", "ICE pwd"),
    ice_lite    = ProtoField.bool("sdp_in_webex.ice_lite", "ICE lite"),
    fingerprint = ProtoField.string("sdp_in_webex.fingerprint", "DTLS fingerprint"),
    setup       = ProtoField.string("sdp_in_webex.setup", "DTLS setup"),
    candidate   = ProtoField.string("sdp_in_webex.candidate", "Candidate"),
    mid         = ProtoField.string("sdp_in_webex.mid", "Media section"),
    mid_id      = ProtoField.string("sdp_in_webex.mid.id", "mid"),
    mid_kind    = ProtoField.string("sdp_in_webex.mid.kind", "Media"),
    mid_content = ProtoField.string("sdp_in_webex.mid.content", "Content"),
    mid_dir     = ProtoField.string("sdp_in_webex.mid.direction", "Direction"),
    mid_proto   = ProtoField.string("sdp_in_webex.mid.proto", "Transport profile"),
    mid_tias    = ProtoField.string("sdp_in_webex.mid.tias", "b=TIAS"),
    mid_csi     = ProtoField.string("sdp_in_webex.mid.csi", "jmp-source csi"),
    mid_codecs  = ProtoField.string("sdp_in_webex.mid.codecs", "Codecs"),
    mid_sim     = ProtoField.string("sdp_in_webex.mid.simulcast", "ssrc-group SIM"),
    mid_maxfs   = ProtoField.string("sdp_in_webex.mid.ssrc_max_fs", "ssrc max-fs"),
    reach       = ProtoField.string("sdp_in_webex.reach.cluster", "Reachability"),
    reach_udp   = ProtoField.uint32("sdp_in_webex.reach.udp_ms", "UDP latency (ms)"),
    reach_tcp   = ProtoField.uint32("sdp_in_webex.reach.tcp_ms", "TCP latency (ms)"),
    reach_xtls  = ProtoField.uint32("sdp_in_webex.reach.xtls_ms", "xTLS latency (ms)"),
    reach_ip    = ProtoField.string("sdp_in_webex.reach.client_ip", "Client media IP"),
    cluster     = ProtoField.string("sdp_in_webex.calliope.cluster", "Calliope cluster"),
    target      = ProtoField.string("sdp_in_webex.calliope.target", "STUN target"),
    note        = ProtoField.string("sdp_in_webex.note", "Note"),
}
local pf_list = {}
for _, f in pairs(pf) do pf_list[#pf_list + 1] = f end
webex.fields = pf_list

local ef_note = ProtoExpert.new("sdp_in_webex.note", "Webex SDP note", expert.group.PROTOCOL,
                                expert.severity.NOTE)
local ef_undecoded = ProtoExpert.new("sdp_in_webex.undecoded", "Locus body could not be decoded",
                                     expert.group.UNDECODED, expert.severity.WARN)
webex.experts = { ef_note, ef_undecoded }

local mf = {
    id      = ProtoField.string("webex_mercury.id", "Message id"),
    mtype   = ProtoField.string("webex_mercury.type", "Type"),
    event   = ProtoField.string("webex_mercury.event", "Event type"),
    ack_of  = ProtoField.string("webex_mercury.message_id", "Acknowledged message id"),
    locus   = ProtoField.string("webex_mercury.locus_url", "Locus URL"),
    track   = ProtoField.string("webex_mercury.tracking_id", "Tracking id"),
}
mercury.fields = { mf.id, mf.mtype, mf.event, mf.ack_of, mf.locus, mf.track }

local sf = {
    kind    = ProtoField.string("webex_stun.kind", "Kind"),
    cluster = ProtoField.string("webex_stun.cluster", "Cluster (Calliope)"),
    rtt     = ProtoField.double("webex_stun.rtt_ms", "RTT (ms)"),
    nominate = ProtoField.bool("webex_stun.use_candidate", "USE-CANDIDATE (nomination)"),
    seq     = ProtoField.uint32("webex_stun.roap_seq", "ROAP seq of the ufrags"),
}
wstun.fields = { sf.kind, sf.cluster, sf.rtt, sf.nominate, sf.seq }

local f_tcp_stream = Field.new("tcp.stream")
local f_h2data     = Field.new("http2.data.data")
local f_ws_text    = Field.new("websocket.payload.text")
local f_http_uri   = Field.new("http.request.uri")
local f_stun_type  = Field.new("stun.type")
local f_stun_user  = Field.new("stun.att.username")
local f_stun_att   = Field.new("stun.att.type")
local f_stun_time  = Field.new("stun.time")
local f_ip_src     = Field.new("ip.src")
local f_ip_dst     = Field.new("ip.dst")
local f_udp_src    = Field.new("udp.srcport")
local f_udp_dst    = Field.new("udp.dstport")
local sdp_dissector  = Dissector.get("sdp")
local json_dissector = Dissector.get("json")

local PAIRS = { OFFER = "ANSWER", TURN_DISCOVERY_REQUEST = "TURN_DISCOVERY_RESPONSE" }
local REVERSE = { ANSWER = "OFFER", TURN_DISCOVERY_RESPONSE = "TURN_DISCOVERY_REQUEST" }

local h2req    = {}   -- "tcp:sid" -> { method, path }
local roaps    = {}   -- seq -> messageType -> { frame, ts, sdp }
local clusters = {}   -- "ip:port" -> cluster name (Calliope)
local ice      = {}   -- "answer_ufrag:offer_ufrag" -> seq
local mercury_streams = {}
function webex.init()
    h2req, roaps, clusters, ice, mercury_streams = {}, {}, {}, {}, {}
end

-- =====================================================================  JSON decoding
-- Minimal JSON parser: objects -> tables, arrays -> tables (1-based), null -> NULL.
local NULL = setmetatable({}, { __tostring = function() return "null" end })
local ESC = { ['"'] = '"', ['\\'] = '\\', ['/'] = '/', b = '\b', f = '\f', n = '\n', r = '\r', t = '\t' }

local function utf8char(cp)
    local f = math.floor
    if cp < 0x80 then return string.char(cp) end
    if cp < 0x800 then return string.char(0xC0 + f(cp / 64), 0x80 + cp % 64) end
    if cp < 0x10000 then
        return string.char(0xE0 + f(cp / 4096), 0x80 + f(cp / 64) % 64, 0x80 + cp % 64)
    end
    return string.char(0xF0 + f(cp / 262144), 0x80 + f(cp / 4096) % 64, 0x80 + f(cp / 64) % 64, 0x80 + cp % 64)
end

local function json_decode(s)
    local pos = 1
    local function ws() pos = s:find("[^ \t\r\n]", pos) or #s + 1 end
    local function str()
        pos = pos + 1
        local parts = {}
        while true do
            local i = s:find('["\\]', pos)
            if not i then error("unterminated string") end
            parts[#parts + 1] = s:sub(pos, i - 1)
            if s:sub(i, i) == '"' then pos = i + 1; break end
            local c = s:sub(i + 1, i + 1)
            if c == "u" then
                local cp = tonumber(s:sub(i + 2, i + 5), 16)
                if not cp then error("bad \\u escape") end
                pos = i + 6
                if cp >= 0xD800 and cp <= 0xDBFF and s:sub(pos, pos + 1) == "\\u" then
                    local lo = tonumber(s:sub(pos + 2, pos + 5), 16)
                    if lo and lo >= 0xDC00 and lo <= 0xDFFF then
                        cp, pos = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00), pos + 6
                    end
                end
                parts[#parts + 1] = utf8char(cp)
            else
                parts[#parts + 1] = ESC[c] or error("bad escape")
                pos = i + 2
            end
        end
        return table.concat(parts)
    end
    local val
    local function container(close, is_obj)
        local t = {}
        pos = pos + 1
        ws()
        if s:sub(pos, pos) == close then pos = pos + 1; return t end
        while true do
            ws()
            if is_obj then
                if s:sub(pos, pos) ~= '"' then error("expected key") end
                local k = str()
                ws()
                if s:sub(pos, pos) ~= ":" then error("expected ':'") end
                pos = pos + 1
                t[k] = val()
            else
                t[#t + 1] = val()
            end
            ws()
            local d = s:sub(pos, pos)
            pos = pos + 1
            if d == close then return t end
            if d ~= "," then error("expected ',' or '" .. close .. "'") end
        end
    end
    function val()
        ws()
        local c = s:sub(pos, pos)
        if c == "{" then return container("}", true) end
        if c == "[" then return container("]", false) end
        if c == '"' then return str() end
        for lit, v in pairs({ ["true"] = true, ["false"] = false, null = NULL }) do
            if s:sub(pos, pos + #lit - 1) == lit then pos = pos + #lit; return v end
        end
        local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
        if not num or num == "" then error("unexpected '" .. c .. "' at " .. pos) end
        pos = pos + #num
        return tonumber(num)
    end
    local v = val()
    ws()
    if pos <= #s then error("trailing data") end
    return v
end

local function jdecode(s)
    if type(s) ~= "string" or not s:find("^%s*[{%[]") then return nil end
    local ok, v = pcall(json_decode, s)
    if ok and type(v) == "table" then return v end
    return nil
end

local function tget(t, ...)
    for _, k in ipairs({ ... }) do
        if type(t) ~= "table" then return nil end
        t = t[k]
    end
    return t
end

local function sorted_keys(t)
    local ks = {}
    for k in pairs(t) do ks[#ks + 1] = k end
    table.sort(ks, function(a, b) return tostring(a) < tostring(b) end)
    return ks
end

-- =====================================================================  SDP summary
local function parse_sdp(sdp)
    local secs, cur = {}, nil
    local sess = { attrs = {} }
    for line in (sdp .. "\n"):gmatch("([^\n]*)\n") do
        line = line:gsub("\r$", "")
        if line:sub(1, 2) == "m=" then
            local f = {}
            for w in line:sub(3):gmatch("%S+") do f[#f + 1] = w end
            cur = { kind = f[1], proto = f[3], pts = { select(4, unpack(f)) }, attrs = {} }
            secs[#secs + 1] = cur
        elseif line:sub(1, 7) == "b=TIAS:" and cur then
            cur.tias = line:sub(8)
        elseif line:sub(1, 2) == "a=" then
            local k, v = line:match("^a=([^:]+):?(.*)$")
            local t = (cur or sess).attrs
            if k then
                t[k] = t[k] or {}
                table.insert(t[k], v)
            end
        end
    end
    for _, s in ipairs(secs) do
        local a = s.attrs
        s.mid = a.mid and a.mid[1] or "?"
        s.content = a.content and a.content[1] or nil
        s.dir = "sendrecv (default)"
        for _, d in ipairs({ "sendrecv", "sendonly", "recvonly", "inactive" }) do
            if a[d] then s.dir = d end
        end
        local csi = {}
        for _, v in ipairs(a["jmp-source"] or {}) do csi[#csi + 1] = v:match("csi=(%d+)") end
        s.csi = #csi > 0 and table.concat(csi, ",") or nil
        s.max_msg = a["max-message-size"] and a["max-message-size"][1] or nil
        local rtpmap, fmtp = {}, {}
        for _, v in ipairs(a.rtpmap or {}) do
            local pt, name = v:match("^(%S+)%s+([^/]+)")
            if pt then rtpmap[pt] = name end
        end
        for _, v in ipairs(a.fmtp or {}) do
            local pt, p = v:match("^(%S+)%s+(.*)$")
            if pt then fmtp[pt] = p end
        end
        local cs = {}
        for _, pt in ipairs(s.pts) do
            local name = rtpmap[pt] or (s.kind == "application" and "" or "?")
            local apt = (fmtp[pt] or ""):match("apt=(%d+)")
            if name:lower() == "rtx" and apt then name = "rtx>" .. apt end
            local plid = name:upper() == "H264" and (fmtp[pt] or ""):match("profile%-level%-id=(%w+)")
            if plid then
                local pm = (fmtp[pt] or ""):match("packetization%-mode=(%d)")
                name = name .. "(" .. plid .. (pm and (",pm" .. pm) or "") .. ")"
            end
            cs[#cs + 1] = name == "" and pt or (pt .. ":" .. name)
        end
        s.codecs = table.concat(cs, " ")
        s.sim, s.maxfs = {}, {}
        for _, v in ipairs(a["ssrc-group"] or {}) do
            if v:find("^SIM ") then s.sim[#s.sim + 1] = v:sub(5) end
        end
        for _, v in ipairs(a.ssrc or {}) do
            local ssrc, fs = v:match("^(%d+) fmtp:%S+ .-max%-fs=(%d+)")
            if ssrc then s.maxfs[#s.maxfs + 1] = ssrc .. "=" .. fs end
        end
    end
    return secs, sess
end

-- unique values of attribute k across all sections (and session level)
local function attr_values(secs, sess, k)
    local seen, out = {}, {}
    local function add(list)
        for _, v in ipairs(list or {}) do
            if not seen[v] then seen[v] = true; out[#out + 1] = v end
        end
    end
    add(sess.attrs[k])
    for _, s in ipairs(secs) do add(s.attrs[k]) end
    return out
end

-- Notes on Webex-specific / non-standard SDP. offer_sdp is only given for an answer.
local function sdp_notes(sdp, offer_sdp)
    local secs, sess = parse_sdp(sdp)
    local cands = attr_values(secs, sess, "candidate")
    local out = {}
    local dummy = #cands > 0
    for _, c in ipairs(cands) do
        if not c:find(" 0%.0%.0%.0 9 ") then dummy = false end
    end
    if dummy then
        out[#out + 1] = "only placeholder candidates (0.0.0.0:9) - the peer learns this side as " ..
                        "peer-reflexive from the ICE checks"
    end
    if sess.attrs["ice-lite"] then out[#out + 1] = "ice-lite - the browser is ICE controlling" end
    local xtls, fqdn, found, fseen = 0, {}, {}, {}
    for _, c in ipairs(cands) do
        local f = {}
        for w in c:gmatch("%S+") do f[#f + 1] = w end
        if f[3] == "xTLS" then xtls = xtls + 1 end
        if f[5] and f[5]:find("%a") and not f[5]:find(":") and not fseen[f[5]] then
            fseen[f[5]] = true
            fqdn[#fqdn + 1] = f[5]
        end
        if f[6] then
            found[f[1]] = found[f[1]] or {}
            found[f[1]][f[5] .. ":" .. f[6] .. "/" .. f[3]] = true
        end
    end
    if xtls > 0 then
        out[#out + 1] = xtls .. " xTLS candidate(s) - Webex-specific transport (TLS on 443), " ..
                        "ignored by browser ICE"
    end
    if #fqdn > 0 then out[#out + 1] = "FQDN candidates: " .. table.concat(fqdn, ", ") end
    local dup = {}
    for _, k in ipairs(sorted_keys(found)) do
        if #sorted_keys(found[k]) > 1 then dup[#dup + 1] = k end
    end
    if #dup > 0 then
        out[#out + 1] = "candidate foundations reused for different addresses: " .. table.concat(dup, ", ")
    end
    if offer_sdp then
        local by = {}
        for _, s in ipairs(parse_sdp(offer_sdp)) do by[s.mid] = s end
        local seen = {}
        for _, s in ipairs(secs) do
            local o = by[s.mid]
            if o and o.proto ~= s.proto and not seen[o.proto .. s.proto] then
                seen[o.proto .. s.proto] = true
                out[#out + 1] = "transport profile " .. s.proto .. " answers offered " .. o.proto
            end
            if o and o.max_msg and s.max_msg and o.max_msg ~= s.max_msg then
                out[#out + 1] = "mid " .. s.mid .. " max-message-size: offer " .. o.max_msg ..
                                ", answer " .. s.max_msg
            end
        end
    end
    return out, secs, sess
end

-- =====================================================================  tree
local function add_list(tree, label, field, items)
    if #items == 0 then return end
    local t = tree:add(webex, label .. " (" .. #items .. ")")
    for _, s in ipairs(items) do t:add(field, s) end
end

local function add_notes(tree, notes)
    if #notes == 0 then return end
    local t = tree:add(webex, "Notes (" .. #notes .. ")")
    for _, n in ipairs(notes) do t:add(pf.note, n):add_proto_expert_info(ef_note, n) end
end

local function add_sdp_summary(ti, sdp, offer_sdp)
    local notes, secs, sess = sdp_notes(sdp, offer_sdp)
    for _, v in ipairs(attr_values(secs, sess, "ice-ufrag")) do ti:add(pf.ice_ufrag, v) end
    for _, v in ipairs(attr_values(secs, sess, "ice-pwd")) do ti:add(pf.ice_pwd, v) end
    if sess.attrs["ice-lite"] then ti:add(pf.ice_lite, true) end
    for _, v in ipairs(attr_values(secs, sess, "fingerprint")) do ti:add(pf.fingerprint, v) end
    for _, v in ipairs(attr_values(secs, sess, "setup")) do ti:add(pf.setup, v) end
    add_list(ti, "Candidates", pf.candidate, attr_values(secs, sess, "candidate"))
    local mt = ti:add(webex, "Media sections (" .. #secs .. ")")
    for _, s in ipairs(secs) do
        local summary = string.format("mid %s: %s%s, %s, %s%s", s.mid, s.kind,
                                      s.content and (" " .. s.content) or "", s.dir, s.proto,
                                      s.csi and (", csi " .. s.csi) or "")
        local st = mt:add(pf.mid, summary)
        st:add(pf.mid_id, s.mid)
        st:add(pf.mid_kind, s.kind)
        if s.content then st:add(pf.mid_content, s.content) end
        st:add(pf.mid_dir, s.dir)
        st:add(pf.mid_proto, s.proto)
        if s.tias then st:add(pf.mid_tias, s.tias) end
        if s.csi then st:add(pf.mid_csi, s.csi) end
        st:add(pf.mid_codecs, s.codecs)
        for _, v in ipairs(s.sim) do st:add(pf.mid_sim, v) end
        if #s.maxfs > 0 then st:add(pf.mid_maxfs, table.concat(s.maxfs, " ")) end
    end
    add_notes(ti, notes)
    return secs, sess
end

local function ufrag_of(sdp)
    local secs, sess = parse_sdp(sdp)
    return attr_values(secs, sess, "ice-ufrag")[1]
end

-- one localSdp / remoteSdp string
local function add_media(tree, range, pinfo, ctx, key, jpath, env, parent)
    local roap = type(env.roapMessage) == "table" and env.roapMessage or nil
    local echo = ctx.direction == "response" and key == "localSdp"
    local mtype = roap and tostring(roap.messageType or "?") or nil
    local seq = roap and tonumber(roap.seq) or nil
    local sdp = roap and type(roap.sdps) == "table" and type(roap.sdps[1]) == "string" and roap.sdps[1] or nil

    local ti = tree:add(webex, range)
    ti:append_text(": " .. (roap and ("ROAP " .. mtype .. " seq " .. tostring(seq)) or "media state (no ROAP)")
                   .. (echo and " (echo)" or ""))
    if roap then
        ti:add(pf.rtype, mtype)
        if seq then ti:add(pf.seq, seq) end
        if roap.version then ti:add(pf.version, tostring(roap.version)) end
        if tonumber(roap.tieBreaker) then ti:add(pf.tiebreaker, math.floor(tonumber(roap.tieBreaker))) end
    end
    ti:add(pf.path, jpath)
    ti:add(pf.direction, ctx.direction):set_generated()
    if ctx.locus then ti:add(pf.locus, ctx.locus):set_generated() end
    if ctx.participant then ti:add(pf.participant, ctx.participant):set_generated() end
    if type(env.audioMuted) == "boolean" then ti:add(pf.audio_muted, env.audioMuted) end
    if type(env.videoMuted) == "boolean" then ti:add(pf.video_muted, env.videoMuted) end
    if type(parent.mediaAgentCluster) == "string" then
        ti:add(pf.agent, parent.mediaAgentCluster)
    end
    if not roap then
        if ctx.direction == "request" then
            pinfo.cols.info:append(string.format(" [Locus media audioMuted=%s videoMuted=%s]",
                                   tostring(env.audioMuted), tostring(env.videoMuted)))
        end
        return
    end

    local ht = nil
    for _, h in ipairs(type(roap.headers) == "table" and roap.headers or {}) do
        h = tostring(h)
        local k, v = h:match("^([^=]+)=(.*)$")
        if k == "x-cisco-turn-url" then ti:add(pf.turn_url, v)
        elseif k == "x-cisco-turn-username" then ti:add(pf.turn_user, v)
        elseif k == "x-cisco-turn-password" then ti:add(pf.turn_pwd, v)
        else
            ht = ht or ti:add(webex, "ROAP headers")
            ht:add(pf.header, h)
        end
    end

    -- link request/response of the same ROAP transaction (seq)
    local r = seq and roaps[seq] or nil
    if seq and not roaps[seq] then r = {}; roaps[seq] = r end
    if echo then
        local orig = r and r[mtype]
        ti:add(pf.echo, true):set_generated()
        if orig and orig.frame ~= pinfo.number then
            ti:add(pf.echo_of, orig.frame):set_generated()
            if orig.sdp == sdp then
                ti:append_text(", identical to frame " .. orig.frame)
                return
            end
        end
    else
        if r and not r[mtype] then r[mtype] = { frame = pinfo.number, ts = pinfo.abs_ts, sdp = sdp } end
        local peer = r and r[PAIRS[mtype] or REVERSE[mtype] or ""]
        if peer and peer.frame ~= pinfo.number then
            if REVERSE[mtype] then
                ti:add(pf.req_in, peer.frame):set_generated()
                ti:add(pf.delay, math.floor((pinfo.abs_ts - peer.ts) * 10000 + 0.5) / 10):set_generated()
            else
                ti:add(pf.resp_in, peer.frame):set_generated()
            end
        end
        pinfo.cols.info:append(" [ROAP " .. mtype .. " seq=" .. tostring(seq) .. "]")
    end

    if sdp then
        local offer = mtype == "ANSWER" and r and r.OFFER and r.OFFER.sdp or nil
        add_sdp_summary(ti, sdp, offer)
        if mtype == "ANSWER" and offer then
            local a, o = ufrag_of(sdp), ufrag_of(offer)
            if a and o then ice[a .. ":" .. o] = seq end
        end
        local sdp_tvb = ByteArray.new(sdp, true):tvb("Webex ROAP " .. mtype)
        sdp_dissector:call(sdp_tvb, pinfo, tree)
    end
end

local function add_reachability(tree, range, rep)
    local tests = tget(rep, "result", "tests")
    if type(tests) ~= "table" then return end
    local names = sorted_keys(tests)
    local dur = tonumber(tget(rep, "result", "metrics", "total-duration-ms"))
    local rt = tree:add(webex, range, string.format("Reachability report (%d clusters%s)", #names,
                                                    dur and string.format(", %.0f ms", dur) or ""))
    for _, name in ipairs(names) do
        local t, parts = tests[name], {}
        for _, proto in ipairs({ "udp", "tcp", "xtls" }) do
            local p = type(t) == "table" and t[proto] or nil
            if type(p) == "table" then
                local ok = tostring(p.reachable) == "true"
                parts[#parts + 1] = proto .. " " .. (ok and ((p.latencyInMilliseconds or "?") .. " ms") or "no")
            end
        end
        local ct = rt:add(pf.reach, name .. ": " .. table.concat(parts, ", "))
        for _, proto in ipairs({ "udp", "tcp", "xtls" }) do
            local p = type(t) == "table" and t[proto] or nil
            local ms = type(p) == "table" and tostring(p.reachable) == "true" and tonumber(p.latencyInMilliseconds)
            if ms then ct:add(pf["reach_" .. proto], math.floor(ms)) end
            if proto == "udp" and type(p) == "table" and type(p.clientMediaIPs) == "table" then
                for _, ip in ipairs(p.clientMediaIPs) do ct:add(pf.reach_ip, tostring(ip)) end
            end
        end
    end
end

local function add_calliope(tree, range, cl)
    local names = sorted_keys(cl)
    local ct = tree:add(webex, range, "Calliope media clusters (" .. #names .. ")")
    for _, name in ipairs(names) do
        local targets = {}
        for _, proto in ipairs(sorted_keys(type(cl[name]) == "table" and cl[name] or {})) do
            for _, u in ipairs(type(cl[name][proto]) == "table" and cl[name][proto] or {}) do
                local hp = tostring(u):match("^[^:]+:(.*)$") or tostring(u)
                clusters[hp] = clusters[hp] or name
                targets[#targets + 1] = proto .. " " .. hp
            end
        end
        local t = ct:add(pf.cluster, name)
        for _, s in ipairs(targets) do t:add(pf.target, s) end
    end
end

-- one decoded Locus / Calliope JSON body
local function handle_body(obj, tree, range, pinfo, info)
    local ctx = { direction = obj.mediaConnections and "response" or "request" }
    local path = info and info.path or ""
    local UUID = "(%x+%-%x+%-%x+%-%x+%-%x+)"
    ctx.locus = path:match("/loci/" .. UUID) or
                tostring(tget(obj, "locus", "url") or ""):match("/loci/" .. UUID)
    ctx.participant = path:match("/participant/" .. UUID) or tget(obj, "locus", "self", "id")

    local rep = tget(obj, "clientMediaPreferences", "reachability")
    if type(rep) == "table" then add_reachability(tree, range, rep) end
    if type(obj.clusters) == "table" then add_calliope(tree, range, obj.clusters) end

    for _, list in ipairs({ "localMedias", "mediaConnections" }) do
        for i, m in ipairs(type(obj[list]) == "table" and obj[list] or {}) do
            for _, key in ipairs({ "localSdp", "remoteSdp" }) do
                local env = type(m) == "table" and jdecode(m[key]) or nil
                if env then
                    add_media(tree, range, pinfo, ctx, key,
                              string.format("%s[%d].%s", list, i - 1, key), env, m)
                elseif type(m) == "table" and type(m[key]) == "string" then
                    tree:add(webex, range):add_proto_expert_info(ef_undecoded)
                end
            end
        end
    end
end

-- =====================================================================  Mercury
local function dissect_mercury(fi, pinfo, tree)
    local obj = jdecode(fi.value)
    if not obj then return end
    local mt = tree:add(mercury, fi.range)
    local ev = tget(obj, "data", "eventType")
    local label = ev or obj.type or "message"
    if type(obj.id) == "string" then mt:add(mf.id, obj.id) end
    if type(obj.type) == "string" then mt:add(mf.mtype, obj.type) end
    if type(ev) == "string" then mt:add(mf.event, ev) end
    if type(obj.messageId) == "string" then mt:add(mf.ack_of, obj.messageId) end
    local lu = tget(obj, "data", "locusUrl")
    if type(lu) == "string" then mt:add(mf.locus, lu) end
    if type(obj.trackingId) == "string" then mt:add(mf.track, obj.trackingId) end
    mt:append_text(": " .. tostring(label))
    pinfo.cols.info:append(" [Mercury " .. tostring(label) .. "]")
    json_dissector:call(ByteArray.new(fi.value, true):tvb("Mercury JSON"), pinfo, mt)
end

-- =====================================================================  STUN
local function dissect_stun(pinfo, tree)
    local st = f_stun_type()
    local src, dst = f_ip_src(), f_ip_dst()
    local sp, dp = f_udp_src(), f_udp_dst()
    if not (st and src and dst and sp and dp) then return end
    st = st.value
    local user = f_stun_user()
    if st == 0x0001 and user then
        local seq = ice[tostring(user.value)]
        if seq == nil then return end
        local nominate = false
        for _, a in ipairs({ f_stun_att() }) do
            if a.value == 0x0025 then nominate = true end
        end
        local t = tree:add(wstun, "Webex ICE connectivity check" .. (nominate and " (USE-CANDIDATE)" or ""))
        t:add(sf.kind, "ice"):set_generated()
        t:add(sf.seq, seq):set_generated()
        if nominate then t:add(sf.nominate, true):set_generated() end
        pinfo.cols.info:append(" [Webex ICE check" .. (nominate and ", nominated" or "") .. "]")
        return
    end
    if user then return end
    local req = st == 0x0001
    local peer = req and (tostring(dst.value) .. ":" .. dp.value) or (tostring(src.value) .. ":" .. sp.value)
    local cl = clusters[peer]
    if not cl or not (st == 0x0001 or st == 0x0101) then return end
    local t = tree:add(wstun, "Webex reachability " .. (req and "probe to " or "response from ") .. cl)
    t:add(sf.kind, "reachability"):set_generated()
    t:add(sf.cluster, cl):set_generated()
    local rtt = f_stun_time()
    if not req and rtt then
        local ms = tonumber(tostring(rtt.value)) or 0
        t:add(sf.rtt, math.floor(ms * 10000 + 0.5) / 10):set_generated()
        t:append_text(string.format(", %.1f ms", ms * 1000))
    end
    pinfo.cols.info:append(" [Webex reachability " .. cl .. "]")
end

-- =====================================================================  dissector
local MARKS = { "localSdp", "remoteSdp", "clientMediaPreferences", '"clusters"' }

function webex.dissector(tvb, pinfo, tree)
    local ts = f_tcp_stream()
    local tcp = ts and ts.value or nil

    -- Mercury: WebSocket upgraded from GET .../apps/wx2/registrations/<id>/messages
    local uri = f_http_uri()
    if tcp and uri and tostring(uri.value):find("/apps/wx2/registrations/", 1, true) then
        mercury_streams[tcp] = true
    end
    if tcp and mercury_streams[tcp] then
        for _, fi in ipairs({ f_ws_text() }) do dissect_mercury(fi, pinfo, tree) end
    end

    if f_stun_type() then dissect_stun(pinfo, tree) end

    -- HTTP/2: remember :method/:path per stream; bodies only on DATA frames that complete
    -- a body - END_STREAM set or reassembled here
    if tcp == nil then return end
    local cur, frames = nil, {}
    for _, fi in ipairs({ all_field_infos() }) do
        local n = fi.name
        if n == "http2.stream" then
            cur = { chunks = {} }
            frames[#frames + 1] = cur
        elseif cur and n == "http2.streamid" then
            cur.sid = fi.value
        elseif cur and n == "http2.headers.path" and cur.sid then
            local k = tcp .. ":" .. cur.sid
            h2req[k] = h2req[k] or { path = tostring(fi.value) }
        elseif cur and (n == "http2.body.reassembled.data" or (n == "http2.flags.end_stream" and fi.value)) then
            cur.complete = true
        elseif cur and n == "http2.data.data" then
            cur.chunks[#cur.chunks + 1] = fi
        end
    end
    if not f_h2data() then return end
    for _, fr in ipairs(frames) do
        if fr.complete then
            for _, fi in ipairs(fr.chunks) do
                local raw = fi.value:raw()
                local hit = false
                for _, m in ipairs(MARKS) do
                    if raw:find(m, 1, true) then hit = true; break end
                end
                if hit then
                    local obj = jdecode(raw)
                    if obj then
                        handle_body(obj, tree, fi.range, pinfo, fr.sid and h2req[tcp .. ":" .. fr.sid])
                    end
                end
            end
        end
    end
end

-- 'true' = ask for all fields, so the http2/websocket/stun fields are available on every pass
register_postdissector(webex, true)
