-- webrtc-sdp_in_zoom.lua
-- Wireshark dissector for the Zoom web client signalling. All signalling runs over
-- WebSockets to one "RWG" host; every binary WebSocket message holds one or more Zoom
-- records (batching):
--   record := type:u8 len:u16be body[len]
--     0x01/0x02  session handshake (C->S / S->C), opaque
--     0x03/0x04  ping / pong: u32 counter, u32 timestamp, 00, 37 f9, channel, 00
--     0x05       data: u16 seq, 00, 37 f9, channel, flags, subtype (0x0d JSON, 0x0a ACK), ...
--                JSON {"evt": <int>, "seq": <int>, "body": {...}} follows the sub-header
-- The browser builds two RTCPeerConnections:
--   PC-DC     /webclient/<meeting>         evt 24321 offer.sdp / evt 24322 answer.sdp
--   PC-AUDIO  /wc/media/<meeting>?mode=16  evt 32769 body.type 1 offer / 2 answer
--                                          (SDP gzip+base64, "sdpEncoding": 1)
-- This plugin splits the records (zoom_ws.*), hands the JSON to the built-in JSON
-- dissector, decodes the SDP (same logic as zoom-extract-sdp.py) and dissects it with the
-- built-in SDP dissector, so every line becomes its own tree item and sdp.* filters work.
-- Offer and answer are linked. Ping/pong records give the WebSocket RTT, and STUN checks
-- are labelled with their PeerConnection (zoom_stun.*).
--
-- Requires decrypted TLS (key log file or pcapng with embedded secrets). No preferences
-- needed.
--
-- Install: copy to the "Personal Lua Plugins" folder
--   (Help > About Wireshark > Folders), then Analyze > Reload Lua Plugins.
--
-- Filters:  sdp_in_zoom                          sdp_in_zoom.pc == "PC-AUDIO"
--           zoom_ws.evt == 24321                 zoom_ws.ping.rtt_ms > 150
--           zoom_ws.turn.url                     zoom_stun.initiator == "server"

local zoom  = Proto("zoom_ws", "Zoom web client signalling (WebSocket)")
local zsdp  = Proto("sdp_in_zoom", "SDP from Zoom web client")
local zstun = Proto("zoom_stun", "Zoom ICE connectivity checks")

local frametype = frametype or {}

local MAGIC = 0x37f9
local REC_TYPES = { [1] = "handshake", [2] = "handshake reply", [3] = "ping", [4] = "pong", [5] = "data" }
local CHANNELS = { [0x09] = "main (/webclient)", [0x0a] = "media (/wc/media)" }
local SUBTYPES = { [0x0d] = "JSON", [0x0a] = "ACK" }
local AUDIO_TYPES = { [1] = "offer", [2] = "answer", [3] = "confirm", [4] = "pre-offer" }
local EVT_NAMES = {
    [0] = "welcome", [4098] = "join response", [4128] = "meeting token", [4130] = "media SDK config",
    [4167] = "client telemetry", [4301] = "join meeting", [4305] = "request", [4309] = "request",
    [4310] = "token response", [7938] = "meeting state", [8015] = "meeting state",
    [8024] = "meeting state", [8193] = "audio mute", [8203] = "audio on", [12307] = "video on",
    [12308] = "see myself", [24321] = "PC-DC offer", [24322] = "PC-DC answer",
    [32769] = "PC-AUDIO negotiation", [32770] = "link quality", [32776] = "SSRC announcement",
}

local zf = {
    rec       = ProtoField.string("zoom_ws.rec", "Record"),
    rtype     = ProtoField.uint8("zoom_ws.rec.type", "Record type", base.HEX, REC_TYPES),
    rlen      = ProtoField.uint16("zoom_ws.rec.len", "Record length"),
    rseq      = ProtoField.uint16("zoom_ws.rec.seq", "Record seq"),
    magic     = ProtoField.uint16("zoom_ws.magic", "Magic", base.HEX),
    channel   = ProtoField.uint8("zoom_ws.channel", "Channel", base.HEX, CHANNELS),
    flags     = ProtoField.uint8("zoom_ws.flags", "Flags", base.HEX),
    subtype   = ProtoField.uint8("zoom_ws.subtype", "Subtype", base.HEX, SUBTYPES),
    subhdr    = ProtoField.bytes("zoom_ws.subheader", "Sub-header (not decoded)"),
    opaque    = ProtoField.bytes("zoom_ws.opaque", "Opaque body"),
    counter   = ProtoField.uint32("zoom_ws.ping.counter", "Ping counter"),
    pts       = ProtoField.uint32("zoom_ws.ping.ts", "Ping timestamp"),
    ping_in   = ProtoField.framenum("zoom_ws.ping.request_in", "Ping in", base.NONE, frametype.REQUEST),
    pong_in   = ProtoField.framenum("zoom_ws.ping.response_in", "Pong in", base.NONE, frametype.RESPONSE),
    rtt       = ProtoField.double("zoom_ws.ping.rtt_ms", "Ping RTT (ms)"),
    ws        = ProtoField.string("zoom_ws.websocket", "WebSocket"),
    direction = ProtoField.string("zoom_ws.direction", "Direction"),
    evt       = ProtoField.uint32("zoom_ws.evt", "evt", base.DEC, EVT_NAMES),
    seq       = ProtoField.int32("zoom_ws.seq", "seq"),
    turn_url  = ProtoField.string("zoom_ws.turn.url", "ICE server url"),
    turn_user = ProtoField.string("zoom_ws.turn.username", "ICE server username"),
    turn_cred = ProtoField.string("zoom_ws.turn.credential", "ICE server credential"),
    ssrc      = ProtoField.string("zoom_ws.ssrc", "SSRC"),
    lq        = ProtoField.string("zoom_ws.link_quality", "Link quality"),
}
local zf_list = {}
for _, f in pairs(zf) do zf_list[#zf_list + 1] = f end
zoom.fields = zf_list

local ef_json = ProtoExpert.new("zoom_ws.json_error", "Zoom JSON could not be decoded",
                                expert.group.MALFORMED, expert.severity.WARN)
zoom.experts = { ef_json }

local sf = {
    pc          = ProtoField.string("sdp_in_zoom.pc", "PeerConnection"),
    role        = ProtoField.string("sdp_in_zoom.type", "Type"),
    encoding    = ProtoField.string("sdp_in_zoom.encoding", "SDP encoding"),
    session_id  = ProtoField.int32("sdp_in_zoom.session_id", "sessionID"),
    peer_id     = ProtoField.int32("sdp_in_zoom.peer_id", "peerID"),
    msg_id      = ProtoField.int32("sdp_in_zoom.msg_id", "msgID"),
    offer_in    = ProtoField.framenum("sdp_in_zoom.offer_in", "Offer in", base.NONE, frametype.REQUEST),
    answer_in   = ProtoField.framenum("sdp_in_zoom.answer_in", "Answer in", base.NONE, frametype.RESPONSE),
    delay       = ProtoField.double("sdp_in_zoom.delay_ms", "Offer to answer (ms)"),
    toggle      = ProtoField.string("sdp_in_zoom.feature_toggle", "featureToggle"),
    ice_ufrag   = ProtoField.string("sdp_in_zoom.ice_ufrag", "ICE ufrag"),
    ice_pwd     = ProtoField.string("sdp_in_zoom.ice_pwd", "ICE pwd"),
    ice_lite    = ProtoField.bool("sdp_in_zoom.ice_lite", "ICE lite"),
    fingerprint = ProtoField.string("sdp_in_zoom.fingerprint", "DTLS fingerprint"),
    setup       = ProtoField.string("sdp_in_zoom.setup", "DTLS setup"),
    candidate   = ProtoField.string("sdp_in_zoom.candidate", "Candidate"),
    mid         = ProtoField.string("sdp_in_zoom.mid", "Media section"),
    mid_id      = ProtoField.string("sdp_in_zoom.mid.id", "mid"),
    mid_kind    = ProtoField.string("sdp_in_zoom.mid.kind", "Media"),
    mid_dir     = ProtoField.string("sdp_in_zoom.mid.direction", "Direction"),
    mid_ssrc    = ProtoField.string("sdp_in_zoom.mid.ssrc", "SSRC"),
    mid_codecs  = ProtoField.string("sdp_in_zoom.mid.codecs", "Codecs"),
    mid_opus    = ProtoField.string("sdp_in_zoom.mid.opus", "Opus fmtp"),
    note        = ProtoField.string("sdp_in_zoom.note", "Note"),
}
local sf_list = {}
for _, f in pairs(sf) do sf_list[#sf_list + 1] = f end
zsdp.fields = sf_list

local ef_note = ProtoExpert.new("sdp_in_zoom.note", "Zoom SDP note", expert.group.PROTOCOL,
                                expert.severity.NOTE)
local ef_undecoded = ProtoExpert.new("sdp_in_zoom.undecoded", "Zoom SDP could not be decoded",
                                     expert.group.UNDECODED, expert.severity.WARN)
zsdp.experts = { ef_note, ef_undecoded }

local tf = {
    pc        = ProtoField.string("zoom_stun.pc", "PeerConnection"),
    initiator = ProtoField.string("zoom_stun.initiator", "Check sent by"),
    nominate  = ProtoField.bool("zoom_stun.use_candidate", "USE-CANDIDATE (nomination)"),
    req_in    = ProtoField.framenum("zoom_stun.request_in", "Request in", base.NONE, frametype.REQUEST),
}
zstun.fields = { tf.pc, tf.initiator, tf.nominate, tf.req_in }

local f_tcp_stream = Field.new("tcp.stream")
local f_http_uri   = Field.new("http.request.uri")
local f_http_meth  = Field.new("http.request.method")
local f_stun_type  = Field.new("stun.type")
local f_stun_id    = Field.new("stun.id")
local f_stun_user  = Field.new("stun.att.username")
local f_stun_att   = Field.new("stun.att.type")
local sdp_dissector  = Dissector.get("sdp")
local json_dissector = Dissector.get("json")

local streams = {}   -- tcp.stream -> { ws = "webclient" | "media mode=16", client_port }
local pings   = {}   -- "tcp:counter+ts" -> { frame, ts, port, pong }
local negs    = {}   -- negotiation key -> list of { offer = {frame, ts, sdp}, answer = ... }
local ice     = {}   -- "ufragA:ufragB" -> { pc, initiator }
local stun_tx = {}   -- STUN transaction id -> { frame, pc }
function zoom.init()
    streams, pings, negs, ice, stun_tx = {}, {}, {}, {}, {}
end

-- =====================================================================  JSON decoding
-- Minimal JSON parser: objects -> tables, arrays -> tables (1-based), null -> NULL.
-- Returns the value and the position after it; trailing bytes are allowed (the record
-- may carry data after the JSON).
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
    return v, pos
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
            cur = { kind = f[1], proto = f[3], pts = { table.unpack(f, 4) }, attrs = {} }
            secs[#secs + 1] = cur
        elseif line:sub(1, 2) == "t=" and not cur then
            sess.t = line:sub(3)
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
        s.dir = "sendrecv (default)"
        for _, d in ipairs({ "sendrecv", "sendonly", "recvonly", "inactive" }) do
            if a[d] then s.dir = d end
        end
        s.rtpmap, s.fmtp, s.fb = {}, {}, {}
        for _, v in ipairs(a.rtpmap or {}) do
            local pt, name = v:match("^(%S+)%s+([^/]+)")
            if pt then s.rtpmap[pt] = name end
        end
        for _, v in ipairs(a.fmtp or {}) do
            local pt, p = v:match("^(%S+)%s+(.*)$")
            if pt then s.fmtp[pt] = p end
        end
        for _, v in ipairs(a["rtcp-fb"] or {}) do
            local pt, fb = v:match("^(%S+)%s+(.*)$")
            if pt then s.fb[pt .. " " .. fb] = true end
        end
        local cs, opus = {}, nil
        for _, pt in ipairs(s.pts) do
            local name = s.rtpmap[pt] or (s.kind == "application" and "" or "?")
            local red = (s.fmtp[pt] or ""):match("^(%d+)/")
            if name:lower() == "red" and red then name = "red>" .. red end
            if name:lower() == "opus" and not opus then opus = s.fmtp[pt] end
            cs[#cs + 1] = name == "" and pt or (pt .. ":" .. name)
        end
        s.codecs = table.concat(cs, " ")
        s.opus = opus
        local ssrcs, seen = {}, {}
        for _, v in ipairs(a.ssrc or {}) do
            local id = v:match("^(%d+)")
            if id and not seen[id] then seen[id] = true; ssrcs[#ssrcs + 1] = id end
        end
        s.ssrcs = ssrcs
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

-- Notes on Zoom-specific SDP. offer_sdp is only given for an answer.
local function sdp_notes(secs, sess, role, offer_sdp)
    local out = {}
    local cands = attr_values(secs, sess, "candidate")
    if role == "offer" then
        if #cands == 0 then
            out[#out + 1] = "no candidates (and none are trickled) - the ICE-lite server learns the " ..
                            "client address as peer-reflexive from the ICE checks"
        end
        if sess.t and not sess.t:find("^0 ") then
            out[#out + 1] = "t=" .. sess.t .. " (browsers send t=0 0) - SDP munged by the Zoom client"
        end
        return out
    end
    if sess.attrs["ice-lite"] then out[#out + 1] = "ice-lite - the browser is ICE controlling" end
    local protos = {}
    for _, c in ipairs(cands) do
        local f = {}
        for w in c:gmatch("%S+") do f[#f + 1] = w end
        if f[6] and not f[5]:find(":") then
            local k = f[5] .. ":" .. f[6]
            protos[k] = protos[k] or {}
            protos[k][f[3]:lower()] = true
        end
    end
    for k, p in pairs(protos) do
        if p.udp and p.tcp then out[#out + 1] = "same port on UDP and TCP: " .. k end
    end
    if offer_sdp then
        local o_secs = parse_sdp(offer_sdp)
        local kept, dropped, seen, added = {}, {}, {}, {}
        for _, s in ipairs(secs) do
            for _, n in pairs(s.rtpmap) do kept[n:lower()] = true end
        end
        for _, o in ipairs(o_secs) do
            for _, n in pairs(o.rtpmap) do
                if not kept[n:lower()] and not seen[n] then seen[n] = true; dropped[#dropped + 1] = n end
            end
        end
        table.sort(dropped)
        if #dropped > 0 then out[#out + 1] = "codecs dropped from the offer: " .. table.concat(dropped, ", ") end
        local by = {}
        for _, o in ipairs(o_secs) do by[o.mid] = o end
        seen = {}
        for _, s in ipairs(secs) do
            local o = by[s.mid]
            for k in pairs(o and s.fb or {}) do
                local pt, fb = k:match("^(%S+) (.*)$")
                local name = (s.rtpmap[pt] or pt) .. " " .. fb
                if not o.fb[k] and not seen[name] then seen[name] = true; added[#added + 1] = name end
            end
        end
        table.sort(added)
        if #added > 0 then out[#out + 1] = "rtcp-fb added (not in the offer): " .. table.concat(added, ", ") end
    end
    return out
end

local function ufrag_of(sdp)
    local secs, sess = parse_sdp(sdp)
    return attr_values(secs, sess, "ice-ufrag")[1]
end

local function add_sdp_summary(ti, sdp, role, offer_sdp)
    local secs, sess = parse_sdp(sdp)
    for _, v in ipairs(attr_values(secs, sess, "ice-ufrag")) do ti:add(sf.ice_ufrag, v) end
    for _, v in ipairs(attr_values(secs, sess, "ice-pwd")) do ti:add(sf.ice_pwd, v) end
    if sess.attrs["ice-lite"] then ti:add(sf.ice_lite, true) end
    for _, v in ipairs(attr_values(secs, sess, "fingerprint")) do ti:add(sf.fingerprint, v) end
    for _, v in ipairs(attr_values(secs, sess, "setup")) do ti:add(sf.setup, v) end
    local cands = attr_values(secs, sess, "candidate")
    if #cands > 0 then
        local ct = ti:add(zsdp, "Candidates (" .. #cands .. ")")
        for _, c in ipairs(cands) do ct:add(sf.candidate, c) end
    end
    local mt = ti:add(zsdp, "Media sections (" .. #secs .. ")")
    for _, s in ipairs(secs) do
        local ssrc = #s.ssrcs > 0 and (", ssrc " .. table.concat(s.ssrcs, ",")) or ""
        local st = mt:add(sf.mid, string.format("mid %s: %s, %s%s, %s", s.mid, s.kind, s.dir, ssrc, s.codecs))
        st:add(sf.mid_id, s.mid)
        st:add(sf.mid_kind, s.kind)
        st:add(sf.mid_dir, s.dir)
        for _, v in ipairs(s.ssrcs) do st:add(sf.mid_ssrc, v) end
        st:add(sf.mid_codecs, s.codecs)
        if s.opus then st:add(sf.mid_opus, s.opus) end
    end
    local notes = sdp_notes(secs, sess, role, offer_sdp)
    if #notes > 0 then
        local nt = ti:add(zsdp, "Notes (" .. #notes .. ")")
        for _, n in ipairs(notes) do nt:add(sf.note, n):add_proto_expert_info(ef_note, n) end
    end
end

-- =====================================================================  SDP / negotiation
-- Offer/answer exchanges: PC-DC in order on its WebSocket, PC-AUDIO by connection +
-- peerID + msgID (the answer carries no sessionID/confID).
local function negotiation(key, role, frame)
    local list = negs[key] or {}
    negs[key] = list
    for _, n in ipairs(list) do
        if n[role] and n[role].frame == frame then return n end
    end
    local last = list[#list]
    local opening = role == "offer" or role == "pre-offer"
    if not last or last[role] or (opening and last.answer) then
        last = {}
        list[#list + 1] = last
    end
    return last
end

local function gunzip_b64(b64, name)
    local ok, u = pcall(function()
        local r = ByteArray.new(b64, true):base64_decode():tvb("Zoom SDP (gzip)"):range()
        local ok2, t = pcall(function() return r:uncompress_gzip(name) end)
        if not ok2 or not t then t = r:uncompress(name) end   -- Wireshark < 4.4
        return t:tvb()
    end)
    if ok then return u end
    return nil
end

-- pc = "PC-DC" | "PC-AUDIO"; env = the JSON object holding "sdp"
local function add_sdp(tree, range, pinfo, pc, role, key, env)
    local ti = tree:add(zsdp, range)
    ti:append_text(": " .. pc .. " " .. role)
    ti:add(sf.pc, pc)
    ti:add(sf.role, role)
    if pc == "PC-AUDIO" then
        if tonumber(env.sessionID) then ti:add(sf.session_id, math.floor(env.sessionID)) end
        if tonumber(env.peerID) then ti:add(sf.peer_id, math.floor(env.peerID)) end
        if tonumber(env.msgID) then ti:add(sf.msg_id, math.floor(env.msgID)) end
    end
    for _, t in ipairs(type(env.featureToggles) == "table" and env.featureToggles or {}) do
        if type(t) == "table" then
            local v = t.value
            if type(v) == "table" then v = "[" .. #v .. " item(s)]" end
            ti:add(sf.toggle, tostring(t.key) .. " = " .. tostring(v))
        end
    end

    local n = negotiation(key, role, pinfo.number)
    local rec = n[role] or { frame = pinfo.number, ts = pinfo.abs_ts }
    n[role] = rec
    if role == "answer" and n.offer then
        ti:add(sf.offer_in, n.offer.frame):set_generated()
        ti:add(sf.delay, math.floor((rec.ts - n.offer.ts) * 10000 + 0.5) / 10):set_generated()
    elseif role == "offer" and n.answer then
        ti:add(sf.answer_in, n.answer.frame):set_generated()
    end

    local s = env.sdp
    if type(s) ~= "string" or s == "" then return end
    local label = "Zoom SDP " .. role .. " (" .. pc .. ")"
    local sdp_tvb
    if s:find("^v=0") then
        ti:add(sf.encoding, "plain")
        sdp_tvb = ByteArray.new(s, true):tvb(label)
    elseif tonumber(env.sdpEncoding) == 1 or s:find("^H4sI") then
        ti:add(sf.encoding, "gzip+base64")
        sdp_tvb = gunzip_b64(s, label)
    end
    if not sdp_tvb then
        ti:add_proto_expert_info(ef_undecoded)
        return
    end
    local sdp = sdp_tvb:raw()
    rec.sdp = sdp
    add_sdp_summary(ti, sdp, role, role == "answer" and n.offer and n.offer.sdp or nil)
    if role == "answer" and n.offer and n.offer.sdp then
        local a, o = ufrag_of(sdp), ufrag_of(n.offer.sdp)
        if a and o then
            ice[a .. ":" .. o] = { pc = pc, initiator = "client" }
            ice[o .. ":" .. a] = { pc = pc, initiator = "server" }
        end
    end
    sdp_dissector:call(sdp_tvb, pinfo, tree)
end

-- =====================================================================  records
local function add_ice_servers(tree, cfg)
    for _, list in ipairs({ "iceServers", "stunServers" }) do
        for _, s in ipairs(type(cfg[list]) == "table" and cfg[list] or {}) do
            if type(s) == "table" then
                local t = tree:add(zf.turn_url, tostring(s.urls))
                if s.username then t:add(zf.turn_user, tostring(s.username)) end
                if s.credential then t:add(zf.turn_cred, tostring(s.credential)) end
            else
                tree:add(zf.turn_url, tostring(s))
            end
        end
    end
end

-- one JSON message; returns a short label for the Info column and, for offers/answers,
-- a function that adds the SDP (called after the JSON dissector, for the column order)
local function handle_json(obj, rt, jrange, pinfo, tree, tcp)
    local evt = tonumber(obj.evt)
    local body = type(obj.body) == "table" and obj.body or {}
    if evt then rt:add(zf.evt, math.floor(evt)) end
    if tonumber(obj.seq) then rt:add(zf.seq, math.floor(obj.seq)) end
    local label = evt and ("evt " .. math.floor(evt) .. (EVT_NAMES[evt] and (" " .. EVT_NAMES[evt]) or ""))
                  or "JSON"
    local job = nil

    if type(body.mediasdkConfig) == "table" then add_ice_servers(rt, body.mediasdkConfig) end
    if evt == 32776 then
        for _, k in ipairs({ "normal_ssrc", "share_ssrc" }) do
            if tonumber(body[k]) then
                rt:add(zf.ssrc, string.format("%s %d (0x%08X)", k, body[k], body[k]))
            end
        end
    elseif evt == 32770 and type(body.uplink) == "table" then
        local s = string.format("type %s uplink rtt %s loss %s, downlink rtt %s loss %s",
                                tostring(body.type), tostring(body.uplink.rtt), tostring(body.uplink.avg_loss),
                                tostring((body.downlink or {}).rtt), tostring((body.downlink or {}).avg_loss))
        rt:add(zf.lq, s)
        label = label .. ", rtt " .. tostring(body.uplink.rtt)
    elseif evt == 24321 or evt == 24322 then
        local role = evt == 24321 and "offer" or "answer"
        if type(obj[role]) == "table" then
            job = function() add_sdp(tree, jrange, pinfo, "PC-DC", role, "dc:" .. tcp, obj[role]) end
        end
        label = "PC-DC " .. role
    elseif evt == 32769 then
        local role = AUDIO_TYPES[tonumber(body.type)] or ("type " .. tostring(body.type))
        local key = string.format("audio:%s:%s:%s", tcp, tostring(body.peerID), tostring(body.msgID))
        job = function() add_sdp(tree, jrange, pinfo, "PC-AUDIO", role, key, body) end
        label = "PC-AUDIO " .. role
    end
    rt:append_text(": " .. label)
    return label, job
end

local function dissect_record(tvb, off, rtype, len, pinfo, tree, tcp, dir)
    local r = tvb(off, 3 + len)
    local rt = tree:add(zoom, r, REC_TYPES[rtype])
    rt:add(zf.rtype, tvb(off, 1))
    rt:add(zf.rlen, tvb(off + 1, 2))
    if rtype == 1 or rtype == 2 then
        if len > 0 then rt:add(zf.opaque, tvb(off + 3, len)) end
        return "handshake"
    end
    if rtype == 3 or rtype == 4 then
        rt:add(zf.counter, tvb(off + 3, 4))
        rt:add(zf.pts, tvb(off + 7, 4))
        rt:add(zf.magic, tvb(off + 12, 2))
        rt:add(zf.channel, tvb(off + 14, 1))
        local key = tcp .. ":" .. tvb(off + 3, 8):bytes():tohex()
        local who = dir == "C->S" and "client" or "server"
        local label = (rtype == 3 and (who .. " ping #") or (who .. " pong #")) .. tvb(off + 3, 4):uint()
        if rtype == 3 then
            local p = pings[key]
            if not p then
                p = { frame = pinfo.number, ts = pinfo.abs_ts, port = pinfo.src_port }
                pings[key] = p
            end
            if p.pong then rt:add(zf.pong_in, p.pong):set_generated() end
        else
            -- only a client ping gives the network RTT at the capture point (next to the
            -- client); for a server ping it is just the client's response time
            local p = pings[key]
            if p and p.port ~= pinfo.src_port then
                p.pong = p.pong or pinfo.number
                rt:add(zf.ping_in, p.frame):set_generated()
                if dir == "S->C" then
                    local rtt = math.floor((pinfo.abs_ts - p.ts) * 10000 + 0.5) / 10
                    rt:add(zf.rtt, rtt):set_generated()
                    label = label .. " rtt " .. rtt .. " ms"
                end
            end
        end
        rt:append_text(": " .. label)
        return label
    end

    -- data record
    rt:add(zf.rseq, tvb(off + 3, 2))
    rt:add(zf.magic, tvb(off + 6, 2))
    rt:add(zf.channel, tvb(off + 8, 1))
    rt:add(zf.flags, tvb(off + 9, 1))
    local raw = tvb:raw(off, 3 + len)
    local i = raw:find('{"', 10, true)
    if not i then
        local st = len >= 8 and tvb(off + 10, 1):uint()
        if st == 0x0a or (len >= 14 and tvb(off + 16, 1):uint() == 0x0a) then
            rt:append_text(": ACK")
            return "ACK"
        end
        return "data"
    end
    if i > 11 then rt:add(zf.subhdr, tvb(off + 10, i - 11)) end
    local ok, obj, stop = pcall(json_decode, raw:sub(i))
    if not ok or type(obj) ~= "table" then
        rt:add_proto_expert_info(ef_json)
        return "JSON?"
    end
    local jrange = tvb(off + i - 1, stop - 1)
    local label, job = handle_json(obj, rt, jrange, pinfo, tree, tcp)
    json_dissector:call(jrange:tvb(), pinfo, rt)
    if job then job() end
    return label
end

-- Heuristic on WebSocket payloads: the whole payload must split into Zoom records.
-- Handshake records (types 1/2) carry no magic, so they are only accepted on
-- connections upgraded from /webclient/ or /wc/media/.
local function heur_zoom(tvb, pinfo, tree)
    local n = tvb:len()
    if n < 3 then return false end
    local ts = f_tcp_stream()
    local tcp = ts and ts.value or -1
    local recs, p, magic = {}, 0, false
    while p < n do
        if p + 3 > n then return false end
        local t, len = tvb(p, 1):uint(), tvb(p + 1, 2):uint()
        if not REC_TYPES[t] or p + 3 + len > n then return false end
        if t == 5 then
            if len < 6 or tvb(p + 6, 2):uint() ~= MAGIC then return false end
            magic = true
        elseif t == 3 or t == 4 then
            if len < 12 or tvb(p + 12, 2):uint() ~= MAGIC then return false end
            magic = true
        end
        recs[#recs + 1] = { t, p, len }
        p = p + 3 + len
    end
    local st = streams[tcp]
    if not magic and not st then return false end

    local dir
    if st and st.client_port then
        dir = pinfo.src_port == st.client_port and "C->S" or "S->C"
    else
        dir = pinfo.dst_port == 443 and "C->S" or "S->C"
    end
    pinfo.cols.protocol:append("/Zoom")
    local top = tree:add(zoom, tvb(), "Zoom web client signalling (" .. #recs .. " record" ..
                         (#recs > 1 and "s" or "") .. ")")
    if st then top:add(zf.ws, st.ws):set_generated() end
    top:add(zf.direction, dir):set_generated()

    local labels, last, count = {}, nil, 0
    local function flush()
        if last then labels[#labels + 1] = count > 1 and (last .. " x" .. count) or last end
    end
    for _, r in ipairs(recs) do
        local label = dissect_record(tvb, r[2], r[1], r[3], pinfo, top, tcp, dir)
        if label == last then
            count = count + 1
        else
            flush()
            last, count = label, 1
        end
    end
    flush()
    pinfo.cols.info:append(" [Zoom " .. table.concat(labels, ", ") .. "] ")
    return true
end

zoom:register_heuristic("ws", heur_zoom)

-- =====================================================================  postdissector
-- remembers the Zoom WebSocket upgrades and labels STUN checks with their PeerConnection
function zstun.dissector(tvb, pinfo, tree)
    local meth, uri = f_http_meth(), f_http_uri()
    if meth and uri then
        local path, query = tostring(uri.value):match("^([^?]*)%??(.*)$")
        local ts = f_tcp_stream()
        if ts and (path:find("^/webclient/") or path:find("^/wc/media/")) then
            local mode = query:match("mode=(%d+)")
            streams[ts.value] = { client_port = pinfo.src_port,
                                  ws = path:find("^/webclient/") and "webclient" or
                                       ("media" .. (mode and (" mode=" .. mode) or "")) }
        end
    end

    local st = f_stun_type()
    if not st then return end
    local id = f_stun_id()
    id = id and tostring(id.value) or ""
    if st.value == 0x0001 then
        local user = f_stun_user()
        local m = user and ice[tostring(user.value)]
        if not m then return end
        stun_tx[id] = stun_tx[id] or { frame = pinfo.number, pc = m.pc }
        local nominate = false
        for _, a in ipairs({ f_stun_att() }) do
            if a.value == 0x0025 then nominate = true end
        end
        local t = tree:add(zstun, "Zoom " .. m.pc .. " ICE check sent by the " .. m.initiator ..
                           (nominate and " (USE-CANDIDATE)" or ""))
        t:add(tf.pc, m.pc):set_generated()
        t:add(tf.initiator, m.initiator):set_generated()
        if nominate then t:add(tf.nominate, true):set_generated() end
        pinfo.cols.info:append(" [Zoom " .. m.pc .. " check by " .. m.initiator ..
                               (nominate and ", nominated" or "") .. "]")
    elseif st.value == 0x0101 and stun_tx[id] then
        local q = stun_tx[id]
        local t = tree:add(zstun, "Zoom " .. q.pc .. " ICE check response")
        t:add(tf.pc, q.pc):set_generated()
        t:add(tf.req_in, q.frame):set_generated()
        pinfo.cols.info:append(" [Zoom " .. q.pc .. " check OK]")
    end
end

register_postdissector(zstun)
