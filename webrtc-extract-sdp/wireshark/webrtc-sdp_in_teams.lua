-- webrtc-sdp_in_teams.lua
-- Wireshark postdissector for Microsoft Teams signalling. Teams sends real SDP,
-- but as a JSON string on two different connections:
--   offer   HTTP/2 POST to the conversation service (.../conv/<id>), JSON body,
--           SDP in callInvitation.mediaContent.blob
--   answer  Trouter WebSocket callback, socket.io-style frame
--           3:::{"method":"POST","url":".../call/acceptance/","body":"<base64 gzip JSON>"}
--           SDP in callAcceptance.mediaContent.blob
-- This plugin finds those strings (same logic as teams-extract-sdp.py) and
-- dissects them with the built-in SDP dissector, so every line becomes its own
-- tree item and sdp.* filters work. Offer and answer are linked via mediaLegId.
--
-- It also annotates every Trouter message (teams_trouter.*) and shows the
-- decoded callback body as JSON.
--
-- Requires decrypted TLS (key log file or pcapng with embedded secrets) and
-- the default HTTP/2 preferences (body reassembly).
--
-- Install: copy to the "Personal Lua Plugins" folder
--   (Help > About Wireshark > Folders), then Analyze > Reload Lua Plugins.
--
-- Filters:  sdp_in_teams                     sdp_in_teams.type == "answer"
--           sdp_in_teams.mid.effective_direction == "recvonly"
--           teams_trouter.callback == "call/acceptance"

local sdp_teams = Proto("sdp_in_teams", "SDP from Microsoft Teams signalling JSON")
local trouter   = Proto("teams_trouter", "Microsoft Teams Trouter (socket.io over WebSocket)")

local frametype = frametype or {}
local unpack = table.unpack or unpack

local pf = {
    type        = ProtoField.string("sdp_in_teams.type", "Type"),
    path        = ProtoField.string("sdp_in_teams.json_path", "JSON path"),
    ctype       = ProtoField.string("sdp_in_teams.content_type", "Content type"),
    leg         = ProtoField.string("sdp_in_teams.media_leg", "mediaLegId"),
    offer_in    = ProtoField.framenum("sdp_in_teams.offer_in", "Offer in", base.NONE, frametype.REQUEST),
    answer_in   = ProtoField.framenum("sdp_in_teams.answer_in", "Answer in", base.NONE, frametype.RESPONSE),
    delay       = ProtoField.double("sdp_in_teams.offer_answer_ms", "Offer to answer (ms)"),
    ice_ufrag   = ProtoField.string("sdp_in_teams.ice_ufrag", "ICE ufrag"),
    ice_pwd     = ProtoField.string("sdp_in_teams.ice_pwd", "ICE pwd"),
    fingerprint = ProtoField.string("sdp_in_teams.fingerprint", "DTLS fingerprint"),
    setup       = ProtoField.string("sdp_in_teams.setup", "DTLS setup"),
    candidate   = ProtoField.string("sdp_in_teams.candidate", "Candidate"),
    mid         = ProtoField.string("sdp_in_teams.mid", "Media section"),
    mid_id      = ProtoField.string("sdp_in_teams.mid.id", "mid"),
    mid_kind    = ProtoField.string("sdp_in_teams.mid.kind", "Media"),
    mid_label   = ProtoField.string("sdp_in_teams.mid.label", "Label"),
    mid_dir     = ProtoField.string("sdp_in_teams.mid.direction", "Direction (SDP)"),
    mid_eff     = ProtoField.string("sdp_in_teams.mid.effective_direction",
                                    "Effective direction (mediaDescriptions)"),
    mid_ssrc    = ProtoField.string("sdp_in_teams.mid.ssrc_range", "x-ssrc-range"),
    mid_codecs  = ProtoField.string("sdp_in_teams.mid.codecs", "Codecs"),
    note        = ProtoField.string("sdp_in_teams.note", "Note"),
}
sdp_teams.fields = { pf.type, pf.path, pf.ctype, pf.leg, pf.offer_in, pf.answer_in, pf.delay,
                     pf.ice_ufrag, pf.ice_pwd, pf.fingerprint, pf.setup, pf.candidate, pf.mid,
                     pf.mid_id, pf.mid_kind, pf.mid_label, pf.mid_dir, pf.mid_eff, pf.mid_ssrc,
                     pf.mid_codecs, pf.note }

local SIO_TYPES = { [0] = "disconnect", [1] = "connect", [2] = "heartbeat", [3] = "message",
                    [4] = "json", [5] = "event", [6] = "ack", [7] = "error", [8] = "noop" }
local tf = {
    ftype    = ProtoField.uint8("teams_trouter.type", "socket.io type", base.DEC, SIO_TYPES),
    id       = ProtoField.string("teams_trouter.id", "Message id"),
    event    = ProtoField.string("teams_trouter.event", "Event"),
    method   = ProtoField.string("teams_trouter.method", "Method"),
    url      = ProtoField.string("teams_trouter.url", "URL"),
    token    = ProtoField.string("teams_trouter.link_token", "Link token"),
    callback = ProtoField.string("teams_trouter.callback", "Callback"),
    status   = ProtoField.uint16("teams_trouter.status", "Status"),
    chain    = ProtoField.string("teams_trouter.chain_id", "X-Microsoft-Skype-Chain-ID"),
    encoding = ProtoField.string("teams_trouter.body_encoding", "Body encoding"),
}
trouter.fields = { tf.ftype, tf.id, tf.event, tf.method, tf.url, tf.token, tf.callback, tf.status,
                   tf.chain, tf.encoding }

local ef_undecoded = ProtoExpert.new("sdp_in_teams.undecoded", "Body mentions SDP but could not be decoded",
                                     expert.group.UNDECODED, expert.severity.WARN)
sdp_teams.experts = { ef_undecoded }

local f_ws           = Field.new("websocket.payload")
local f_h2data       = Field.new("http2.data.data")
local sdp_dissector  = Dissector.get("sdp")
local json_dissector = Dissector.get("json")

local legs = {}   -- mediaLegId -> { offer = frame, answer = frame, offer_ts = , answer_ts = }
function sdp_teams.init() legs = {} end

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

-- =====================================================================  body decoding
local function gunzip(s)
    local r = ByteArray.new(s, true):tvb("gzip body"):range()
    local ok, u = pcall(function() return r:uncompress_gzip("Gunzipped body") end)
    if not ok then u = r:uncompress("Gunzipped body") end   -- Wireshark < 4.4
    if not u then error("gunzip failed") end
    return u:bytes():raw()
end

local B64 = "^[%w+/_=%s-]+$"

-- string -> parsed JSON table, the JSON text, and how it was wrapped (socket.io, base64, gzip)
local function decode_any(s, depth, enc)
    depth, enc = depth or 0, enc or {}
    if depth > 4 or type(s) ~= "string" then return nil end
    if s:sub(1, 2) == "\31\139" then
        local ok, u = pcall(gunzip, s)
        if not ok then return nil end
        enc[#enc + 1] = "gzip"
        return decode_any(u, depth + 1, enc)
    end
    s = s:match("^%s*(.-)%s*$")
    local stripped = s:gsub("^%d+:[^:]*:[^:]*:", "", 1)
    s = stripped
    local c = s:sub(1, 1)
    if c == "{" or c == "[" then
        local ok, v = pcall(json_decode, s)
        if ok and type(v) == "table" then return v, s, enc end
        return nil
    end
    if #s > 16 and s:find(B64) then
        s = s:gsub("%s", ""):gsub("%-", "+"):gsub("_", "/")
        s = s .. string.rep("=", (4 - #s % 4) % 4)
        local ok, raw = pcall(function() return ByteArray.new(s, true):base64_decode():raw() end)
        if not ok or not raw or #raw == 0 then return nil end
        enc[#enc + 1] = "base64"
        return decode_any(raw, depth + 1, enc)
    end
    return nil
end

-- Collect every string starting with "v=0". Long strings are tried as nested
-- JSON / base64 / gzip (e.g. the Trouter "body").
local function find_sdps(v, path, out, depth)
    if type(v) == "table" and v ~= NULL then
        for k, x in pairs(v) do
            local p = type(k) == "number" and (path .. "[" .. (k - 1) .. "]") or
                      (path == "" and k or (path .. "." .. k))
            if type(x) == "string" and x:find("^%s*v=0") then
                out.sdps[#out.sdps + 1] = { path = p, sdp = x, parent = v }
            else
                find_sdps(x, p, out, depth)
            end
        end
    elseif type(v) == "string" and #v > 40 and depth < 3 then
        local inner, text, enc = decode_any(v)
        if inner then
            out.decoded[#out.decoded + 1] = { path = path, text = text, enc = enc, value = inner }
            find_sdps(inner, path .. ".<decoded>", out, depth + 1)
        end
    end
end

local function role_of(path)
    local best, role = 0, "sdp"
    for key, r in pairs({ callInvitation = "offer", mediaOffer = "offer", callAcceptance = "answer",
                          mediaAnswer = "answer" }) do
        local i = 0
        while true do
            local j = path:find(key, i + 1, true)
            if not j then break end
            i = j
        end
        if i > best then best, role = i, r end
    end
    return role
end

local function tget(t, ...)
    for _, k in ipairs({ ... }) do
        if type(t) ~= "table" then return nil end
        t = t[k]
    end
    return t
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
            cur = { kind = f[1], pts = { select(4, unpack(f)) },
                    attrs = {}, order = {} }
            secs[#secs + 1] = cur
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
        s.label = a.label and a.label[1] or "-"
        s.dir = "sendrecv (default)"
        for _, d in ipairs({ "sendrecv", "sendonly", "recvonly", "inactive" }) do
            if a[d] then s.dir = d end
        end
        s.ssrc_range = a["x-ssrc-range"] and a["x-ssrc-range"][1] or nil
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
            local name = rtpmap[pt] or "?"
            local apt = (fmtp[pt] or ""):match("apt=(%d+)")
            if name:lower() == "rtx" and apt then name = "rtx>" .. apt end
            local plid = name:upper() == "H264" and (fmtp[pt] or ""):match("profile%-level%-id=(%w+)")
            if plid then name = name .. "(" .. plid .. ")" end
            cs[#cs + 1] = pt .. ":" .. name
        end
        s.codecs = table.concat(cs, " ")
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

local function notes_for(rec, body)
    local out, n, uris, seen = {}, 0, {}, {}
    for line in rec.sdp:gmatch("a=extmap:%d+ ([^\r\n]+)") do
        if line:find("^%a+:\\\\") then
            n = n + 1
            if not seen[line] then seen[line] = true; uris[#uris + 1] = line end
        end
    end
    if n > 0 then
        out[#out + 1] = n .. " extmap lines use backslash URIs as sent on the wire: " .. table.concat(uris, ", ")
    end
    local function walk(t)
        if type(t) ~= "table" or t == NULL then return end
        for k, v in pairs(t) do
            if k == "mediaParameter" and type(v) == "string" then out[#out + 1] = "mediaParameter: " .. v end
            walk(v)
        end
    end
    walk(body)
    return out
end

-- =====================================================================  tree
local function add_list(tree, label, field, items)
    if #items == 0 then return end
    local t = tree:add(sdp_teams, label .. " (" .. #items .. ")")
    for _, s in ipairs(items) do t:add(field, s) end
end

local function add_sdp(tree, range, pinfo, rec, body)
    local role = role_of(rec.path)
    local ti = range and tree:add(sdp_teams, range) or tree:add(sdp_teams)
    ti:append_text(": " .. role)
    ti:add(pf.type, role):set_generated()
    ti:add(pf.path, rec.path)
    local mc = rec.parent
    if type(mc.contentType) == "string" then ti:add(pf.ctype, mc.contentType) end

    local leg = type(mc.mediaLegId) == "string" and mc.mediaLegId or nil
    if leg then
        ti:add(pf.leg, leg)
        local l = legs[leg] or {}
        legs[leg] = l
        if role == "offer" or role == "answer" then
            l[role], l[role .. "_ts"] = l[role] or pinfo.number, l[role .. "_ts"] or pinfo.abs_ts
        end
        if role == "answer" and l.offer and l.offer ~= pinfo.number then
            ti:add(pf.offer_in, l.offer):set_generated()
            ti:add(pf.delay, math.floor((l.answer_ts - l.offer_ts) * 10000 + 0.5) / 10):set_generated()
        elseif role == "offer" and l.answer and l.answer ~= pinfo.number then
            ti:add(pf.answer_in, l.answer):set_generated()
        end
    end

    local secs, sess = parse_sdp(rec.sdp)
    for _, v in ipairs(attr_values(secs, sess, "ice-ufrag")) do ti:add(pf.ice_ufrag, v) end
    for _, v in ipairs(attr_values(secs, sess, "ice-pwd")) do ti:add(pf.ice_pwd, v) end
    for _, v in ipairs(attr_values(secs, sess, "fingerprint")) do ti:add(pf.fingerprint, v) end
    for _, v in ipairs(attr_values(secs, sess, "setup")) do ti:add(pf.setup, v) end
    add_list(ti, "Candidates", pf.candidate, attr_values(secs, sess, "candidate"))

    -- mediaDescriptions overrides the SDP direction per mid
    local eff = {}
    for _, d in ipairs(tget(mc, "mediaDescriptions", "descriptions") or {}) do
        if type(d) == "table" and d.mid ~= nil then eff[tostring(d.mid)] = d.direction end
    end
    local mt = ti:add(sdp_teams, "Media sections (" .. #secs .. ")")
    for _, s in ipairs(secs) do
        local e = eff[s.mid]
        local dir = s.dir .. ((e and e ~= s.dir) and (" -> " .. e .. " (mediaDescriptions)") or "")
        local summary = string.format("mid %s: %s %s, %s%s", s.mid, s.kind, s.label, dir,
                                      s.ssrc_range and (", ssrc " .. s.ssrc_range) or "")
        local st = mt:add(pf.mid, summary)
        st:add(pf.mid_id, s.mid)
        st:add(pf.mid_kind, s.kind)
        st:add(pf.mid_label, s.label)
        st:add(pf.mid_dir, s.dir)
        if e then st:add(pf.mid_eff, tostring(e)) end
        if s.ssrc_range then st:add(pf.mid_ssrc, s.ssrc_range) end
        st:add(pf.mid_codecs, s.codecs)
    end
    add_list(ti, "Notes", pf.note, notes_for(rec, body))

    pinfo.cols.info:append(" [Teams SDP " .. role .. "]")
    local sdp_tvb = ByteArray.new(rec.sdp, true):tvb("Teams SDP " .. role)
    sdp_dissector:call(sdp_tvb, pinfo, tree)
end

-- Look for SDP in one decoded JSON document; returns number found
local function handle_json(obj, tree, range, pinfo, out)
    out = out or { sdps = {}, decoded = {} }
    if #out.sdps == 0 then find_sdps(obj, "", out, 0) end
    table.sort(out.sdps, function(a, b) return a.path < b.path end)
    for _, rec in ipairs(out.sdps) do
        -- the body shown for notes is the innermost decoded document containing the SDP
        local body = obj
        for _, d in ipairs(out.decoded) do
            if rec.path:sub(1, #d.path + 10) == d.path .. ".<decoded>" then body = d.value end
        end
        add_sdp(tree, range, pinfo, rec, body)
    end
    return #out.sdps
end

-- =====================================================================  Trouter
local function dissect_trouter(payload, range, pinfo, tree)
    local ftype, id, plus, rest = payload:match("^([0-8]):(%d*)(%+?):[^:]*:?(.*)$")
    if not ftype then return end
    local tt = tree:add(trouter, range)
    tt:add(tf.ftype, tonumber(ftype))
    if id ~= "" then tt:add(tf.id, id .. plus) end
    local obj = nil
    if rest:find("^%s*[{%[]") then
        local ok, v = pcall(json_decode, rest)
        if ok and type(v) == "table" then obj = v end
    end
    if not obj then
        tt:append_text(": " .. (SIO_TYPES[tonumber(ftype)] or ftype))
        return
    end

    local summary = SIO_TYPES[tonumber(ftype)] or ftype
    if type(obj.name) == "string" then
        tt:add(tf.event, obj.name)
        summary = summary .. " " .. obj.name
    end
    if type(obj.method) == "string" then tt:add(tf.method, obj.method) end
    if type(obj.url) == "string" then
        tt:add(tf.url, obj.url)
        local token, cb = obj.url:match("/callAgent/[^/]+/(%x%x%x%x%x%x%x%x)/(.-)/?$")
        if cb then
            tt:add(tf.token, token)
            tt:add(tf.callback, cb)
            summary = summary .. " " .. tostring(obj.method or "") .. " " .. cb
            pinfo.cols.info:append(" [Trouter " .. cb .. "]")
        end
    end
    if type(obj.status) == "number" then
        tt:add(tf.status, obj.status)
        summary = summary .. " status " .. obj.status
    end
    local chain = tget(obj, "headers", "X-Microsoft-Skype-Chain-ID")
    if type(chain) == "string" then tt:add(tf.chain, chain) end
    tt:append_text(": " .. summary)

    local out = { sdps = {}, decoded = {} }
    find_sdps(obj, "", out, 0)
    for _, d in ipairs(out.decoded) do
        if d.path == "body" then
            tt:add(tf.encoding, #d.enc > 0 and table.concat(d.enc, " -> ") or "plain JSON")
            json_dissector:call(ByteArray.new(d.text, true):tvb("Trouter body (decoded)"), pinfo, tt)
        end
    end
    handle_json(obj, tree, range, pinfo, out)
end

-- =====================================================================  dissector
function sdp_teams.dissector(tvb, pinfo, tree)
    for _, fi in ipairs({ f_ws() }) do
        local ok, raw = pcall(function() return fi.value:raw() end)
        if ok and raw and raw:find("^[0-8]:%d*%+?:") then
            dissect_trouter(raw, fi.range, pinfo, tree)
        end
    end

    -- HTTP/2: only DATA frames that complete a body - END_STREAM set or reassembled
    -- here. (http2.body.reassembled.in is only known on the second pass.)
    if not f_h2data() then return end
    local cur, frames = nil, {}
    for _, fi in ipairs({ all_field_infos() }) do
        local n = fi.name
        if n == "http2.stream" then
            cur = { chunks = {} }
            frames[#frames + 1] = cur
        elseif cur and (n == "http2.body.reassembled.data" or (n == "http2.flags.end_stream" and fi.value)) then
            cur.complete = true
        elseif cur and n == "http2.data.data" then
            cur.chunks[#cur.chunks + 1] = fi
        end
    end
    for _, fr in ipairs(frames) do
        if fr.complete then
            for _, fi in ipairs(fr.chunks) do
                local raw = fi.value:raw()
                -- Webex ROAP bodies are left to webrtc-sdp_in_webex.lua
                if (raw:find("v=0", 1, true) or raw:sub(1, 2) == "\31\139")
                        and not raw:find("roapMessage", 1, true) then
                    local obj = decode_any(raw)
                    if obj then
                        handle_json(obj, tree, fi.range, pinfo)
                    elseif raw:find("^%s*{") and raw:find('"blob"', 1, true) then
                        tree:add(sdp_teams, fi.range):add_proto_expert_info(ef_undecoded)
                    end
                end
            end
        end
    end
end

-- 'true' = ask for all fields, so the http2/websocket fields are available on every pass
register_postdissector(sdp_teams, true)
