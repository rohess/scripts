-- webrtc-sdp_in_meet.lua
-- Wireshark postdissector for Google Meet signalling. Meet never sends SDP on
-- the wire: the browser's offer and the SFU's answer travel as protobuf in one
-- HTTP/2 call,
--   /$rpc/google.rtc.meetings.v1.MediaSessionService/CreateMediaSession
-- This plugin decodes both bodies, renders them as approximate SDP (same
-- mapping as meet-extract-sdp.py) and dissects that with the built-in SDP
-- dissector, so every line becomes its own tree item and sdp.* filters work.
--
-- Requires decrypted TLS (key log file or pcapng with embedded secrets) and
-- the default HTTP/2 preferences (body reassembly and decompression).
--
-- Install: copy to the "Personal Lua Plugins" folder
--   (Help > About Wireshark > Folders), then Analyze > Reload Lua Plugins.
--
-- Filters:  sdp_in_meet              sdp_in_meet.type == "answer"
--           sdp_in_meet.candidate    sdp_in_meet.datachannel.label == "dcrpc"
--
-- Protobuf field meanings are reverse-engineered from one capture. Guesses
-- are listed under "Notes" instead of as comments inside the SDP.

local sdp_meet = Proto("sdp_in_meet", "SDP from Google Meet protobuf (CreateMediaSession)")

local SETUP      = { [1] = "active", [2] = "passive", [3] = "actpass" }  -- guess
local CAND_PROTO = { [1] = "udp", [2] = "tcp", [3] = "ssltcp" }
local MEDIA      = { [1] = "audio", [2] = "video" }

local pf = {
    type        = ProtoField.string("sdp_in_meet.type", "Type"),
    session     = ProtoField.string("sdp_in_meet.session", "Media session"),
    ice_ufrag   = ProtoField.string("sdp_in_meet.ice_ufrag", "ICE ufrag"),
    ice_pwd     = ProtoField.string("sdp_in_meet.ice_pwd", "ICE pwd"),
    fingerprint = ProtoField.string("sdp_in_meet.fingerprint", "DTLS fingerprint"),
    setup       = ProtoField.uint32("sdp_in_meet.setup", "DTLS setup (protobuf value)", base.DEC, SETUP),
    candidate   = ProtoField.string("sdp_in_meet.candidate", "Candidate"),
    dc          = ProtoField.string("sdp_in_meet.datachannel", "Data channel"),
    dc_label    = ProtoField.string("sdp_in_meet.datachannel.label", "Label"),
    dc_id       = ProtoField.uint16("sdp_in_meet.datachannel.stream_id", "SCTP stream id"),
    note        = ProtoField.string("sdp_in_meet.note", "Note"),
    unmapped    = ProtoField.string("sdp_in_meet.unmapped", "Unmapped field"),
}
sdp_meet.fields = { pf.type, pf.session, pf.ice_ufrag, pf.ice_pwd, pf.fingerprint, pf.setup,
                    pf.candidate, pf.dc, pf.dc_label, pf.dc_id, pf.note, pf.unmapped }

local ef_undecoded = ProtoExpert.new("sdp_in_meet.undecoded", "CreateMediaSession body could not be decoded",
                                     expert.group.UNDECODED, expert.severity.WARN)
sdp_meet.experts = { ef_undecoded }

local f_uri         = Field.new("http2.request.full_uri")
local f_data        = Field.new("http2.data.data")
local sdp_dissector = Dissector.get("sdp")

local URI_MARK = "CreateMediaSession"

-- =====================================================================  protobuf (decode_raw)
-- A message is an array of { f = field number, t = "int"|"str"|"bytes"|"msg", v = value }.
-- Integer arithmetic only (no bit operators), so it runs on Lua 5.2 and 5.4.

local function varint(s, i)
    local n, mult = 0, 1
    for _ = 1, 10 do
        local b = s:byte(i)
        if not b then break end
        i = i + 1
        n = n + (b % 128) * mult
        if b < 128 then return n, i end
        mult = mult * 128
    end
    error("bad varint")
end

local function printable(s)
    if s:find("[\0-\31\127]") or s:find("\194[\128-\159]") then return false end
    return not utf8 or utf8.len(s) ~= nil
end

local function parse_pb(s)
    local out, i, len = {}, 1, #s
    while i <= len do
        local tag
        tag, i = varint(s, i)
        local f, wt = math.floor(tag / 8), tag % 8
        if f == 0 then error("field 0") end
        local e = { f = f }
        if wt == 0 then
            e.t = "int"
            e.v, i = varint(s, i)
        elseif wt == 1 or wt == 5 then
            local n = wt == 1 and 8 or 4
            if i + n - 1 > len then error("short fixed") end
            local v, m = 0, 1
            for j = 0, n - 1 do v = v + s:byte(i + j) * m; m = m * 256 end
            e.t, e.v, i = "int", v, i + n
        elseif wt == 2 then
            local ln
            ln, i = varint(s, i)
            if i + ln - 1 > len then error("short len") end
            local chunk = s:sub(i, i + ln - 1)
            i = i + ln
            if printable(chunk) then
                e.t, e.v = "str", chunk
            else
                local ok, m = pcall(parse_pb, chunk)
                if ok then e.t, e.v = "msg", m else e.t, e.v = "bytes", chunk end
            end
        else
            error("wire type " .. wt)
        end
        out[#out + 1] = e
    end
    return out
end

-- first value of field f (or default), plus its type
local function get(m, f, default)
    for _, e in ipairs(m or {}) do
        if e.f == f then return e.v, e.t end
    end
    return default
end

-- first submessage f, or {} if absent / not a message
local function sub(m, f)
    for _, e in ipairs(m or {}) do
        if e.f == f then return e.t == "msg" and e.v or {} end
    end
    return {}
end

-- all submessages with field number f
local function getall(m, f)
    local out = {}
    for _, e in ipairs(m or {}) do
        if e.f == f and e.t == "msg" then out[#out + 1] = e.v end
    end
    return out
end

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function packed_varints(s)
    local out, i = {}, 1
    while i <= #s do
        local ok, v, ni = pcall(varint, s, i)
        if not ok then break end
        out[#out + 1], i = tostring(v), ni
    end
    return table.concat(out, ", ")
end

local function fmt_value(e)
    if e.t == "str" then return '"' .. e.v .. '"' end
    if e.t == "bytes" then return "0x" .. hex(e.v) end
    if e.t == "msg" then
        local parts = {}
        for _, c in ipairs(e.v) do parts[#parts + 1] = c.f .. "=" .. fmt_value(c) end
        return "{" .. table.concat(parts, ", ") .. "}"
    end
    return tostring(e.v)
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

-- gunzip / base64 until we have something that should parse as protobuf
local function unwrap(s)
    for _ = 1, 4 do
        if s:find(B64) then s = s:match("^%s*(.-)%s*$") end
        if s:sub(1, 2) == "\31\139" then
            s = gunzip(s)
        elseif #s > 16 and s:find(B64) then
            s = s:gsub("%s", ""):gsub("%-", "+"):gsub("_", "/")
            s = s .. string.rep("=", (4 - #s % 4) % 4)
            s = ByteArray.new(s, true):base64_decode():raw()
        else
            break
        end
    end
    return s
end

-- Try the concatenated DATA payloads first, then each one alone (largest first)
local function body_to_message(chunks)
    local cands = {}
    if #chunks > 1 then cands[1] = table.concat(chunks) end
    local sorted = { table.unpack(chunks) }
    table.sort(sorted, function(a, b) return #a > #b end)
    for _, c in ipairs(sorted) do cands[#cands + 1] = c end
    for _, c in ipairs(cands) do
        local ok, msg = pcall(function() return parse_pb(unwrap(c)) end)
        if ok and #msg > 0 then return msg end
    end
end

-- =====================================================================  SDP rendering
-- Returns the SDP text plus the extracted values/notes for the tree.
local function render(desc, cand_field, codec_field, ext_field, dc_field)
    local r = { notes = {}, cands = {}, dcs = {} }
    local function note(s) r.notes[#r.notes + 1] = s end

    local tr, ice = sub(desc, 1), sub(desc, 2)
    local fp = sub(tr, 1)
    r.ice_ufrag, r.ice_pwd, r.setup = get(ice, 3), get(ice, 4), get(tr, 2)
    r.fingerprint = tostring(get(fp, 1)) .. " " .. tostring(get(fp, 2))
    local transport = {
        "a=ice-ufrag:" .. tostring(r.ice_ufrag),
        "a=ice-pwd:" .. tostring(r.ice_pwd),
        "a=fingerprint:" .. r.fingerprint,
        "a=setup:" .. (SETUP[r.setup] or "?"),
    }
    note(string.format("a=setup:%s from protobuf value %s (mapping guessed)", SETUP[r.setup] or "?", tostring(r.setup)))

    local cands = {}
    for i, c in ipairs(cand_field and getall(desc, cand_field) or {}) do
        local proto = CAND_PROTO[get(c, 1)] or "?"
        cands[#cands + 1] = string.format("a=candidate:%d %s %s %s %s %s typ host%s", i, tostring(get(c, 5, 1)),
                                          proto, tostring(get(c, 4)), tostring(get(c, 2)), tostring(get(c, 3)),
                                          proto == "tcp" and " tcptype passive" or "")
        r.cands[#r.cands + 1] = string.format("%-6s %s:%s  prio %s", proto, tostring(get(c, 2)),
                                              tostring(get(c, 3)), tostring(get(c, 4)))
        if proto == "ssltcp" then note("a=candidate:" .. i .. " ssltcp = TLS fallback") end
    end
    if #cands > 0 then
        cands[#cands + 1] = "a=ice-lite"
        note("a=ice-lite implied: host candidates only, server sends no checks")
    end

    local body, mids = {}, {}
    local function add(s) body[#body + 1] = s end
    local function addall(t) for _, s in ipairs(t) do add(s) end end

    local codecs, exts = getall(desc, codec_field), getall(desc, ext_field)
    for _, mk in ipairs({ { 0, 1 }, { 1, 2 } }) do
        local mid, kind = mk[1], mk[2]
        local cs, pts = {}, {}
        for _, c in ipairs(codecs) do
            if get(c, 3) == kind then cs[#cs + 1] = c; pts[#pts + 1] = tostring(get(c, 1)) end
        end
        if #cs > 0 then
            mids[#mids + 1] = mid
            add("m=" .. MEDIA[kind] .. " 9 UDP/TLS/RTP/SAVPF " .. table.concat(pts, " "))
            add("c=IN IP4 0.0.0.0")
            addall(transport)
            addall(cands)
            add("a=mid:" .. mid)
            for _, e in ipairs(exts) do
                if get(e, 3) == kind then
                    local uri = tostring(get(e, 2))
                    if get(e, 4) == 2 then uri = "urn:ietf:params:rtp-hdrext:encrypt " .. uri end
                    add("a=extmap:" .. tostring(get(e, 1)) .. " " .. uri)
                end
            end
            add("a=sendrecv")
            add("a=rtcp-mux")
            if kind == 2 then add("a=rtcp-rsize") end
            for _, c in ipairs(cs) do
                local pt, name, clock, ch = get(c, 1), get(c, 2), get(c, 4), get(c, 5)
                local chs = (kind == 1 and type(ch) == "number" and ch > 1) and ("/" .. ch) or ""
                add(string.format("a=rtpmap:%s %s/%s%s", tostring(pt), tostring(name), tostring(clock), chs))
                local params = {}
                for _, p in ipairs(getall(c, 6)) do
                    local k, v = tostring(get(p, 1, "")), tostring(get(p, 2, ""))
                    params[#params + 1] = k == "" and v or (k .. "=" .. v)
                end
                if #params > 0 then add("a=fmtp:" .. tostring(pt) .. " " .. table.concat(params, ";")) end
                local ns = {}
                if get(c, 7) ~= nil then
                    ns[#ns + 1] = "flag 7=" .. tostring(get(c, 7)) .. " (2nd codec set - screenshare/alt profile?)"
                end
                if get(c, 8) ~= nil or get(c, 9) ~= nil then
                    ns[#ns + 1] = "fields 8/9 present (probably rtcp-fb set)"
                end
                if #ns > 0 then note("pt " .. tostring(pt) .. ": " .. table.concat(ns, "; ")) end
            end
        end
    end

    local dcs = getall(desc, dc_field)
    if #dcs > 0 then
        mids[#mids + 1] = 2
        add("m=application 9 UDP/DTLS/SCTP webrtc-datachannel")
        add("c=IN IP4 0.0.0.0")
        addall(transport)
        add("a=mid:2")
        add("a=sctp-port:5000")
        note("a=sctp-port:5000 assumed; data channels are pre-negotiated (see Data channels)")
        for _, d in ipairs(dcs) do
            local attrs = {}
            for _, fl in ipairs({ { 3, "stream-id" }, { 5, "maxPacketLifeTime?ms" }, { 6, "maxRetransmits?" },
                                  { 2, "f2" }, { 4, "f4" } }) do
                local v = get(d, fl[1])
                if v ~= nil then attrs[#attrs + 1] = fl[2] .. "=" .. tostring(v) end
            end
            r.dcs[#r.dcs + 1] = { label = tostring(get(d, 1)), id = get(d, 3), attrs = table.concat(attrs, " ") }
        end
    end

    local L = { "v=0", "o=- 0 2 IN IP4 127.0.0.1", "s=-", "t=0 0" }
    if #mids > 0 then
        L[#L + 1] = "a=group:BUNDLE " .. table.concat(mids, " ")
        note("a=group:BUNDLE assumed: single transport for everything")
    end
    L[#L + 1] = "a=msid-semantic: WMS"
    for _, s in ipairs(body) do L[#L + 1] = s end
    r.sdp = table.concat(L, "\r\n") .. "\r\n"
    return r
end

local function extras(desc, known)
    local out = {}
    for _, e in ipairs(desc) do
        if not known[e.f] then
            if e.t == "bytes" then
                out[#out + 1] = string.format("field %d: bytes %s (as packed varints: %s)", e.f, hex(e.v),
                                              packed_varints(e.v))
            else
                out[#out + 1] = string.format("field %d: %s", e.f, fmt_value(e))
            end
        end
    end
    return out
end

-- Request: 1 { 3 { offer } }.  Response: 1: "mediasessions/...", 2 { answer }
local function interpret(msg)
    local session, t = get(msg, 1)
    if t == "str" and #sub(msg, 2) > 0 then
        local ans = sub(msg, 2)
        return "answer", session, render(ans, 3, 4, 5, 12), extras(ans, { [1]=1, [2]=1, [3]=1, [4]=1, [5]=1, [12]=1 })
    end
    local offer = sub(sub(msg, 1), 3)
    if #offer == 0 then offer = #sub(msg, 3) > 0 and sub(msg, 3) or msg end
    return "offer", nil, render(offer, nil, 3, 4, 17), extras(offer, { [1]=1, [2]=1, [3]=1, [4]=1, [17]=1 })
end

-- =====================================================================  dissector
-- Group fields per HTTP/2 frame (each starts with http2.stream), so bodies are
-- matched with their own request URI when one TCP segment carries several streams.
local function h2_frames()
    local frames, cur = {}, nil
    for _, fi in ipairs({ all_field_infos() }) do
        local n = fi.name
        if n == "http2.stream" then
            cur = { chunks = {}, ranges = {} }
            frames[#frames + 1] = cur
        elseif cur and n == "http2.data.data" then
            cur.chunks[#cur.chunks + 1] = fi.value:raw()
            cur.ranges[#cur.ranges + 1] = fi.range
        elseif cur and n == "http2.request.full_uri" then
            cur.uri = tostring(fi.value)
        end
    end
    return frames
end

local function add_list(tree, label, field, items)
    if #items == 0 then return end
    local t = tree:add(sdp_meet, label .. " (" .. #items .. ")")
    for _, s in ipairs(items) do t:add(field, s) end
end

function sdp_meet.dissector(tvb, pinfo, tree)
    if not f_data() then return end
    local hit = false
    for _, fi in ipairs({ f_uri() }) do
        if tostring(fi.value):find(URI_MARK, 1, true) then hit = true; break end
    end
    if not hit then return end

    for _, fr in ipairs(h2_frames()) do
        if fr.uri and fr.uri:find(URI_MARK, 1, true) and #fr.chunks > 0 then
            local range = fr.ranges[#fr.ranges]
            local ti = range and tree:add(sdp_meet, range) or tree:add(sdp_meet)
            local msg = body_to_message(fr.chunks)
            if not msg then
                ti:add_proto_expert_info(ef_undecoded)
            else
                local kind, session, r, unmapped = interpret(msg)
                ti:append_text(": " .. kind .. (session and (" (" .. session .. ")") or ""))
                ti:add(pf.type, kind):set_generated()
                if session then ti:add(pf.session, session) end
                if r.ice_ufrag then ti:add(pf.ice_ufrag, tostring(r.ice_ufrag)) end
                if r.ice_pwd then ti:add(pf.ice_pwd, tostring(r.ice_pwd)) end
                ti:add(pf.fingerprint, r.fingerprint)
                if type(r.setup) == "number" then ti:add(pf.setup, r.setup) end
                add_list(ti, "Candidates", pf.candidate, r.cands)
                if #r.dcs > 0 then
                    local dt = ti:add(sdp_meet, "Data channels (" .. #r.dcs .. ", pre-negotiated)")
                    for _, d in ipairs(r.dcs) do
                        local di = dt:add(pf.dc, string.format("%-20s %s", d.label, d.attrs))
                        di:add(pf.dc_label, d.label)
                        if type(d.id) == "number" then di:add(pf.dc_id, d.id) end
                    end
                end
                add_list(ti, "Notes", pf.note, r.notes)
                add_list(ti, "Protobuf fields with no SDP equivalent", pf.unmapped, unmapped)

                pinfo.cols.info:append(" [Meet SDP " .. kind .. "]")
                local sdp_tvb = ByteArray.new(r.sdp, true):tvb("Meet SDP " .. kind)
                sdp_dissector:call(sdp_tvb, pinfo, tree)
            end
        end
    end
end

-- 'true' = ask for all fields, so the http2 fields are available on every pass
register_postdissector(sdp_meet, true)
