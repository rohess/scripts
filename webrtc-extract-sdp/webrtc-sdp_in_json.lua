-- sdp_in_json.lua
-- Wireshark postdissector: finds SDP bodies carried as JSON strings
-- (WebRTC signalling over WebSocket / HTTP) and dissects them with the
-- built-in SDP dissector, so every line becomes its own tree item.
--
-- Requires WebSocket text to be dissected as JSON:
--   Preferences > Protocols > WebSocket > Dissect websocket text as: JSON
--
-- Install: copy to the "Personal Lua Plugins" folder
--   (Help > About Wireshark > Folders), then Analyze > Reload Lua Plugins.

local sdp_json = Proto("sdp_in_json", "SDP carried in JSON (WebRTC signalling)")

local f_json_str    = Field.new("json.value.string")
local sdp_dissector = Dissector.get("sdp")

-- Undo JSON string escaping, in case the JSON dissector hands us the raw form
local ESC = { n = "\n", r = "\r", t = "\t", ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }
local function unescape(s)
    if not s:find("\\", 1, true) then return s end
    return (s:gsub("\\(.)", function(c) return ESC[c] or ("\\" .. c) end))
end

function sdp_json.dissector(tvb, pinfo, tree)
    local n = 0
    for _, fi in ipairs({ f_json_str() }) do
        local s = tostring(fi.value)
        if s:sub(1, 3) == "v=0" then
            n = n + 1
            local sdp_tvb = ByteArray.new(unescape(s), true):tvb("SDP #" .. n)
            sdp_dissector:call(sdp_tvb, pinfo, tree)
        end
    end
end

-- 'true' = ask for all fields, so json.value.string is available on every pass
register_postdissector(sdp_json, true)
