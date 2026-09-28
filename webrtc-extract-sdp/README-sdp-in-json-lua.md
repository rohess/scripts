


## webrtc-sdp-in-json.lua
When capturing WebRTC signaling via WebSocket in GoTo, the SDP is packed as a long string in a JSON object. The plugin hooks into the Websocket JSON dissector, finds the SDP element and call the regular SDP dissector on it, so that its shown nicely formatted in the packet details.
The protocol display in packet list is expanded to show  ```WebSocket/JSON/SDP```

#### Install
```Preferences → Protocols → WebSocket → Dissect websocket text as → JSON```.

Copy webrtc-sdp_in_json.lua into your _Personal Lua Plugins_ folder.

```Help → About Wireshark → Folders``` reload with ```Analyze → Reload Lua```

> Tested on MacOS Tahoe Wireshark 4.6.8 with capture done on Windows


