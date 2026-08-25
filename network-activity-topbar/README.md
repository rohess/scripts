# Network Activity (GNOME Shell extension)

Shows live upload/download speed in the GNOME top bar, read from `/proc/net/dev`.

## Install

```bash
git clone https://github.com/<you>/netspeed@local.git \
  ~/.local/share/gnome-shell/extensions/netspeed@local
gnome-extensions enable netspeed@local
```

On X11, reload with `Alt+F2` → `r`. On Wayland, log out and back in first.

## Configuration

Edit the constants at the top of `extension.js`:

- `REFRESH_SECONDS` — update interval
- `IGNORED_PREFIXES` — interface name prefixes excluded from the total (VPNs, bridges, etc.)
- `USE_BITS` — show Mb/s instead of MB/s

## Debugging

```bash
journalctl -f -o cat /usr/bin/gnome-shell
```
