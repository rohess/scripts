import GObject from 'gi://GObject';
import GLib from 'gi://GLib';
import St from 'gi://St';
import Clutter from 'gi://Clutter';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

// ---- tweakables -------------------------------------------------------
const REFRESH_SECONDS = 1;

// Interfaces whose names start with any of these are excluded from the sum.
// tun/tap/wg are skipped so VPN traffic isn't counted twice (the physical
// NIC already carries the encrypted version of the same bytes).
const IGNORED_PREFIXES = [
    'lo', 'virbr', 'docker', 'veth', 'br-', 'vboxnet',
    'vnet', 'tun', 'tap', 'wg', 'ifb', 'bond',
];

// Show speeds in bits/s instead of bytes/s
const USE_BITS = true;
// -----------------------------------------------------------------------

const DECODER = new TextDecoder();

function isIgnored(iface) {
    return IGNORED_PREFIXES.some(p => iface.startsWith(p));
}

function formatRate(bytesPerSec) {
    let value = USE_BITS ? bytesPerSec * 8 : bytesPerSec;
    const units = USE_BITS
        ? ['b/s', 'kb/s', 'Mb/s', 'Gb/s']
        : ['B/s', 'kB/s', 'MB/s', 'GB/s'];

    let i = 0;
    while (value >= 1000 && i < units.length - 1) {
        value /= 1000;
        i++;
    }

    const digits = (i === 0 || value >= 100) ? 0 : 1;
    return `${value.toFixed(digits)} ${units[i]}`;
}

const NetSpeedIndicator = GObject.registerClass(
class NetSpeedIndicator extends PanelMenu.Button {
    _init() {
        // third arg `true` = don't create a popup menu; the button is purely
        // informational, so clicking it shouldn't open an empty dropdown.
        super._init(0.0, 'Network Activity', true);

        this._box = new St.BoxLayout({
            style_class: 'netspeed-box',
            y_align: Clutter.ActorAlign.CENTER,
        });

        this._downLabel = new St.Label({
            style_class: 'netspeed-label',
            y_align: Clutter.ActorAlign.CENTER,
            text: '↓ —',
        });
        this._upLabel = new St.Label({
            style_class: 'netspeed-label',
            y_align: Clutter.ActorAlign.CENTER,
            text: '↑ —',
        });

        this._box.add_child(this._downLabel);
        this._box.add_child(this._upLabel);
        this.add_child(this._box);

        this._lastDown = 0;
        this._lastUp = 0;
        this._lastTime = 0;
        this._timeoutId = null;

        // Prime the counters so the first displayed value isn't a huge spike.
        this._sample();
        this._start();
    }

    _start() {
        this._timeoutId = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT,
            REFRESH_SECONDS,
            () => {
                this._update();
                return GLib.SOURCE_CONTINUE;
            }
        );
    }

    /** Returns [totalRxBytes, totalTxBytes] across all non-ignored interfaces. */
    _sample() {
        let down = 0;
        let up = 0;

        try {
            const [ok, contents] = GLib.file_get_contents('/proc/net/dev');
            if (!ok)
                return [this._lastDown, this._lastUp];

            const lines = DECODER.decode(contents).split('\n');
            for (const line of lines) {
                const colon = line.indexOf(':');
                if (colon < 0)
                    continue;

                const iface = line.slice(0, colon).trim();
                if (!iface || isIgnored(iface))
                    continue;

                const f = line.slice(colon + 1).trim().split(/\s+/);
                // /proc/net/dev column layout:
                // rx: bytes packets errs drop fifo frame compressed multicast
                // tx: bytes packets errs drop fifo colls carrier compressed
                down += Number.parseInt(f[0], 10) || 0;
                up += Number.parseInt(f[8], 10) || 0;
            }
        } catch (e) {
            logError(e, 'netspeed: failed reading /proc/net/dev');
            return [this._lastDown, this._lastUp];
        }

        return [down, up];
    }

    _update() {
        const now = GLib.get_monotonic_time(); // microseconds
        const [down, up] = this._sample();

        if (this._lastTime > 0) {
            const elapsed = (now - this._lastTime) / 1e6;
            if (elapsed > 0) {
                // Counters can reset (interface down, 32-bit wrap) — clamp.
                const dRate = Math.max(0, down - this._lastDown) / elapsed;
                const uRate = Math.max(0, up - this._lastUp) / elapsed;

                this._downLabel.text = `↓ ${formatRate(dRate)}`;
                this._upLabel.text = `↑ ${formatRate(uRate)}`;
            }
        }

        this._lastDown = down;
        this._lastUp = up;
        this._lastTime = now;
    }

    destroy() {
        if (this._timeoutId) {
            GLib.Source.remove(this._timeoutId);
            this._timeoutId = null;
        }
        super.destroy();
    }
});

export default class NetworkActivityExtension extends Extension {
    enable() {
        this._indicator = new NetSpeedIndicator();
        // index 0 in the 'right' box puts it just left of the quick settings.
        Main.panel.addToStatusArea(this.uuid, this._indicator, 0, 'right');
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}
