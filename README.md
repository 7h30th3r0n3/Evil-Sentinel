<div align="center">

# Evil-Sentinel

**A DIY parallel 2.4 GHz WiFi capture array built from spare ESP32 boards.**

Lock one ESP32 per channel, stream every node over USB, merge the streams live into one Wireshark timeline. Inspired by the [Hak5 WiFi Coconut](https://shop.hak5.org/products/wifi-coconut), fully passive, in pure Python with no external dependencies.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/firmware-ESP32--C3%20%7C%20C5%20%7C%20C6%20%7C%20S3-informational)
![Host](https://img.shields.io/badge/host-Linux%20%7C%20stdlib%20Python-success)
![Mode](https://img.shields.io/badge/radio-100%25%20passive-brightgreen)

</div>

---

## Get started in 5 minutes

1. **Flash** a node, no toolchain needed. Easiest path: open the web flasher in Chrome or Edge,
   pick your board under **Evil-Sentinel**, and click Install:
   [**7h30th3r0n3.github.io/Evil-Flasher**](https://7h30th3r0n3.github.io/Evil-Flasher/).
   It flashes a full image over USB, one board or ten, same firmware. (Command-line alternative:
   grab `sentinel-<chip>.bin` from the latest
   [release](https://github.com/7h30th3r0n3/Evil-Sentinel/releases) and
   `esptool --port /dev/ttyACM0 write-flash 0x10000 sentinel-c3.bin`.)
2. **Plug** the nodes into a powered USB hub, and the hub into your machine (or phone).
3. **Capture.** On a computer: `./tools/sentinel.py` finds the nodes, assigns channels, and
   opens Wireshark. On Android: open the Evil-Sentinel app. That is the whole flow.

![capture demo](docs/demo.gif) <!-- TODO: drop a short capture GIF here -->

## Why

A single WiFi radio can only sit on one channel at a time. To watch the whole 2.4 GHz band it has to hop, and while it is parked on channel 6 it is deaf to everything on 1 and 11. You miss frames.

The fix is one radio per channel, all listening at once. Evil-Sentinel does this with the ESP32 boards you already have in a drawer: each board locks to a single channel, never hops, and streams its captured frames as pcap over its native USB-CDC. One host process merges every stream into a single timeline and hands it to Wireshark. The result is full-band 2.4 GHz coverage with no channel-hop blind spots.

Each node can also run in hopping mode on its own, so a single board is still a useful standalone full-band sniffer.

## Architecture

```
  ch 1   ESP32-C3 ─┐
  ch 6   ESP32-C3 ─┤                             ┌── live dashboard (curses TUI)
  ch 11  ESP32-C3 ─┼─ powered USB hub ─ USB ─ host ─ sentinel.py ─┤
  ch 13  ESP32-C5 ─┤                             └── merged pcap ─ FIFO ─ Wireshark
  hop    ESP32-C5 ─┘
   (one radio each,         (90 mA/board,          (one process owns every port,
    locked, no hop)          a cheap hub is fine)   no multi-process contention)
```

Every node is 100% passive: it only puts the radio in promiscuous RX mode and listens. Nothing is ever transmitted, no deauth, no injection, no jamming.

## Build the rig

You only need boards, a powered hub, and one cable. Below is the exact kit this project is built and tested on, so you can order it and go. The shop links are affiliate/referral links: they cost you nothing extra and help fund the project.

### Bill of materials

| Part | Role in the rig | Buy |
|------|-----------------|-----|
| **Powered 7-port USB 3.0 hub** (pick the 7-port model) | The backbone: powers and multiplexes every node onto one host port. Start here. | [AliExpress](https://s.click.aliexpress.com/e/_c4pHCJRv) |
| **M5StampC5** (ESP32-C5) | Dual-band node: adds 5 GHz capture, lock a channel or sweep `hop5`. | [M5Stack](https://shop.m5stack.com/products/m5stampc5-module-esp32-c5?ref=7h30th3r0n3) |
| **ESP32-C3 SuperMini**, external antenna (4-pack) | 2.4 GHz capture nodes, one per channel. Cheapest way to fill 1/6/11 and spread. | [AliExpress](https://s.click.aliexpress.com/e/_c3d5vI1D) |
| **M5Stack NanoC6** (ESP32-C6) | The smallest board in the array, a tidy 2.4 GHz node. | [M5Stack](https://shop.m5stack.com/products/m5stack-nanoc6-dev-kit?ref=7h30th3r0n3) |
| **USB-C to USB-C cable** (male/male) | Hub to a USB-C host: laptop or phone. | [AliExpress](https://s.click.aliexpress.com/e/_c4a3XJxZ) |
| **USB-A 3.0 to USB-C adapter** (male/male) | Hub to a USB-A host, when your machine has no USB-C. | [AliExpress](https://s.click.aliexpress.com/e/_c3c8NZV5) |

### Suggested starter rig

- **1x powered 7-port hub** + the cable or adapter that matches your host
- **4x M5StampC5** -> dual-band: lock 4 distinct 5 GHz channels (e.g. 36 / 44 / 149 / 157) for parallel 5 GHz coverage, or `hop5` to sweep the band
- **3x ESP32-C3 SuperMini** -> lock 2.4 GHz channels 1 / 6 / 11 = full 2.4 GHz coverage

Seven nodes fill the 7-port hub exactly: a complete dual-band array that watches 2.4 and 5 GHz in parallel. Add or swap boards on the spare ports any time; the controller picks them up automatically.

### Notes

- Each board draws about 90 mA at 5 V, so a powered 7-port hub carries a full set comfortably. Always power the hub; do not rely on a bare laptop port to feed a full array.
- The C3 and C6 are 2.4 GHz only; the C5 is dual-band and adds 5 GHz. Any mix works, the controller is band-aware.
- An ESP32 cannot be the hub itself: multiplexing several USB devices onto one host port needs a real hub controller IC (FE1.1s, CH334, USB2517), not GPIO. Use a standard powered hub.
- Host: any Linux laptop, mini PC, or Raspberry Pi (through the hub), or an Android phone over USB-C.

> **Affiliate note.** The shop links above are affiliate/referral links. Buying through them supports Evil-Sentinel at no extra cost to you. You are free to source the same parts anywhere.

## Quick start

### 1. Flash the firmware

**Easiest, no toolchain: the web flasher.** Open
[**7h30th3r0n3.github.io/Evil-Flasher**](https://7h30th3r0n3.github.io/Evil-Flasher/) in Chrome or
Edge (desktop; Web Serial), pick your board under the **Evil-Sentinel** group (M5StampC5 / ESP32-C3
SuperMini / M5 NanoC6), plug it in, and click Install. It writes a full flash image over USB, no
drivers or toolchain. One firmware fits every board; the host picks lock-or-hop at runtime.

**Command line alternative.** Grab the matching `sentinel-<chip>.bin` from the latest
[release](https://github.com/7h30th3r0n3/Evil-Sentinel/releases) and write it with esptool:

```bash
esptool --port /dev/ttyACM0 write-flash 0x10000 sentinel-c5.bin   # or sentinel-c3.bin / sentinel-c6.bin
```

**From source** (Arduino IDE or arduino-cli), building `firmware/sentinel_sniffer`:

```bash
# ESP32-C3 / C6 (native USB; CDC-on-boot)
arduino-cli compile --fqbn esp32:esp32:esp32c3:CDCOnBoot=cdc firmware/sentinel_sniffer
arduino-cli upload  --fqbn esp32:esp32:esp32c3:CDCOnBoot=cdc -p /dev/ttyACM0 firmware/sentinel_sniffer

# ESP32-C5 needs arduino-esp32 core 3.1+
arduino-cli compile --fqbn esp32:esp32:esp32c5:CDCOnBoot=cdc firmware/sentinel_sniffer
```

A freshly flashed board boots in hopping mode, so it is immediately useful on its own.

### 2. Run the controller

```bash
cd tools
./sentinel.py                    # auto-detect nodes, auto-assign channels, launch Wireshark
```

That is the whole flow. `sentinel.py` probes `/dev/serial/by-id`, finds every node, and by default leaves each one hopping (2.4 nodes sweep 2.4 GHz, a dual-band C5 sweeps 5 GHz), so you get full-band coverage out of the box. Pass `--channels` to lock one channel per node for simultaneous no-blind-spot capture (for example `--channels 1,6,11,hop5`). Either way it opens a live dashboard and merges all streams into Wireshark through a named pipe. You can also retune any node live from the dashboard (`c` in the TUI, or the per-node selector in `--web`).

```
⬢ EVIL-SENTINEL      4 nodes      137 f/s      28431 frames      up 3m12s      [q]uit
────────────────────────────────────────────────────────────────────────────────
2.4 GHz BAND  (total packets)
  ██    ██          ██
  ██    ██          ██          ░░
  ██    ██    ░░    ██          ░░
   1  2  3  4  5  6  7  8  9 10 11 12 13
NODES
34:CD:B0:E9:67:30   ch1    58 f/s     12044  ██████████░░░░░░  ▃▄▅▇▆▄▃▂
3C:DC:75:F5:A0:xx   ch6    41 f/s      9881  ████████░░░░░░░░  ▂▃▄▅▄▃▄▅
...
```

### Other modes

```bash
./sentinel.py --watch                 # wait for nodes to appear, then auto-start (plug-and-go)
./sentinel.py --list                  # list detected nodes and exit
./sentinel.py --channels 1,6,11,hop5  # force assignment (order follows sorted nodes)
./sentinel.py --no-wireshark          # dashboard only, no GUI
./sentinel.py --seconds 30            # headless, print per-node totals after 30 s
./sentinel.py --web --port 8808       # styled web dashboard instead of the TUI
./sentinel.py --pipe                  # merged pcap on a named pipe (--fifo path), no GUI
./sentinel.py --stdout > capture.pcap # merged pcap on stdout, logs on stderr
./sentinel.py --install-extcap        # register the Wireshark extcap, then exit
```

## Two ways into Wireshark

**Controller (recommended).** `sentinel.py` owns every serial port in one process and merges all nodes into a single pipe. No port contention, plus the live dashboard. This is the default path.

**Native extcap.** `tools/sentinel-extcap.py` registers each board as its own Wireshark capture interface. Drop it in your extcap directory, tick the boards you want, and start. Each interface exposes a channel option (1-14 locks a channel, 0 hops). Good when you want Wireshark to drive the capture directly. See `docs/WIRESHARK.md`.

## Feed other tools (Kismet, aircrack-ng, airodump-ng, bettercap, tcpdump)

The merged stream is ordinary `LINKTYPE_IEEE802_11_RADIOTAP` pcap, so any tool that reads pcap can consume it, live from a pipe or from a saved file. The capture stays 100% passive and receive-only; this only changes where the frames go, it never transmits. Pass `--fcs off` for Kismet, aircrack-ng and bettercap (see the FCS note below).

**Live, on a named pipe.** `--pipe` writes the merged pcap to a FIFO (the `--fifo` path, default `/tmp/sentinel.pcap`) and waits for a reader, no GUI. Start it first so the pipe exists, then attach any reader in another shell:

```bash
./tools/sentinel.py --pipe --fcs off
# then, in another shell:
wireshark -k -i /tmp/sentinel.pcap
tshark    -l -r /tmp/sentinel.pcap          # -l = line buffered, redraws per frame
tcpdump   -r /tmp/sentinel.pcap
kismet -c '/tmp/sentinel.pcap:type=pcapfile'
sudo airodump-ng -r /tmp/sentinel.pcap      # the binary lives in /usr/sbin
```

**One-liners that start the rig and a tool together.** The FIFO ones background the rig, wait for the pipe, run the tool, then stop the rig on exit (Ctrl-C / `q`):

```bash
# airodump-ng live table
cd ~/cyber/dev/Evil-Sentinel && ./tools/sentinel.py --pipe --fcs off >/tmp/sentinel.log 2>&1 & until [ -p /tmp/sentinel.pcap ]; do sleep 0.3; done; sudo /usr/sbin/airodump-ng -r /tmp/sentinel.pcap; kill %1

# Kismet, then open http://localhost:2501
cd ~/cyber/dev/Evil-Sentinel && ./tools/sentinel.py --pipe --fcs off >/tmp/sentinel.log 2>&1 & until [ -p /tmp/sentinel.pcap ]; do sleep 0.3; done; kismet -c '/tmp/sentinel.pcap:type=pcapfile'; kill %1

# record 30 s, then list / crack with aircrack-ng
./tools/sentinel.py --stdout --fcs off --seconds 30 > /tmp/sentinel.pcap && aircrack-ng /tmp/sentinel.pcap

# straight into tshark or tcpdump (stdin, no FIFO needed)
./tools/sentinel.py --stdout --fcs off | tshark  -l -r -
./tools/sentinel.py --stdout --fcs off | tcpdump -nr -
```

**Pipe straight into another tool** with `--stdout` (raw pcap on stdout, every log line on stderr):

```bash
./tools/sentinel.py --stdout --fcs off | tshark -l -r -
./tools/sentinel.py --stdout --fcs off > capture.pcap    # or record a file, Ctrl-C when done
```

**aircrack-ng suite.** Point airodump-ng at the pipe or a file for the live AP/client table, and aircrack-ng / airdecap-ng at a saved capture:

```bash
airodump-ng -r /tmp/sentinel.pcap     # live recon table (BSSID, channel, ESSID, clients)
aircrack-ng capture.pcap              # list networks, or crack a captured handshake
```

**bettercap** reads a pcap instead of a monitor interface with `wifi.source.file` (bettercap needs root):

```bash
./tools/sentinel.py --pipe --fcs off
sudo bettercap -eval "set wifi.source.file /tmp/sentinel.pcap; wifi.recon on; events.stream on"
```

This is recon only: bettercap sees the networks, clients, handshakes and PMKIDs, but its active features (deauth, association) never go out through the rig, which does not transmit.

### Notes and gotchas

- **FCS: use `--fcs off` for Kismet, aircrack-ng and bettercap.** The ESP32 reports a trailing FCS that does not verify, and these tools silently drop frames whose FCS fails to check, so with the default (`--fcs on`) they ingest packets but build zero devices. `--fcs off` makes each node strip the FCS and clear the radiotap flag, so every frame is accepted. Wireshark, tshark and tcpdump do not care either way.
- **Kismet** needs no special privileges to read a pcap: its `pcapfile` helper is world-executable, the `kismet` group is only for live wifi capture (which Sentinel does not do). Always pass `type=pcapfile` in single quotes: it selects the right helper straight away and stops zsh from eating `:type` as a `:t` modifier. Start `--pipe` before Kismet so the FIFO exists. Verified on a 7-node rig building ~90 access points live in the Kismet web UI at http://localhost:2501.
- **Kismet is the one with a working web dashboard.** bettercap's web UI expects a live interface and crashes on a pcap source (`wifi.state.channels is null`), so drive bettercap from its CLI or REST API, not its UI. For a browser view of the rig, use Kismet.
- **airodump-ng refreshes in bursts (every 5 to 10 s), not once per second.** That is libpcap block-buffering its read of the pipe, not a capture gap; every frame is still recorded. For a per-frame live view use `tshark -l` or the Kismet UI.
- **airodump-ng lives in `/usr/sbin`**, so use the full path if it is not on your `PATH`. Reading a file with `-r` does not need root.

## Serial protocol

Each node speaks a tiny line protocol over USB-CDC, so you can drive a board by hand with any serial terminal:

| Command | Effect |
|---------|--------|
| `S` | start streaming pcap |
| `X` | stop streaming |
| `ch N\n` | lock to channel N (1-14 = 2.4 GHz, 36-165 = 5 GHz on the C5), stops hopping |
| `hop\n` | sweep 2.4 GHz |
| `hop5\n` | sweep 5 GHz (C5 only) |
| `hopdual\n` | sweep 2.4 + 5 GHz (C5 only) |
| `ping` | replies `pong` |
| `id` | replies `sentinel` (plus ` dualband` on the C5); used for auto-discovery |

The stream is `LINKTYPE_IEEE802_11_RADIOTAP` (127). Each frame carries a 15-byte radiotap header with the real RX channel (2.4 or 5 GHz) and RSSI, so Wireshark shows which channel every frame came from.

### Dual-band (ESP32-C5)

The C3 and C6 are 2.4 GHz only. The C5 is dual-band: it can lock a 5 GHz channel (36-165) or sweep 5 GHz / both bands. The firmware detects 5 GHz support at boot (it reports ` dualband` in `id`), and the band is chosen automatically by the channel number. On the desktop, pass 5 GHz channels or `hop5` / `hopdual` to `sentinel.py --channels` (for example `--channels 1,6,11,hop5`); in the Android app the 5 GHz options appear only on a dual-band node.

## Known limitation: cosmetic "malformed" beacons

The ESP32 reports `sig_len` including the 4-byte 802.11 FCS. Some Wireshark versions do not strip that trailing CRC before parsing information elements, so a fraction of beacons show a red "malformed" flag on a phantom trailing tag. This is cosmetic: all fields (SSID, BSSID, channel, security, RSSI) parse and read correctly. The firmware already flags "FCS at end" in the radiotap header; versions that honor it hide the warning. To mute it in the view:

```
!_ws.malformed
```

## Android app

The same capture in your pocket: plug the rig into the phone over USB-C, watch the per-channel
traffic live, export the merged pcap. It is `sentinel.py` as a native Android app (Kotlin +
Compose), using the ESP32 nodes as the radios, so no root and no phone-WiFi limits. Multi-node
from the start; a powered USB-C hub with PD passthrough feeds the rig. See [`android/`](android/).

## Layout

```
Evil-Sentinel/
├── firmware/sentinel_sniffer/sentinel_sniffer.ino   ESP32-C3/C5 passive sniffer (lock or hop)
├── tools/sentinel.py                               controller: discover, dashboard, merge to Wireshark
├── tools/sentinel-extcap.py                        Wireshark extcap (one interface per board)
├── android/                                        Android app (Kotlin/Compose): live capture + pcap export
└── docs/                                           hardware notes and Wireshark setup
```

## Legal

Evil-Sentinel is a passive receiver for authorized security testing, research, and education. It listens, it never transmits. You are responsible for complying with the laws of your jurisdiction on radio monitoring and the privacy of the networks around you. Capture only traffic you are authorized to capture.

## License

GPL-3.0-or-later. Copyright (c) 7h30th3r0n3. See [LICENSE](LICENSE).
