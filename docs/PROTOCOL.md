# Evil-Sentinel protocol

This is the single source of truth for the node protocol and the channel plan. The firmware,
the desktop tools (`sentinel.py`, `sentinel-extcap.py`) and the Android app all implement what
is described here; keep them in sync with this file.

## Transport

Each node is a USB-CDC serial device. Native-USB chips (ESP32-C3/C5/C6, VID `0x303a`) ignore
the baud rate; bridge chips (CP210x `0x10c4`, CH340/CH9102 `0x1a86`) use a real UART. The host
opens the port raw and takes an exclusive `flock` so only one process drives a node at a time.

The node's USB serial number is its MAC, so a node keeps a stable identity across replugs
(`/dev/serial/by-id/...<MAC>...`).

## Commands (host to node)

Line-oriented ASCII. Single-byte commands have no newline; word commands end with `\n`.

| Command | Meaning |
|---------|---------|
| `S` | start streaming pcap |
| `X` | stop streaming |
| `ch N\n` | lock channel N (1-14 = 2.4 GHz; 36-112 = 5 GHz, C5 only), stops hopping |
| `hop\n` | sweep 2.4 GHz (weighted 1/6/11) |
| `hop5\n` | sweep 5 GHz (C5 only) |
| `hopdual\n` | sweep 2.4 + 5 GHz (C5 only) |
| `fcs on\|off\n` | keep (on) or strip (off) the trailing 802.11 FCS |
| `ping\n` | node replies `pong` |
| `id\n` | node replies an identity line (see below) |
| `stat\n` | node replies a one-line health readout (see below) |

A node ignores a 5 GHz channel or a `hop5`/`hopdual` it cannot do (2.4-only chips).

## Replies (node to host)

Replies are single lines of space-separated ASCII tokens. Parsers match by substring/token so
the lines can grow without breaking older hosts.

- **id** - always begins with `sentinel`. A dual-band node also contains the token `dualband`.
  A richer form is allowed, for example: `sentinel v1 c5 2.4,5 up42`
  (name, firmware version, chip, bands, uptime seconds). Hosts must only rely on the substrings
  `sentinel` and `dualband`.
- **stat** - a health readout, for example: `stat drop=12 hiwater=48 sent=90213 up=42 ch=36`
  (dropped frames, queue high-water, frames sent, uptime, current channel/mode).
- **pong** - reply to `ping`.

Discovery: open the port, send `id\n`, and keep the device if the reply contains `sentinel`.

## pcap stream

After `S`, the node streams a classic pcap stream, link type `LINKTYPE_IEEE802_11_RADIOTAP`
(127):

- 24-byte global header (magic `0xa1b2c3d4`, snaplen, linktype 127).
- Per frame: a 16-byte record header (ts_sec, ts_usec, caplen, origlen) followed by a 15-byte
  radiotap header and then the 802.11 frame (which still includes the 4-byte FCS unless `fcs off`).

The node never emits a partial record: if the USB TX buffer is full it drops the whole frame,
so the stream stays record-aligned.

### 15-byte radiotap header

| Offset | Field | Notes |
|--------|-------|-------|
| 0 | version | 0 |
| 1 | pad | 0 |
| 2..3 | it_len | 15 (LE) |
| 4..7 | present | `0x2A` = Flags + Channel + dBm antenna signal |
| 8 | Flags | `0x10` = FCS at end of frame (cleared when `fcs off`) |
| 9 | pad | aligns Channel |
| 10..11 | Channel frequency | MHz, LE (2.4: `2412 + (ch-1)*5`, ch14 = 2484; 5 GHz: `5000 + ch*5`) |
| 12..13 | Channel flags | `0x0080` = 2.4 GHz, `0x0100` = 5 GHz |
| 14 | dBm antenna signal | signed RSSI |

## Channel plan (canonical)

The host assigns one channel per node, band-aware:

- **2.4 GHz nodes:** `1, 6, 11, 3, 8, 13, 2, 4, 5, 7, 9, 10, 12, 14` (non-overlapping first).
- **5 GHz (dual-band C5):** `36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112`. The C5 RX
  cannot demodulate above ~5.56 GHz (channel 116+), a silicon AGC/calibration limit, so the
  upper 5 GHz channels are intentionally omitted from hopping, locks and the app.
- **Default assignment:** give 2.4-only nodes `1/6/11` then spread; send the first dual-band
  node to `hop5` (sweep 5 GHz) and lock any further dual-band nodes to distinct 5 GHz channels.

`sentinel.py` keeps this list in `PLAN_24` / `CH5`; the Android app keeps it in `core.Chan`.
Both must match this section.
