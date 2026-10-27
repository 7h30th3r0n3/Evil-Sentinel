# Evil-Sentinel - Improvement Roadmap

Output of a 5-role design congress (UX, UI, firmware, app core, integration). North star:
**as cool and as plug-and-play as a Hak5 WiFi Coconut**. Plug the rig in, it captures, you
see something worth seeing, you walk away with a crackable handshake. Every item below is a
proposal, grounded in the current code. Passive only, GPL-3.0.

## Consensus (where several forks converged)

These came up independently from more than one role, so they are the safest bets:

- **Auto-start / zero-config** (UX, integration, app-core): plugging the hub should start the
  capture with no taps and no per-device dialog ritual.
- **Capture that survives real use** (UX, app-core): a foreground service + wakelock so it keeps
  running screen-off / backgrounded, and a crash-safe pcap (periodic flush + fsync).
- **The Handshake Hunter** (app-core, UX, UI): per-BSSID EAPOL M1-M4 + PMKID tracking, a
  dedicated view, and one-tap hashcat 22000 export. This is the reason-to-use that a generic
  sniffer lacks, and it is the headline "cool" feature.
- **Visible capture health** (firmware, app-core): drops are counted but never shown; surface
  written vs dropped per node so the user trusts the capture.
- **5 GHz made legible** (UI, UX): 5 GHz nodes are invisible on the band strip today; add a
  5 GHz lane and a distinct accent so a C5 is visible.
- **Band-aware auto channel plan** (app-core, integration): a C5 currently gets a 2.4 channel
  like any C3; it should default to 5 GHz / hop5, with 1/6/11 guaranteed.
- **Flash without a toolchain** (integration): prebuilt per-chip `.bin` on releases + a web
  flasher. The single biggest cut to time-from-unboxing-to-packets.

## Sprint 1 - the plug-and-play moment (mostly small, high impact)

The minimal set that makes it both plug-and-play and visibly cool. Do these first.

| # | Item | Domain | Effort | Impact |
|---|------|--------|--------|--------|
| 1 | Prebuilt `sentinel-{c3,c5,c6}.bin` on each release + a copy-paste `esptool --write-flash` line | integration | S | H |
| 2 | App auto-start when permitted nodes are present (launch + attach) + "tap Always allow" hint | UX | S | H |
| 3 | `sentinel.py --watch` (wait for nodes, then auto-start) as the default no-arg behavior | integration | S | H |
| 4 | Crash-safe pcap: periodic flush + `fd.sync()` in the writer (app) / keep the desktop FIFO as-is | app-core | S | H |
| 5 | Surface dropped/written frames: node `stat` command + a per-node counter in the app | firmware + app-core | S | H |
| 6 | Band-aware auto plan everywhere (guarantee 1/6/11, push the C5 to hop5 / 5 GHz) | app-core + integration | S | M |
| 7 | Band bars redesign: rounded + vertical gradient + soft glow (`drawRoundRect`) | UI | S | H |
| 8 | Packet-row left color rail by type (deauth red, eapol amber, beacon teal, data green) | UI | S | H |
| 9 | Honest empty/error states (no-device / not-a-node / permission-denied / check hub power) | UX | S | H |

## Sprint 2 - the headline feature + plug-and-walk

| # | Item | Domain | Effort | Impact |
|---|------|--------|--------|--------|
| 10 | `HandshakeCollector`: capture PMKID + full EAPOL and export hashcat 22000 (WPA*01 / WPA*02) | app-core | M | H |
| 11 | Handshakes view: per-BSSID M1-M4 progress + one-tap export of that handshake | UX | M | H |
| 12 | Header EAPOL M1-M4 capture pill + "handshakes captured" counter | UI | M | H |
| 13 | Foreground service (connectedDevice) + wakelock + notification; VM binds to it | app-core | L | H |
| 14 | 5 GHz mini-strip (second BandStrip over `Chan.CH5`) + distinct 5 GHz accent `#8B7CFF` | UI + UX | M | H |
| 15 | Channel picker redesign: segmented 2.4 / 5G / HOP + compact grid + AUTO one-tap | UX | M | H |
| 16 | Web flasher page (ESP Web Tools on GitHub Pages, reuse the Evil-Flasher pattern) | integration | M | H |
| 17 | RGB status LED on the node (`rgbLedWrite(RGB_BUILTIN)`, `#ifdef` guarded): boot/idle/stream/drop | firmware | M | H |

## Sprint 3 - robustness, fidelity, distribution

| # | Item | Domain | Effort | Impact |
|---|------|--------|--------|--------|
| 18 | Fix `onDeviceDetached`: react only to a lost captured serial, keep the one pcap, keep other nodes | app-core | M | H |
| 19 | Gate `appendPacket()`/`describe()` behind Packets-tab-visible or move off the read thread | app-core | M | H |
| 20 | Reusable growable buffer in `SerialNode.onData` (drop `buf +=` + per-call copyOfRange) | app-core | M | M |
| 21 | Enriched `id` (`sentinel v<ver> <chip> <bands> up<sec>`, keep substrings) | firmware | S | H |
| 22 | Persist channel + hopMode in NVS (node) and the app layout in DataStore | firmware + app-core | S | M |
| 23 | Bigger TX buffer (32 KB) + drain the queue fully each loop | firmware | S | M |
| 24 | Adaptive dwell (extend on traffic, skip silent DFS) + report `set_channel` failures | firmware | M | M |
| 25 | Selectable FCS handling (`fcs on/off`) to kill the cosmetic "malformed" | firmware | M | M |
| 26 | Live node hot-add (ATTACH) to a running capture; SAF "Save As"; pcap rotation | app-core | M | M |
| 27 | Tap-to-expand packet detail; node rename persisted by MAC; REC status chip | UX | S | M |
| 28 | UI polish: fps-scaled node pulse, RSSI mini signal bars, KPI tiles, colored filter chips, bundled JetBrains Mono, 3-dot icon | UI | S-M | M |
| 29 | `PROTOCOL.md` + one shared channel-plan constant across firmware/tools/app | integration | S | M |
| 30 | Release-signed APK; Linux udev rule + `dialout` preflight in `sentinel.py`; hardware BOM; 5-min README + GIF; F-Droid metadata; `pipx` entry point + `--install-extcap` | integration | S-M | M |

## Strategic axes by domain

**UX** - zero-config plug-and-go; status you can trust; the handshake hunter as the purpose;
legible multi-band RF; a lifecycle that survives screen-off; friendly channel control.

**UI** - make the spectrum the hero and dual-band aware; motion that encodes activity (calmed
in FROZEN); spotlight the money frames (deauth, EAPOL); stronger type hierarchy with tabular
figures; one coherent status-colored hexagon identity.

**Firmware** - capture health and throughput; self-describing nodes (rich `id`/`stat`);
glanceable state (LED) + NVS resilience; smarter spectrum coverage (adaptive dwell); capture
fidelity (FCS, CAP). Strictly passive.

**App core** - unattended reliability (service + wakelock + crash-safe pcap); hot-plug
resilience (per-node, keep the file); hot-path throughput (reusable buffer, parse off the read
thread); actionable captures (handshake/PMKID + hashcat export); band-aware persisted channel
plan; observability (counters + per-BSSID handshake map).

**Integration** - flash without a toolchain; zero-config plug-and-run; one source of truth +
`PROTOCOL.md`; friendly distribution (signed APK, F-Droid, prebuilt bins); a real kit story
(BOM, enclosure, labeled nodes); 5-minute onboarding.

## Cross-cutting: the Handshake Hunter

The one feature that spans three roles and defines the product. It needs:
- **app-core**: a `HandshakeCollector` that pairs EAPOL M1-M4 by replay counter per BSSID,
  pulls the PMKID from the M1 RSN KDE, and writes hashcat 22000 (`WPA*01*` PMKID, `WPA*02*`
  EAPOL).
- **UX**: a Handshakes surface (per-BSSID M1-M4 progress, PMKID yes/no, export).
- **UI**: a header capture pill / counter so a caught handshake is a visible trophy.

Build the collector first; the UX and UI surfaces hang off its per-BSSID map.

## Constraints (apply to every item)

Passive receive only (no transmit, deauth, injection, jamming). GPL-3.0. Code, comments and UI
strings in English. No em-dash anywhere.
