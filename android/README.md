# Evil-Sentinel - Android app

Evil-Sentinel in your pocket. Plug the ESP32 rig into the phone over USB, watch the
per-channel traffic live, and export a merged pcap. It is `sentinel.py` transposed to a
native Android app: the phone is only the USB host and the screen, the ESP32 nodes are the
radios. **No root needed** (the phone's own WiFi chip is not used).

## What it does

- Enumerates every ESP32 node on the USB bus (native USB `303a`, plus CP210x / CH340 bridges).
- Probes each with `id` and keeps the ones that answer `sentinel`.
- Assigns one 2.4 GHz channel per node (1/6/11 first, then spread; a node can be set to hop).
- Streams all nodes in parallel, merges them into one pcap, and writes it to a file.
- Live dashboard: per-channel band graph (total packets), per-node frames/s, totals, sparklines.
- Tap a node's channel badge to retune it live: lock any 2.4 GHz channel, or on a dual-band C5
  lock a 5 GHz channel (36-165) or sweep 2.4 / 5 GHz / both. 5 GHz options show only on a C5.
- **Packets tab:** read the capture live, frame by frame (time, channel, type, SSID/MAC, RSSI,
  length), with a text filter (SSID / MAC / type / channel) and quick type chips.
- Share the merged pcap to any app (open it later in desktop Wireshark).

## Hardware

Same rig as the desktop tool, with the phone as host:

- The ESP32 nodes flashed with `firmware/sentinel_sniffer`.
- A **powered USB-C hub with PD passthrough**: data (OTG) to the phone, external power to the
  boards. The phone's OTG port cannot feed several boards on its own.
- For a single node in hop mode, a plain USB-C OTG adapter is enough.

## Build

Requires JDK 17 and the Android SDK (platform 35). Either open `android/` in Android Studio
and Run, or from the command line:

```bash
cd android
./gradlew assembleDebug
# APK at app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

On first launch (or when a node is plugged in) Android asks permission for each USB device;
the manifest's device filter pre-targets the known vendor IDs so it can auto-grant on attach.

## Design notes

- `core/Pcap.kt`, `core/Dot11.kt` - pcap framing and a minimal radiotap/802.11 parser
  (channel, frame type, SSID), ported from the Python.
- `core/SerialNode.kt` - one node: parses its pcap stream, counts frames, hands payloads to
  the merge writer.
- `CaptureViewModel.kt` - discovery, USB permission, handshake, channel assignment, the merge
  writer thread, and the live `UiState`.
- `ui/` - the Jetpack Compose dashboard (Material3, dark).

Captures are written to the app's external files dir (`Android/data/com.evilsentinel.sentinel/
files/captures/`) and shared through a `FileProvider`.

## Status

v1.0.0, multi-node. The capture runs while the app is foreground (screen kept on). A
foreground service for background capture is a natural next step.
