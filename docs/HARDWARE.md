# Hardware notes

## Nodes

Any ESP32 with native USB-CDC and promiscuous WiFi RX works. Tested:

- **ESP32-C3** (for example M5Stack Stamp-C3). 2.4 GHz only. Perfect for one locked channel.
- **ESP32-C5**. Dual-band, needs arduino-esp32 core 3.1 or newer. Build with `CDCOnBoot=cdc`.
  5 GHz RX is usable on channels **36-112 only**: above ~5.56 GHz (channel 116 and up) the C5
  receiver does not demodulate frames (a silicon AGC/DC-offset calibration limit, not the
  regulatory channel mask), so the firmware, tools and app omit the upper 5 GHz channels.

Each board covers exactly one channel when locked. For full non-overlapping 2.4 GHz coverage you need three boards (channels 1, 6, 11). Add more to cover the overlapping channels or to dedicate one to hopping.

## Power budget

An ESP32-C3 in promiscuous RX draws roughly 90 mA at 5 V, so about 0.45 W per board. Ten boards is around 900 mA, well within a basic powered USB hub. You do not need an industrial hub for a modest array; a cheap powered hub with its own supply is enough. Do not try to power a large array from a laptop's unpowered port.

## Why you still need a hub (and why an ESP32 cannot be one)

A USB host port talks to exactly one device unless a hub sits between them. A hub is not a passive splitter: it contains a hub controller IC (for example FE1.1s, CH334, or the 7-port Microchip USB2517) that enumerates and multiplexes the downstream devices for the host.

An ESP32 has a USB *device* peripheral, not a USB *host hub* controller. You cannot wire several boards' D+/D- lines onto one ESP32's GPIO and have it present them to the PC as multiple devices. Use a real powered hub. For very large arrays, cascade hubs or use a 7-port controller and chain two of them.

## Host options

- **Laptop or mini PC.** Simplest. Plug in the hub, run `sentinel.py`.
- **Raspberry Pi (including Pi Zero W).** Works as a standalone headless host. It still needs the powered hub; the Pi's own ports will not carry a large array and the Pi should not try to power the boards itself.

## Serial paths

The tools key each board by the MAC embedded in its `/dev/serial/by-id` path, which is stable across replugs and reboots. If `/dev/serial/by-id` is absent, they fall back to `/dev/ttyACM*` ordering.

## A known-good kit (BOM)

A tidy, cheap rig that behaves like one appliance:

| Part | Suggestion | Why |
|------|------------|-----|
| 3+ nodes | ESP32-C3 SuperMini (2.4 GHz) and one ESP32-C5 (dual-band) | C3 is a few euros and native-USB; one C5 adds 5 GHz. Three covers 1/6/11. |
| Powered USB hub | A mains-powered USB 3 hub with per-port output and its own 5 V supply (for example a 7-port Sabrent/Anker class hub) | Feeds 90 mA per board from the wall, not from the laptop/phone port. |
| Cables | Short USB-A/C to the node's connector, **data cables** (not charge-only) | Charge-only cables are the number one "no device detected" cause. |
| Phone host | A USB-C hub with PD passthrough (data to the phone, power from the wall) | Lets the phone drive the rig and stay charged. |

An ESP32 cannot be the hub itself (no host-hub controller); use a real powered hub.

## Labeling nodes

Each node's USB serial number is its MAC, which is also its stable `/dev/serial/by-id` name and
how both tools identify it. Put a small sticker on each board with the last 4 MAC hex and the
channel you usually assign it, for example `67:30 - ch1`. Then a glance at the rig maps to the
dashboard, and `--channels` order (sorted by MAC) is predictable. The MACs are printed on first
run and by `sentinel.py --list`.

