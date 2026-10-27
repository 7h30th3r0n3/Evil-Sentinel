# Wireshark integration

There are two independent ways to get the captures into Wireshark. Pick one.

## Option A: the controller (recommended)

`sentinel.py` owns every serial port in a single process, merges all node streams into one pcap stream, and pipes it to Wireshark through a named FIFO that it launches for you.

```bash
cd tools
./sentinel.py
```

Advantages:

- No port contention. One process reads all boards, so there is never a race between several Wireshark extcap instances for the same port.
- A live dashboard (channels, frames per second, totals, per-node activity).
- One merged timeline across every channel.

To run the dashboard without the GUI:

```bash
./sentinel.py --no-wireshark
```

## Option B: native extcap

`tools/sentinel-extcap.py` makes each board appear as its own capture interface inside the Wireshark interface list.

### Install

Copy or symlink the script into your Wireshark extcap directory, then confirm it is executable:

```bash
# find your extcap dir
wireshark -v | grep -i extcap            # or: Help > About Wireshark > Folders
# typical locations:
#   ~/.local/lib/wireshark/extcap/
#   ~/.config/wireshark/extcap/
ln -s "$(pwd)/tools/sentinel-extcap.py" ~/.local/lib/wireshark/extcap/sentinel-extcap.py
chmod +x tools/sentinel-extcap.py
```

Restart Wireshark (or refresh interfaces). Each detected board shows up as `Sentinel <MAC> (chN)`.

### Use

1. Tick one or more Sentinel interfaces.
2. Optionally open each interface's options and set its channel (1-14 locks that channel, 0 hops).
3. Start. Ticking several locked interfaces captures all of those channels in parallel into one merged timeline.

The extcap discovers boards with a non-blocking lock and skips any port already in use, so starting several interfaces never deadlocks on a port another interface is already reading.

## Link-layer type

Both paths produce `LINKTYPE_IEEE802_11_RADIOTAP` (DLT 127). Every frame has a 15-byte radiotap header carrying Flags (FCS present at end), the real RX channel frequency, and the dBm antenna signal, so Wireshark shows the correct source channel and RSSI per frame.

## The "malformed" flag on some beacons

See the README's "Known limitation" section. In short: the ESP32 includes the 4-byte FCS in the frame length, and some Wireshark versions parse those trailing bytes as a phantom information element. It is cosmetic, all fields read correctly. Hide it with the display filter:

```
!_ws.malformed
```
