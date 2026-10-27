#!/usr/bin/env python3
# ============================================================================
#  sentinel-extcap.py  -  Wireshark extcap for Evil-Sentinel
#
#  Discovers every sentinel_sniffer board plugged in and presents ONE Wireshark
#  interface per device. Each interface has a Channel option:
#     1..14  lock the radio to that channel (no hopping)
#     0      hop across all channels (single-radio full-band sweep)
#  Tick several locked interfaces and Start => all channels captured in parallel
#  into one merged timeline: Evil-Sentinel.
#
#  Robustness notes (multi-interface capture):
#   - a capturing process holds an exclusive flock on its serial port;
#   - discovery probes with a NON-BLOCKING flock and SKIPS busy ports, so starting
#     N interfaces never deadlocks on a port another interface is already reading;
#   - --extcap-config opens NO port (channel default from the sorted device index),
#     because Wireshark calls it per-interface while captures are starting.
#
#  Devices are keyed by the stable /dev/serial/by-id MAC.
#  Stdlib only (no pyserial). Serial opened raw via termios.
#  SPDX-License-Identifier: GPL-3.0-or-later  -  Copyright (c) 7h30th3r0n3
# ============================================================================
import sys, os, argparse, signal, tty, termios, glob, select, time, re, fcntl

BYID = "/dev/serial/by-id"
CHAN_PLAN = [1, 6, 11, 3, 8, 13, 2, 4, 5, 7, 9, 10, 12, 14]   # non-overlapping first

def all_ports():
    return sorted(glob.glob(BYID + "/*")) if os.path.isdir(BYID) else sorted(glob.glob("/dev/ttyACM*"))

def mac_of(path):
    m = re.search(r'([0-9A-Fa-f:]{17})', os.path.basename(path))
    return m.group(1) if m else os.path.basename(path)

def iface_value(mac):  return "sent-" + mac.replace(":", "")
def chan_for_path(p):
    ap = all_ports()
    i = ap.index(p) if p in ap else 0
    return CHAN_PLAN[i % len(CHAN_PLAN)]

def open_locked(port, exclusive_block=False):
    """Open raw, non-blocking. Take an flock: blocking-exclusive for capture,
    else non-blocking (raises BlockingIOError if the port is busy)."""
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if exclusive_block else fcntl.LOCK_NB))
    except Exception:
        os.close(fd); raise
    try:
        tty.setraw(fd)
        a = termios.tcgetattr(fd); a[2] |= (termios.CLOCAL | termios.CREAD)
        termios.tcsetattr(fd, termios.TCSANOW, a)
        fl = fcntl.fcntl(fd, fcntl.F_GETFL); fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
    except Exception:
        pass
    return fd

def read_for(fd, ms):
    end = time.time() + ms/1000.0; out = b""
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
        if not r: break
        try:
            d = os.read(fd, 4096)
            if not d: break
            out += d
        except OSError: break
    return out

def is_sentinel(path):
    # Probe only FREE ports. A port already locked (an active sentinel capture) is
    # kept listed without probing, so re-enumeration during a multi-interface
    # capture neither drops the busy interface nor steals bytes from its stream.
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except Exception:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            return True                    # busy = our capture is running -> keep listed
        tty.setraw(fd)
        a = termios.tcgetattr(fd); a[2] |= (termios.CLOCAL | termios.CREAD); termios.tcsetattr(fd, termios.TCSANOW, a)
        fl = fcntl.fcntl(fd, fcntl.F_GETFL); fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        os.write(fd, b"id\n"); reply = read_for(fd, 400)
        try: fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception: pass
        return b"sentinel" in reply
    finally:
        try: os.close(fd)
        except Exception: pass

def discover():
    return [(mac_of(p), p) for p in all_ports() if is_sentinel(p)]

def resolve_path(mac):
    for p in all_ports():
        if mac_of(p) == mac: return p
    return None

def cmd_interfaces():
    print("extcap {version=1.0.0}{help=Evil-Sentinel (lock one channel per unit, or hop)}")
    for mac, path in discover():
        print("interface {value=%s}{display=Sentinel %s (ch%d)}" % (iface_value(mac), mac, chan_for_path(path)))

def cmd_dlts(iface):
    print("dlt {number=127}{name=IEEE802_11_RADIOTAP}{display=802.11 plus radiotap}")

def cmd_config(iface):
    # NO serial access here (Wireshark calls this per-interface during capture start).
    ch = 6
    for p in all_ports():
        if iface_value(mac_of(p)) == iface: ch = chan_for_path(p); break
    print("arg {number=0}{call=--channel}{display=WiFi channel}{type=integer}"
          "{range=0,112}{default=%d}{tooltip=0 = hop 2.4 GHz; 1-14 = 2.4 GHz; 36-112 = 5 GHz (C5 only)}" % ch)

def cmd_capture(iface, fifo, channel):
    mac = iface.replace("sent-", "")
    if ":" not in mac:
        mac = ":".join(mac[i:i+2] for i in range(0, len(mac), 2))
    port = resolve_path(mac)
    if not port:
        sys.stderr.write("sentinel device %s not found\n" % mac); sys.exit(1)
    ser = open_locked(port, exclusive_block=True)   # hold the port; discovery will skip it

    def stop(*_):
        try: os.write(ser, b"X")
        except Exception: pass
        try: os.close(ser)
        except Exception: pass
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    if channel < 1:
        channel = chan_for_path(port)                # default lock = this device's plan channel
    try: os.write(ser, b"X"); read_for(ser, 120)
    except Exception: pass
    cmd = ("ch %d\n" % channel).encode() if channel >= 1 else b"hop\n"
    try: os.write(ser, cmd); read_for(ser, 120)
    except Exception: pass

    out = os.open(fifo, os.O_WRONLY)
    try: os.write(ser, b"S")
    except Exception: pass
    try:
        while True:
            data = os.read(ser, 8192)
            if data: os.write(out, data)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try: os.write(ser, b"X")
        except Exception: pass
        try: os.close(ser)
        except Exception: pass
        try: os.close(out)
        except Exception: pass

def main():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--extcap-interfaces", action="store_true")
    p.add_argument("--extcap-dlts", action="store_true")
    p.add_argument("--extcap-config", action="store_true")
    p.add_argument("--capture", action="store_true")
    p.add_argument("--extcap-interface", default="")
    p.add_argument("--extcap-version", default="")
    p.add_argument("--fifo", default="")
    p.add_argument("--channel", type=int, default=0)
    args, _ = p.parse_known_args()

    if args.extcap_interfaces: cmd_interfaces(); return
    if args.extcap_dlts:       cmd_dlts(args.extcap_interface); return
    if args.extcap_config:     cmd_config(args.extcap_interface); return
    if args.capture:
        if not args.fifo: sys.stderr.write("no --fifo\n"); sys.exit(1)
        cmd_capture(args.extcap_interface, args.fifo, args.channel); return
    cmd_interfaces()

if __name__ == "__main__":
    main()
