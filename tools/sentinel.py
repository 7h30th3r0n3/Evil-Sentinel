#!/usr/bin/env python3
# ============================================================================
#  sentinel.py  -  Evil-Sentinel controller (ESP32-C3/C5 nodes)
#
#  ONE process owns every node's serial port, so there is no multi-process port
#  contention (unlike N Wireshark extcap instances). It:
#    1. auto-detects sentinel_sniffer nodes on /dev/serial/by-id (probes "id");
#    2. band-aware auto plan: 2.4 nodes take 1/6/11 then spread, a dual-band C5 sweeps 5 GHz;
#    3. locks each node to its channel and reads its pcap stream;
#    4. shows a live per-node dashboard (channel, frames/s, total, activity bar);
#    5. MERGES every node's frames into one pcap stream and feeds it to Wireshark
#       through a named pipe, launched automatically.
#
#  Passive (listen only). Stdlib only. Serial via termios, flock-guarded.
#  Protocol and channel plan: see docs/PROTOCOL.md (single source of truth).
#
#  Usage:
#    sentinel.py                      auto-detect, band-aware channels, launch Wireshark
#    sentinel.py --watch              wait for nodes to appear, then auto-start (plug-and-go)
#    sentinel.py --channels 1,6,11,hop5   force assignment (order = sorted nodes)
#    sentinel.py --no-wireshark       dashboard only, no GUI
#    sentinel.py --list               just list detected nodes and exit
#    sentinel.py --seconds N          run headless for N s, print per-node totals
#    sentinel.py --install-extcap     symlink the Wireshark extcap, then exit
#
#  SPDX-License-Identifier: GPL-3.0-or-later  -  Copyright (c) 7h30th3r0n3
# ============================================================================
import os, sys, time, glob, re, termios, tty, fcntl, select, struct, threading, subprocess, argparse, signal, queue
import collections, json, http.server

BYID = "/dev/serial/by-id"
# Canonical channel plan (single source of truth; mirrored in docs/PROTOCOL.md).
# 2.4 GHz: non-overlapping 1/6/11 first, then the rest. 5 GHz: standard 20 MHz channels.
PLAN_24 = [1, 6, 11, 3, 8, 13, 2, 4, 5, 7, 9, 10, 12, 14]
# Only the channels the ESP32-C5 can actually receive (36..112). Above ~5.56 GHz (ch 116+)
# the C5 RX does not demodulate, so the upper 5 GHz channels are left out everywhere.
CH5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112]
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"

# ───────────────────────── serial helpers ─────────────────────────────────
def all_ports():
    return sorted(glob.glob(BYID + "/*")) if os.path.isdir(BYID) else sorted(glob.glob("/dev/ttyACM*"))

def mac_of(path):
    m = re.search(r'([0-9A-Fa-f:]{17})', os.path.basename(path))
    return m.group(1) if m else os.path.basename(path)

def _raw(fd):
    tty.setraw(fd)
    a = termios.tcgetattr(fd); a[2] |= (termios.CLOCAL | termios.CREAD); termios.tcsetattr(fd, termios.TCSANOW, a)
    fl = fcntl.fcntl(fd, fcntl.F_GETFL); fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)

def open_lock(port):
    """Open + exclusive flock (raises if busy). Caller owns the port until close."""
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _raw(fd)
    except Exception:
        os.close(fd); raise
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

def probe(port):
    """Return (is_sentinel, dualband). A busy port is assumed ours (band unknown).
    The id reply may be a rich line ('sentinel v1 c5 2.4,5 up12'); we match substrings."""
    try:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except Exception:
        return (False, False)
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError): return (True, False)   # busy = assume ours
        _raw(fd)
        os.write(fd, b"id\n"); reply = read_for(fd, 400)
        try: fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception: pass
        return (b"sentinel" in reply, b"dualband" in reply)
    finally:
        try: os.close(fd)
        except Exception: pass

def discover():
    """List of (mac, port, dualband) for every node that answers the id probe."""
    out = []
    for p in all_ports():
        ok, dual = probe(p)
        if ok: out.append((mac_of(p), p, dual))
    return out

def auto_assign(nodes_raw):
    """Default channel plan for (mac, port, dualband) nodes: everyone hops, matching the
    firmware boot default and the 'allhop' control. Dual-band (C5) nodes sweep 5 GHz (hop5 = -1),
    the rest sweep 2.4 GHz (hop = 0). Lock distinct channels with --channels for parallel coverage."""
    return [-1 if item[2] else 0 for item in nodes_raw]

def preflight():
    """Print actionable hints for the two classic Linux gotchas: no Wireshark, no serial access."""
    import shutil
    if shutil.which("wireshark") is None:
        print("[preflight] Wireshark not found. Install it (e.g. sudo apt install wireshark) "
              "or run with --no-wireshark.")
    try:
        import grp, getpass
        user = getpass.getuser()
        if user not in grp.getgrnam("dialout").gr_mem:
            print("[preflight] user '%s' is not in the 'dialout' group; serial ports may be denied." % user)
            print("            fix: sudo usermod -aG dialout %s   (then log out and back in)" % user)
            print("            or:  sudo cp tools/99-evil-sentinel.rules /etc/udev/rules.d/ && "
                  "sudo udevadm control --reload")
    except Exception:
        pass

def install_extcap():
    """Symlink sentinel-extcap.py into the Wireshark extcap dir so it shows up as interfaces."""
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel-extcap.py")
    cands = [os.path.expanduser("~/.local/lib/wireshark/extcap"),
             os.path.expanduser("~/.config/wireshark/extcap")]
    dst_dir = next((d for d in cands if os.path.isdir(d)), cands[0])
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, "sentinel-extcap.py")
    try:
        if os.path.islink(dst) or os.path.exists(dst): os.remove(dst)
        os.symlink(src, dst); os.chmod(src, 0o755)
        print("linked %s -> %s\nrestart Wireshark or refresh its interfaces." % (dst, src))
    except Exception as e:
        print("install-extcap failed: %s" % e)

# ───────────────────────── node reader ────────────────────────────────────
FCS_MODE = "on"   # "on" keeps + flags the trailing FCS (firmware default); "off" strips it. Set
                  # from --fcs. Kismet and aircrack drop frames whose FCS fails to verify, and the
                  # ESP32's reported FCS does not verify, so they need "off" to build any devices.

class Node:
    def __init__(self, mac, port, channel, merged_q, dual=False):
        self.mac = mac; self.port = port; self.channel = channel
        self.dual = dual          # dual-band (5 GHz capable); gates the channel menu options
        self.merged = merged_q
        self.fd = None; self.thread = None; self.running = False
        self.total = 0; self.dropped = 0
        self._win = []            # timestamps of recent frames (for fps)
        self.last_freq = 0
        self.chan_count = {}      # frames captured per real channel (from each frame's radiotap);
                                  # spreads a hopping node's catch across the band columns
        self.alive = False
        self.hist = collections.deque([0]*60, maxlen=60)   # per-second fps, for the web sparkline

    def open(self):
        self.fd = open_lock(self.port)
        os.write(self.fd, b"X"); read_for(self.fd, 120)
        os.write(self.fd, b"fcs off\n" if FCS_MODE == "off" else b"fcs on\n"); read_for(self.fd, 120)
        os.write(self.fd, chan_cmd(self.channel)); read_for(self.fd, 120)
        os.write(self.fd, b"S")
        self.alive = True

    def label(self):
        return chan_label(self.channel)

    def set_channel(self, ch):
        """Retune a live node. The firmware applies 'ch N'/'hop*' without restarting the
        stream, so no pcap resync is needed; just update our view of the channel."""
        if self.fd is None: return
        try:
            os.write(self.fd, chan_cmd(ch)); self.channel = ch
        except OSError:
            pass

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True); self.thread.start()

    def fps(self):
        now = time.time(); self._win = [t for t in self._win if now - t <= 1.0]
        return len(self._win)

    def _run(self):
        buf = b""; synced = False
        while self.running:
            r, _, _ = select.select([self.fd], [], [], 0.3)
            if not r: continue
            try: d = os.read(self.fd, 8192)
            except OSError: break
            if not d: continue
            buf += d
            if not synced:                              # skip this node's pcap global header
                i = buf.find(PCAP_MAGIC)
                if i < 0:
                    if len(buf) > 65536: buf = buf[-64:]
                    continue
                buf = buf[i + 24:]; synced = True
            # parse records: 16-byte header + caplen payload
            while len(buf) >= 16:
                ts, us, caplen, orig = struct.unpack("<IIII", buf[:16])
                if caplen == 0 or caplen > 4096: buf = buf[1:]; continue   # resync on garbage
                if len(buf) < 16 + caplen: break
                rec = buf[16:16 + caplen]; buf = buf[16 + caplen:]
                self.total += 1; self._win.append(time.time())
                if caplen >= 12:                        # radiotap channel freq (15-byte header, freq at offset 10)
                    f = struct.unpack("<H", rec[10:12])[0]
                    self.last_freq = f
                    c = freq_to_ch(f)                    # tally this frame on the channel it was seen on
                    if c: self.chan_count[c] = self.chan_count.get(c, 0) + 1
                self.merged.put(rec)                    # hand payload to the merge writer

    def stop(self):
        self.running = False
        try: os.write(self.fd, b"X")
        except Exception: pass
        try:
            if self.fd is not None: os.close(self.fd)
        except Exception: pass

# ───────────────────────── merged pcap writer ─────────────────────────────
def le32(v): return struct.pack("<I", v)
def le16(v): return struct.pack("<H", v)

def global_header():
    return (le32(0xa1b2c3d4) + le16(2) + le16(4) + le32(0) + le32(0) + le32(525) + le32(127))

def merge_writer(merged_q, out_fd, stop_evt):
    os.write(out_fd, global_header())
    while not stop_evt.is_set():
        try: rec = merged_q.get(timeout=0.3)
        except queue.Empty: continue
        ms = time.time()
        hdr = le32(int(ms)) + le32(int((ms % 1) * 1e6)) + le32(len(rec)) + le32(len(rec))
        try: os.write(out_fd, hdr + rec)
        except (BrokenPipeError, OSError): break

def open_fifo_write(path, proc=None, timeout=None, stop_evt=None):
    """Open a FIFO's write end without hanging. O_WRONLY on a FIFO blocks until a reader attaches
    (ENXIO until then), so retry non-blocking. Give up if the launched consumer `proc` exits, if
    `timeout` seconds pass, or if `stop_evt` is set (Ctrl-C). Returns a blocking fd, or None."""
    import errno
    deadline = time.time() + timeout if timeout else None
    while True:
        if stop_evt is not None and stop_evt.is_set(): return None
        if deadline is not None and time.time() > deadline: return None
        if proc is not None and proc.poll() is not None: return None
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            fl = fcntl.fcntl(fd, fcntl.F_GETFL); fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
            return fd
        except OSError as e:
            if e.errno != errno.ENXIO: return None
            time.sleep(0.2)

# ───────────────────────── dashboard (curses) ─────────────────────────────
def freq_to_ch(f):
    if f >= 4900: return (f - 5000)//5        # 5 GHz
    if f == 2484: return 14
    if f >= 2412: return (f - 2412)//5 + 1     # 2.4 GHz
    return 0

# channel encoding: >=1 lock (2.4 or 5 GHz), 0 hop 2.4, -1 hop 5 GHz, -2 hop dual-band
def chan_cmd(ch):
    if ch == 0:  return b"hop\n"
    if ch == -1: return b"hop5\n"
    if ch == -2: return b"hopdual\n"
    return ("ch %d\n" % ch).encode()

def chan_label(ch):
    return {0: "HOP", -1: "H5", -2: "HD"}.get(ch, "ch%d" % ch)

def parse_chan(tok):
    tok = tok.strip().lower()
    names = {"hop": 0, "hop5": -1, "hopdual": -2}
    # NB: must not use dict.get(tok, int(tok)) - the default is evaluated eagerly, so int("hop")
    # would raise before the hop tokens are ever matched. Look the name up first.
    return names[tok] if tok in names else int(tok)

def chan_needs_dual(ch):
    """True if channel code ch only works on a dual-band (5 GHz capable) radio: a 5 GHz lock
    (CH5), hop5 (-1) or hopdual (-2). A 2.4 GHz lock (1..14) and plain hop (0) work on any node."""
    return ch in (-1, -2) or ch in CH5

def resolve_plan(nodes_raw, chans, auto):
    """Turn a positional --channels request into a final per-node plan that respects each node's
    band. nodes_raw is [(mac, port, dual), ...], chans the parsed request (may be shorter than the
    node list), auto the band-aware default. Returns (final, notes): final[i] is the channel code
    for node i, notes a list of human lines explaining any reshuffle.

    A 5 GHz channel landing on a 2.4-only node would be silently ignored by the firmware. Rather
    than just drop it to HOP, first try to SWAP it with a dual-band node that was handed a channel
    a 2.4-only radio can do anyway (a 2.4 lock or plain hop): the dual-band node takes the 5 GHz
    channel, the 2.4-only node takes the 2.4 one, nobody loses coverage. Only if no dual-band node
    is free to take it do we fall back to that slot's auto (2.4 GHz) default."""
    final = [chans[i] if i < len(chans) else auto[i] for i in range(len(nodes_raw))]
    requested = [i < len(chans) for i in range(len(nodes_raw))]   # came from --channels, not auto
    notes = []
    for c in range(len(nodes_raw)):
        if not (requested[c] and chan_needs_dual(final[c]) and not nodes_raw[c][2]):
            continue
        # node c is 2.4-only but was asked for a 5 GHz channel. Find a dual-band node holding a
        # channel that a 2.4-only radio can take, and swap.
        swap = None
        for d in range(len(nodes_raw)):
            if d != c and nodes_raw[d][2] and not chan_needs_dual(final[d]):
                swap = d; break
        if swap is not None:
            final[c], final[swap] = final[swap], final[c]
            notes.append("  ~ %s is 2.4 GHz only; moved %s to dual-band %s and gave it %s"
                         % (nodes_raw[c][0], chan_label(final[swap]), nodes_raw[swap][0],
                            chan_label(final[c])))
        else:
            notes.append("  ! %s is 2.4 GHz only and no dual-band node is free; %s -> %s"
                         % (nodes_raw[c][0], chan_label(chans[c]), chan_label(auto[c])))
            final[c] = auto[c]
    return final, notes

BLK = " ▁▂▃▄▅▆▇█"   # sparkline levels

def run_dashboard(nodes, stop_evt):
    import curses, locale
    locale.setlocale(locale.LC_ALL, "")
    t0 = time.time()
    def draw(scr):
        curses.curs_set(0); scr.nodelay(True)
        if curses.has_colors():
            curses.start_color()
            try: curses.use_default_colors()
            except Exception: pass
            for i, c in ((1, curses.COLOR_GREEN), (2, curses.COLOR_YELLOW), (3, curses.COLOR_RED),
                         (4, curses.COLOR_CYAN), (5, curses.COLOR_BLUE)):
                curses.init_pair(i, c, -1)
        GREEN=curses.color_pair(1); AMBER=curses.color_pair(2); RED=curses.color_pair(3)
        ACC=curses.color_pair(4); DIM=curses.color_pair(5)|curses.A_DIM; B=curses.A_BOLD
        def load_col(l): return RED if l > .66 else AMBER if l > .33 else GREEN
        def put(y, x, s, a=0):
            try: scr.addstr(y, x, s, a)
            except curses.error: pass
        def channel_menu(scr):
            """Blocking modal: pick a node, type a new channel, retune it live."""
            scr.nodelay(False); curses.echo(); curses.curs_set(1)
            try:
                scr.erase()
                put(0, 2, "CHANGE CHANNEL", ACC|B)
                for i, n in enumerate(nodes):
                    put(2+i, 4, "%d) %-17s  %-5s  %s" % (i, n.mac, n.label(),
                        "dual-band" if n.dual else "2.4 only"), DIM if not n.dual else 0)
                aidx = 2 + len(nodes)
                put(aidx, 4, "a) ALL  ->  C5 hop5, others hop", ACC)
                py = aidx + 2
                put(py, 2, "pick #, 'a', Enter: ", B); scr.refresh()
                sel = scr.getstr(py, 22, 4).decode("ascii", "ignore").strip().lower()
                if not sel: return
                if sel in ("a", "all", "allhop"):     # dual-band -> hop5, everything else -> hop
                    for nd in nodes:
                        nd.set_channel(-1 if nd.dual else 0)
                    put(py+2, 2, "allhop sent: C5 -> hop5, others -> hop", GREEN); scr.refresh(); time.sleep(1.0)
                    return
                try: idx = int(sel)
                except ValueError: return
                if not (0 <= idx < len(nodes)): return
                n = nodes[idx]
                # No client-side dual-band gate: the firmware ignores 5 GHz / hop5 / hopdual on a
                # 2.4-only radio by itself, and our dual-band auto-detect is not reliable enough
                # to refuse on. Validate the format/range only, then let the node decide.
                put(py+2, 2, "channel: 1-14, %s, hop, hop5, hopdual" % ",".join(map(str, CH5)), DIM)
                put(py+3, 2, "> ", B); scr.refresh()
                tok = scr.getstr(py+3, 4, 12).decode("ascii", "ignore").strip().lower()
                if not tok: return
                try: ch = parse_chan(tok)
                except ValueError:
                    put(py+5, 2, "not understood: '%s'" % tok, RED); scr.refresh(); time.sleep(1.2); return
                if ch in (0, -1, -2) or (1 <= ch <= 14) or (ch in CH5):
                    n.set_channel(ch)
                    put(py+5, 2, "sent %s -> %s" % (chan_label(ch), n.mac), GREEN); scr.refresh(); time.sleep(0.8)
                else:
                    put(py+5, 2, "out of range: '%s'" % tok, RED); scr.refresh(); time.sleep(1.2)
            except Exception:
                pass
            finally:
                curses.noecho(); curses.curs_set(0); scr.nodelay(True)
        while not stop_evt.is_set():
            scr.erase(); H, W = scr.getmaxyx()
            fps = [n.fps() for n in nodes]; peak = max(fps + [1])
            totals = [n.total for n in nodes]; peaktot = max(totals + [1])
            tot = sum(totals); ftot = sum(fps)
            up = int(time.time() - t0); ups = ("%dm%02ds" % (up//60, up%60)) if up >= 60 else "%ds" % up
            put(0, 2, "⬢ EVIL-SENTINEL", ACC|B)
            put(0, 19, "%d nodes" % len(nodes)); put(0, 31, "%d f/s" % ftot, ACC|B)
            put(0, 45, "%d frames" % tot); put(0, 63, "up %s" % ups, DIM); put(0, max(62, W-13), "[c]han [q]uit", DIM)
            put(1, 2, "─" * (W-4), DIM)
            # band charts: TOTAL captured packets per channel, tallied from each frame's own
            # radiotap channel. Locked nodes pile onto their one channel; hopping nodes spread
            # their catch across the columns they swept.
            BH = 6; x0 = 4; cw = 5
            def band_chart(title, chlist, top):
                tot_by = {c: 0.0 for c in chlist}
                for n in nodes:
                    cc = n.chan_count
                    for c in chlist:
                        v = cc.get(c)
                        if v: tot_by[c] += v
                bpeak = max(list(tot_by.values()) + [1])
                put(top, 2, title, DIM|B)
                for i, c in enumerate(chlist):
                    l = tot_by[c]/bpeak; filled = int(round(l*BH)); x = x0 + i*cw
                    cc = load_col(l)
                    for r in range(BH):
                        on = (BH-r) <= filled
                        put(top+1+r, x, "██" if on else "  ", cc if on else DIM)
                    put(top+1+BH, x, "%d" % c, ACC if tot_by[c] > 0 else DIM)
                return top + 1 + BH + 1          # first free row below the chart
            y = band_chart("2.4 GHz BAND  (total packets)", list(range(1, 14)), 3)
            if any(n.dual or n.channel in CH5 or n.channel in (-1, -2) for n in nodes):
                y = band_chart("5 GHz BAND  (total packets)", CH5, y + 1)
            ny = y + 1
            put(ny-1, 2, "NODES", DIM|B)
            for i, n in enumerate(nodes):
                f = n.fps(); l = f/peak; y = ny + i
                seen = freq_to_ch(n.last_freq)
                put(y, 2, "%-17s" % n.mac)
                put(y, 20, "%-4s" % n.label(), ACC|B)
                put(y, 26, "%4d f/s" % f, load_col(l)|B)
                put(y, 36, "%8d" % n.total, DIM)
                barw = min(18, max(6, W-70))
                lt = n.total / peaktot                       # bar = share of total packets
                fb = int(lt*barw)
                put(y, 46, "█"*fb, load_col(lt)); put(y, 46+fb, "░"*(barw-fb), DIM)
                h = list(n.hist)[-16:]; m = max(h + [1])
                spk = "".join(BLK[min(8, int(v/m*8))] for v in h)
                put(y, 46+barw+1, spk, ACC)
                if seen and n.channel >= 1 and seen != n.channel:
                    put(y, 46+barw+2+len(spk), "⚠ ch%d" % seen, RED)
            fy = ny + len(nodes) + 1
            put(fy, 2, "─" * (W-4), DIM)
            put(fy+1, 2, "merged → Wireshark   ·   passive   ·   [c]hange channel   ·   [q]uit", DIM)
            scr.refresh()
            try:
                k = scr.getch()
                if k in (ord('q'), ord('Q')): break
                elif k in (ord('c'), ord('C')): channel_menu(scr)
            except Exception: pass
            time.sleep(0.33)
    curses.wrapper(draw)
    stop_evt.set()

# ───────────────────────── web dashboard ──────────────────────────────────
_WEB = {"nodes": [], "t0": time.time()}

def sampler_loop(nodes, stop_evt):
    while not stop_evt.is_set():
        time.sleep(1.0)
        for n in nodes: n.hist.append(n.fps())

HTML_PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Evil-Sentinel</title><style>
:root{--bg:#070b0f;--panel:#0d141b;--line:#1c2a36;--txt:#cfe9e0;--dim:#5f7d78;
--c1:#39d98a;--c2:#f2c744;--c3:#ff5d5d;--acc:#2de0c8;--mono:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#0c1620,#070b0f 60%);
color:var(--txt);font-family:var(--mono);-webkit-font-smoothing:antialiased}
.wrap{max-width:1040px;margin:0 auto;padding:22px 20px 40px}
header{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:14px}
h1{font-size:22px;letter-spacing:4px;margin:0;color:#eafff6;text-shadow:0 0 18px rgba(45,224,200,.35)}
h1 .hex{color:var(--acc)}
.sub{color:var(--dim);font-size:12px;letter-spacing:2px}
.spacer{flex:1}
.stat{font-size:12px;color:var(--dim);letter-spacing:1px}
.stat b{color:var(--acc);font-size:16px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--c1);display:inline-block;margin-right:6px;
box-shadow:0 0 10px var(--c1);animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
h2{font-size:11px;letter-spacing:3px;color:var(--dim);margin:26px 0 12px;font-weight:600}
/* band strip */
.band{display:grid;grid-template-columns:repeat(13,1fr);gap:6px;align-items:end;height:150px;
background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 12px 8px}
.ch{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;position:relative}
.ch .bar{width:70%;border-radius:4px 4px 2px 2px;min-height:2px;height:2px;
transition:height .45s cubic-bezier(.2,.8,.2,1),background .4s;background:#17323a}
.ch.on .bar{box-shadow:0 0 12px -2px currentColor}
.ch .n{font-size:11px;color:var(--dim);margin-top:6px}
.ch.on .n{color:var(--txt)}
.ch .f{position:absolute;top:-16px;font-size:10px;color:var(--dim);opacity:0;transition:opacity .3s}
.ch.on .f{opacity:1;color:var(--acc)}
/* node cards */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.card{background:linear-gradient(180deg,#0e171f,#0b1118);border:1px solid var(--line);border-radius:14px;
padding:16px 16px 14px;position:relative;overflow:hidden}
.card:before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:var(--acc);opacity:.8}
.card .top{display:flex;align-items:center;gap:12px}
.badge{min-width:50px;height:50px;border-radius:10px;display:flex;flex-direction:column;align-items:center;justify-content:center;
background:#0a1f1c;border:1px solid #1f3f39;color:var(--acc)}
.badge .cn{font-size:20px;font-weight:700;line-height:1}
.badge .cl{font-size:8px;letter-spacing:2px;color:var(--dim)}
.mac{font-size:13px;color:#dff5ee;letter-spacing:1px}
.meta{font-size:10px;color:var(--dim);letter-spacing:1px;margin-top:2px}
.fps{margin-left:auto;text-align:right}
.fps b{font-size:26px;color:#eafff6}
.fps span{font-size:10px;color:var(--dim);display:block;letter-spacing:2px}
.pbar{height:7px;background:#12222a;border-radius:4px;margin-top:14px;overflow:hidden}
.pbar>i{display:block;height:100%;width:0;border-radius:4px;background:linear-gradient(90deg,var(--c1),var(--acc));
transition:width .45s cubic-bezier(.2,.8,.2,1),background .4s}
.spark{margin-top:10px;width:100%;height:34px;display:block}
.warn{color:var(--c3)}
footer{margin-top:28px;color:var(--dim);font-size:11px;letter-spacing:1px;display:flex;gap:18px;flex-wrap:wrap;
border-top:1px solid var(--line);padding-top:14px}
footer b{color:var(--txt)}
.controls{display:flex;gap:10px;align-items:center;margin:16px 0 0;flex-wrap:wrap}
.btn{font-family:var(--mono);font-size:11px;letter-spacing:2px;color:#031b16;background:var(--acc);
border:0;border-radius:8px;padding:8px 14px;cursor:pointer;font-weight:700;box-shadow:0 0 14px -4px var(--acc)}
.btn:hover{filter:brightness(1.12)}
.ctl{margin-top:12px;display:flex;align-items:center;gap:8px}
.ctl select{flex:1;font-family:var(--mono);font-size:12px;color:var(--txt);background:#0a141b;
border:1px solid var(--line);border-radius:8px;padding:7px 8px;cursor:pointer;appearance:none}
.ctl select:focus{outline:none;border-color:var(--acc)}
.tag{font-size:9px;letter-spacing:2px;color:var(--acc);border:1px solid #1f3f39;border-radius:5px;padding:3px 6px}
</style></head><body><div class="wrap">
<header>
  <h1><span class="hex">&#x2b22;</span> EVIL-SENTINEL</h1>
  <div class="sub">DIY multi-band parallel capture</div>
  <div class="spacer"></div>
  <div class="stat"><span class="dot"></span><b id="nn">0</b> nodes</div>
  <div class="stat"><b id="tf">0</b> f/s</div>
  <div class="stat"><b id="tt">0</b> frames</div>
</header>
<div class="controls">
  <button class="btn" id="allhop">ALL HOP &nbsp;(C5&rarr;5G, rest&rarr;2.4)</button>
  <span class="stat">per-node channel below &middot; applies live</span>
</div>
<h2>2.4 GHz BAND <span class="stat">&middot; packets seen, hopping-aware</span></h2>
<div class="band" id="band"></div>
<section id="sec5" style="display:none">
<h2>5 GHz BAND <span class="stat">&middot; C5 dual-band nodes</span></h2>
<div class="band" id="band5"></div>
</section>
<h2>NODES</h2>
<div class="cards" id="cards"></div>
<footer><div>uptime <b id="up">0s</b></div><div>merged &rarr; <b>Wireshark</b></div><div>passive &middot; multi-band</div></footer>
</div><script>
const CH_COLOR=(load)=>load>.66?'var(--c3)':load>.33?'var(--c2)':'var(--c1)';
const CH24=[1,2,3,4,5,6,7,8,9,10,11,12,13];
const CH5=[36,40,44,48,52,56,60,64,100,104,108,112];
function fmtK(v){return v>=1000?(v/1000).toFixed(v>=10000?0:1)+'k':''+v;}
function spark(h){const w=260,ht=34,m=Math.max(...h,1);
 const pts=h.map((v,i)=>`${(i/(h.length-1)*w).toFixed(1)},${(ht-v/m*(ht-3)-1).toFixed(1)}`).join(' ');
 return `<svg class="spark" viewBox="0 0 ${w} ${ht}" preserveAspectRatio="none"><polyline fill="none" stroke="var(--acc)" stroke-width="1.5" points="${pts}"/></svg>`;}
function fmtUp(s){s=Math.floor(s);return s<60?s+'s':Math.floor(s/60)+'m'+(s%60)+'s';}
function chOptions(dual){
 let o='<option value="0">HOP 2.4</option>';
 if(dual)o+='<option value="-1">HOP 5 GHz</option><option value="-2">HOP DUAL</option>';
 o+='<optgroup label="2.4 GHz lock">';CH24.forEach(c=>o+=`<option value="${c}">ch ${c}</option>`);o+='</optgroup>';
 if(dual){o+='<optgroup label="5 GHz lock">';CH5.forEach(c=>o+=`<option value="${c}">ch ${c}</option>`);o+='</optgroup>';}
 return o;}
async function post(b){try{await fetch('/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});}catch(e){}}
function setCh(mac,v){post({action:'set',mac:mac,ch:parseInt(v,10)});}
document.getElementById('allhop').onclick=()=>post({action:'allhop'});
function fillBand(el,chans,counts,gmax){
 if(el.children.length!==chans.length){el.innerHTML='';el.style.gridTemplateColumns=`repeat(${chans.length},1fr)`;
  chans.forEach(c=>el.insertAdjacentHTML('beforeend',`<div class="ch"><div class="f"></div><div class="bar"></div><div class="n">${c}</div></div>`));}
 chans.forEach((c,idx)=>{const cnt=counts[idx]||0,load=Math.min(cnt/gmax,1),e=el.children[idx];
  e.classList.toggle('on',cnt>0);const bar=e.querySelector('.bar');
  bar.style.height=(cnt>0?8+load*100:2)+'px';
  bar.style.background=cnt>0?CH_COLOR(load):'#17323a';bar.style.color=cnt>0?CH_COLOR(load):'transparent';
  e.querySelector('.f').textContent=cnt>0?fmtK(cnt):'';});}
async function tick(){
 let d; try{d=await(await fetch('/stats',{cache:'no-store'})).json();}catch(e){return;}
 document.getElementById('nn').textContent=d.nodes.length;
 document.getElementById('tf').textContent=d.fps_total;
 document.getElementById('tt').textContent=d.total.toLocaleString();
 document.getElementById('up').textContent=fmtUp(d.uptime);
 const gmax=Math.max(1,...d.band24,...d.band5);
 fillBand(document.getElementById('band'),CH24,d.band24,gmax);
 const sec5=document.getElementById('sec5');
 if(d.has5){sec5.style.display='';fillBand(document.getElementById('band5'),d.ch5,d.band5,gmax);}
 else sec5.style.display='none';
 const peak=Math.max(...d.nodes.map(n=>n.fps),1);
 const cards=document.getElementById('cards');
 if(cards.children.length!==d.nodes.length){cards.innerHTML=d.nodes.map((n,i)=>
  `<div class="card" id="cd${i}">
    <div class="top">
     <div class="badge"><div class="cn" id="cn${i}">${n.label}</div><div class="cl" id="cl${i}">${n.ch<1?'SWEEP':'CHAN'}</div></div>
     <div><div class="mac">${n.mac}</div><div class="meta" id="mt${i}"></div></div>
     <div class="fps"><b id="fp${i}">0</b><span>FRAMES/S</span></div>
    </div>
    <div class="ctl"><select id="se${i}" onchange="setCh('${n.mac}',this.value)">${chOptions(n.dual)}</select>${n.dual?'<span class="tag">DUAL</span>':''}</div>
    <div class="pbar"><i id="pb${i}"></i></div>
    <div id="sp${i}"></div>
   </div>`).join('');}
 d.nodes.forEach((n,i)=>{
   document.getElementById('fp'+i).textContent=n.fps;
   document.getElementById('cn'+i).textContent=n.label;
   document.getElementById('cl'+i).textContent=n.ch<1?'SWEEP':'CHAN';
   const se=document.getElementById('se'+i);if(se&&document.activeElement!==se)se.value=String(n.ch);
   const seenBad=n.ch_seen&&n.ch>0&&n.ch_seen!==n.ch;   // only flag a mismatch when the node is locked
   document.getElementById('mt'+i).innerHTML=`${n.total.toLocaleString()} frames`+(seenBad?` <span class="warn">&#9888; sees ch${n.ch_seen}</span>`:``);
   const i2=document.getElementById('pb'+i);const load=Math.min(n.fps/peak,1);
   i2.style.width=(load*100)+'%';
   i2.style.background=load>.66?'linear-gradient(90deg,var(--c2),var(--c3))':'linear-gradient(90deg,var(--c1),var(--acc))';
   document.getElementById('sp'+i).innerHTML=spark(n.hist);});
}
tick();setInterval(tick,500);
</script></body></html>"""

class _WebHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ctype):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith("/stats"):
            nodes = _WEB["nodes"]
            b24 = [0] * 13                                  # channels 1..13, hopping-aware
            b5 = {c: 0 for c in CH5}
            for n in nodes:
                for c, cnt in n.chan_count.items():
                    if 1 <= c <= 13: b24[c - 1] += cnt
                    elif c in b5:    b5[c] += cnt
            data = {"nodes": [{"mac": n.mac, "ch": n.channel, "label": n.label(), "fps": n.fps(),
                               "total": n.total, "ch_seen": freq_to_ch(n.last_freq), "dual": n.dual,
                               "hist": list(n.hist)} for n in nodes],
                    "total": sum(n.total for n in nodes),
                    "fps_total": sum(n.fps() for n in nodes),
                    "uptime": time.time() - _WEB["t0"],
                    "band24": b24, "ch5": CH5, "band5": [b5[c] for c in CH5],
                    "has5": any(n.dual for n in nodes)}
            self._send(json.dumps(data).encode(), "application/json")
        else:
            self._send(HTML_PAGE.encode(), "text/html; charset=utf-8")

    def do_POST(self):
        # live channel control from the web UI: {"action":"set","mac":..,"ch":int} or {"action":"allhop"}
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            req = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            req = {}
        nodes = _WEB["nodes"]; act = req.get("action")
        if act == "allhop":
            for n in nodes: n.set_channel(-1 if n.dual else 0)   # C5 -> hop5, the rest -> hop
        elif act == "set":
            mac = req.get("mac"); ch = req.get("ch")
            if isinstance(ch, int):
                for n in nodes:
                    if n.mac != mac: continue
                    ok = ch == 0 or (1 <= ch <= 14)                      # hop + 2.4 locks: any node
                    if n.dual: ok = ok or ch in (-1, -2) or ch in CH5    # 5 GHz only on dual-band
                    if ok: n.set_channel(ch)
        self._send(b'{"ok":true}', "application/json")

def start_web(nodes, port):
    _WEB["nodes"] = nodes; _WEB["t0"] = time.time()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), _WebHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

# ───────────────────────── main ───────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--channels", default="",
                    help="comma list in sorted-node order. 1-14 = 2.4 GHz, 36-112 = 5 GHz (C5), "
                         "hop = sweep 2.4, hop5 = sweep 5 GHz, hopdual = sweep both. e.g. 1,6,11,hop5")
    ap.add_argument("--no-wireshark", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--seconds", type=int, default=0, help="headless run for N seconds then exit")
    ap.add_argument("--fifo", default="/tmp/sentinel.pcap")
    ap.add_argument("--pipe", action="store_true",
                    help="write the merged pcap to a named pipe (--fifo path), no GUI, and wait "
                         "for a reader. Point any tool at it: kismet, tshark, tcpdump, Wireshark.")
    ap.add_argument("--stdout", action="store_true",
                    help="write the raw merged pcap to stdout (all logs go to stderr), to pipe into "
                         "another tool, e.g. | tshark -r -  or  | tcpdump -r -")
    ap.add_argument("--fcs", choices=["on", "off"], default="on",
                    help="keep the trailing 802.11 FCS and flag it in radiotap (on, default) or strip "
                         "it (off). Use off for Kismet or aircrack-ng: they drop frames whose FCS "
                         "fails to verify, and the ESP32's reported FCS does not verify.")
    ap.add_argument("--web", action="store_true", help="styled web dashboard + auto-open browser")
    ap.add_argument("--port", type=int, default=8808)
    ap.add_argument("--watch", action="store_true",
                    help="wait for nodes to appear, then auto-start (plug-and-go)")
    ap.add_argument("--install-extcap", action="store_true",
                    help="symlink the Wireshark extcap into your Wireshark extcap dir and exit")
    args = ap.parse_args()

    global FCS_MODE; FCS_MODE = args.fcs

    if args.install_extcap:
        install_extcap(); return

    # --stdout: the raw pcap owns fd 1, so every human/log line must go to stderr instead, or it
    # would corrupt the stream. Keep a dup of the real stdout for the pcap writer, then redirect.
    stdout_fd = None
    if args.stdout:
        stdout_fd = os.dup(1)
        sys.stdout = sys.stderr
        args.no_wireshark = True

    if not args.no_wireshark and not args.web and not args.pipe and not args.stdout:
        preflight()

    if args.watch:
        print("watching %s for nodes (Ctrl-C to stop)..." % BYID)
        try:
            nodes_raw = discover()
            while not nodes_raw:
                time.sleep(1.0); nodes_raw = discover()
        except KeyboardInterrupt:
            return
    else:
        nodes_raw = discover()
        if not nodes_raw:
            print("no sentinel nodes found on %s (try --watch to wait, or check the cable/hub)" % BYID)
            sys.exit(1)

    chans = [parse_chan(x) for x in args.channels.split(",") if x.strip()] if args.channels else []
    auto = auto_assign(nodes_raw)                     # band-aware default plan
    final, notes = resolve_plan(nodes_raw, chans, auto)
    for line in notes:
        print(line)
    print("detected %d node(s):" % len(nodes_raw))
    merged_q = queue.Queue(maxsize=20000)
    nodes = []
    for i, (mac, port, dual) in enumerate(nodes_raw):
        n = Node(mac, port, final[i], merged_q, dual=dual); nodes.append(n)
        print("  %-18s -> %-5s (%s)%s" % (mac, n.label(), port, "  dualband" if dual else ""))
    if args.list:
        return

    # open + start every node
    for n in nodes:
        try: n.open(); n.start()
        except Exception as e: print("  ! %s busy/err: %s" % (n.mac, e))

    stop_evt = threading.Event()
    def shutdown(*_):
        stop_evt.set()
    signal.signal(signal.SIGINT, shutdown); signal.signal(signal.SIGTERM, shutdown)

    # Where does the merged pcap go? stdout, a named pipe for any tool, or Wireshark (default).
    ws = None; out_fd = None; close_out = False
    if args.stdout:
        out_fd = stdout_fd                              # raw pcap on the real stdout fd
        threading.Thread(target=merge_writer, args=(merged_q, out_fd, stop_evt), daemon=True).start()
    elif args.pipe:
        try: os.mkfifo(args.fifo)
        except FileExistsError: pass
        print("merged pcap pipe: %s   (100%% passive, receive only)" % args.fifo)
        print("  attach a reader, for example:")
        print("    wireshark -k -i %s" % args.fifo)
        print("    tshark    -r %s" % args.fifo)
        print("    tcpdump   -r %s" % args.fifo)
        print("    kismet -c '%s:type=pcapfile'" % args.fifo)
        print("  (aircrack-ng reads a saved file: ./tools/sentinel.py --stdout --fcs off > capture.pcap)")
        if FCS_MODE != "off":
            print("  ! for Kismet/aircrack, restart with --fcs off or they drop every frame (bad FCS)")
        print("  waiting for a reader to attach (Ctrl-C to stop)...")
        out_fd = open_fifo_write(args.fifo, stop_evt=stop_evt)   # waits until a reader opens the pipe
        if out_fd is not None:
            close_out = True
            print("reader attached, streaming.")
            threading.Thread(target=merge_writer, args=(merged_q, out_fd, stop_evt), daemon=True).start()
    elif not args.no_wireshark:
        try: os.mkfifo(args.fifo)
        except FileExistsError: pass
        ws = subprocess.Popen(["wireshark", "-k", "-i", args.fifo],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        out_fd = open_fifo_write(args.fifo, proc=ws, timeout=8)  # retry until Wireshark opens the read end
        if out_fd is not None:
            close_out = True
            threading.Thread(target=merge_writer, args=(merged_q, out_fd, stop_evt), daemon=True).start()
        else:
            print("Wireshark did not attach to the pipe - dashboard only."); ws = None

    # nothing consuming the merged queue -> discard it so node readers never block
    if out_fd is None:
        def _discard():
            while not stop_evt.is_set():
                try: merged_q.get(timeout=0.3)
                except queue.Empty: pass
        threading.Thread(target=_discard, daemon=True).start()

    # per-second sampler feeds the web sparklines
    threading.Thread(target=sampler_loop, args=(nodes, stop_evt), daemon=True).start()

    try:
        if args.web:
            srv = start_web(nodes, args.port)
            url = "http://127.0.0.1:%d" % args.port
            print("web dashboard: %s" % url)
            try: subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception: pass
            while not stop_evt.is_set(): time.sleep(0.5)
        elif args.stdout:                               # pcap owns stdout: stream quietly, no curses
            t0 = time.time()
            while not stop_evt.is_set():
                if args.seconds > 0 and time.time() - t0 >= args.seconds: break
                time.sleep(0.5)
        elif args.seconds > 0:                          # headless
            t0 = time.time()
            while time.time() - t0 < args.seconds and not stop_evt.is_set():
                time.sleep(1.0)
                line = "  ".join("%s %s:%dfps/%d" % (n.mac[-5:], n.label(), n.fps(), n.total) for n in nodes)
                print("[%2ds] %s" % (int(time.time()-t0), line))
        else:
            try:
                run_dashboard(nodes, stop_evt)
            except Exception as e:
                # curses unavailable (no tty, tiny terminal, render error) -> text until Ctrl-C.
                # surface the reason instead of degrading silently, so real bugs are visible.
                print("dashboard (curses) unavailable: %s: %s - text mode" % (type(e).__name__, e))
                while not stop_evt.is_set():
                    time.sleep(1.0)
                    print("  ".join("%s ch%d:%dfps/%d" % (n.mac[-5:], n.channel, n.fps(), n.total) for n in nodes), flush=True)
    finally:
        stop_evt.set()
        for n in nodes: n.stop()
        if out_fd is not None and close_out:            # close only a FIFO we opened, never stdout
            try: os.close(out_fd)
            except Exception: pass
        if ws: ws.terminate()
        if not args.stdout:                             # remove the FIFO (none created in stdout mode)
            try: os.unlink(args.fifo)
            except Exception: pass
        print("\nstopped. per-node totals:")
        for n in nodes: print("  %-18s %-5s  %d frames" % (n.mac, n.label(), n.total))

if __name__ == "__main__":
    main()
