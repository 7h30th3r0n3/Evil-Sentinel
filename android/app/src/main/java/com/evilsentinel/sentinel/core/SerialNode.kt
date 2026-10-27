package com.evilsentinel.sentinel.core

import com.hoho.android.usbserial.driver.UsbSerialPort
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicLong

/**
 * One ESP32 node: owns its serial port, parses the pcap stream it sends, counts frames,
 * and hands each frame payload to the merge writer. Mirrors the Node class in sentinel.py.
 *
 * The receive buffer is a single reusable array with head/tail indices, so a busy multi-node
 * capture does not allocate a new array on every USB callback (no GC churn on the hot path).
 */
class SerialNode(
    val key: String,            // USB serial number (the MAC on native-USB chips) or device name
    val displayName: String,
    val chip: String,           // "C3" / "C5" / "C6" / "ESP32" / "?"
    val port: UsbSerialPort,
    private val onPayload: (ByteArray) -> Unit,
) {
    @Volatile var channel: Int = 0          // see core.Chan: 0 hop2.4, -1 hop5, -2 hopdual, >=1 lock
    @Volatile var dualband: Boolean = false // true on ESP32-C5 (5 GHz capable)
    @Volatile var lastFreq: Int = 0
    @Volatile var connected: Boolean = true
    val total = AtomicLong(0)
    val dropped = AtomicLong(0)             // bytes discarded on overflow/resync (health signal)

    private val win = ConcurrentLinkedDeque<Long>()      // recent frame timestamps -> fps
    private val histBuf = ArrayDeque<Int>().apply { repeat(HIST) { add(0) } }

    private var buf = ByteArray(INIT_CAP)
    private var head = 0                     // valid data is buf[head until tail)
    private var tail = 0
    private var synced = false

    fun label(): String = Chan.label(channel)
    fun seenChannel(): Int = Dot11.freqToChannel(lastFreq)

    fun fps(): Int {
        val now = System.currentTimeMillis()
        while (true) {
            val h = win.peekFirst() ?: break
            if (now - h > 1000) win.pollFirst() else break
        }
        return win.size
    }

    fun hist(): List<Int> = synchronized(histBuf) { histBuf.toList() }
    fun sampleHist() = synchronized(histBuf) {
        if (histBuf.size >= HIST) histBuf.removeFirst()
        histBuf.addLast(fps())
    }

    /** Feed raw bytes from the USB read thread. Parses as many complete records as available. */
    fun onData(data: ByteArray) {
        append(data)
        if (!synced) {
            val i = indexOf(Pcap.MAGIC_LE)
            if (i < 0) {
                if (tail - head > 65536) head = tail - 64   // keep only a small tail while hunting
                compactIfEmpty()
                return
            }
            head = i + Pcap.GLOBAL_HEADER_LEN
            synced = true
        }
        while (tail - head >= Pcap.RECORD_HEADER_LEN) {
            val caplen = Pcap.readLe32(buf, head + 8).toInt()
            if (caplen <= 0 || caplen > 4096) { head += 1; dropped.incrementAndGet(); continue }
            if (tail - head < Pcap.RECORD_HEADER_LEN + caplen) break
            val rec = buf.copyOfRange(head + Pcap.RECORD_HEADER_LEN, head + Pcap.RECORD_HEADER_LEN + caplen)
            head += Pcap.RECORD_HEADER_LEN + caplen
            total.incrementAndGet()
            win.addLast(System.currentTimeMillis())
            lastFreq = Dot11.radiotapFreq(rec)
            onPayload(rec)
        }
        compactIfEmpty()
    }

    private fun append(data: ByteArray) {
        val used = tail - head
        if (tail + data.size > buf.size) {
            if (used + data.size <= buf.size) {
                System.arraycopy(buf, head, buf, 0, used)        // compact in place
            } else {
                var nc = buf.size * 2
                while (used + data.size > nc && nc < MAX_CAP) nc *= 2
                if (used + data.size > nc) {                      // would exceed the hard cap: drop oldest
                    dropped.addAndGet(used.toLong()); head = tail; synced = false
                    buf = ByteArray(maxOf(INIT_CAP, data.size)); head = 0; tail = 0
                    System.arraycopy(data, 0, buf, 0, data.size); tail = data.size
                    return
                }
                val nb = ByteArray(nc); System.arraycopy(buf, head, nb, 0, used); buf = nb
            }
            head = 0; tail = used
        }
        System.arraycopy(data, 0, buf, tail, data.size); tail += data.size
    }

    private fun compactIfEmpty() { if (head >= tail) { head = 0; tail = 0 } }

    private fun indexOf(needle: ByteArray): Int {
        val last = tail - needle.size
        var i = head
        outer@ while (i <= last) {
            for (j in needle.indices) if (buf[i + j] != needle[j]) { i++; continue@outer }
            return i
        }
        return -1
    }

    /** Send a one-shot serial command (channel lock, hop, start, stop). */
    fun send(cmd: ByteArray) {
        try { port.write(cmd, WRITE_TIMEOUT) } catch (_: Exception) { connected = false }
    }

    companion object {
        const val WRITE_TIMEOUT = 500
        private const val HIST = 32
        private const val INIT_CAP = 16384
        private const val MAX_CAP = 262144
    }
}
