package com.evilsentinel.sentinel

import android.app.Application
import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.evilsentinel.sentinel.core.Chan
import com.evilsentinel.sentinel.core.CrackUi
import com.evilsentinel.sentinel.core.Cracker
import com.evilsentinel.sentinel.core.Dot11
import com.evilsentinel.sentinel.core.HandshakeCollector
import com.evilsentinel.sentinel.core.HandshakeUi
import com.evilsentinel.sentinel.core.NodeUi
import com.evilsentinel.sentinel.core.PacketRow
import com.evilsentinel.sentinel.core.Pcap
import com.evilsentinel.sentinel.core.SerialNode
import com.evilsentinel.sentinel.core.UiState
import java.util.concurrent.atomic.AtomicLong
import com.evilsentinel.sentinel.usb.SentinelProber
import com.hoho.android.usbserial.driver.UsbSerialPort
import com.hoho.android.usbserial.util.SerialInputOutputManager
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Orchestrates the whole capture: discover nodes, get USB permission, handshake, assign one
 * band-aware channel per node, stream every node, merge into one crash-safe pcap, collect WPA
 * handshakes, and publish a live [UiState]. This is sentinel.py, transposed to Android.
 */
class CaptureViewModel(app: Application) : AndroidViewModel(app) {

    private val usb = app.getSystemService(Context.USB_SERVICE) as UsbManager

    private val _state = MutableStateFlow(UiState())
    val state = _state.asStateFlow()

    // live packet reader: a bounded ring filled by the node threads, filtered for the UI
    private val packetRing = ArrayDeque<PacketRow>()
    private val packetLock = Any()
    private val packetSeq = AtomicLong(0)
    private val RING_MAX = 20000
    private val SHOW_MAX = 1200
    @Volatile private var frozen = false
    @Volatile private var filterText = ""
    @Volatile private var filterType = ""
    private val _packets = MutableStateFlow<List<PacketRow>>(emptyList())
    val packets = _packets.asStateFlow()
    @Volatile var matchCount = 0; private set
    @Volatile var ringCount = 0; private set

    // WPA handshake collection
    private val collector = HandshakeCollector()
    private val _handshakes = MutableStateFlow<List<HandshakeUi>>(emptyList())
    val handshakes = _handshakes.asStateFlow()

    // in-app dictionary cracker
    private val _crack = MutableStateFlow<CrackUi?>(null)
    val crack = _crack.asStateFlow()
    private var crackJob: Job? = null
    private var crackStop = AtomicBoolean(false)

    // Real per-channel frame counts, keyed by each frame's own radiotap channel. A hopping node
    // thus shows up on every channel it sweeps, not only on a locked channel (hop nodes have none).
    private val chan24 = java.util.concurrent.atomic.AtomicLongArray(15)            // index = 2.4 GHz ch 1..14
    private val chan5 = java.util.concurrent.atomic.AtomicLongArray(Chan.CH5.size)  // indexed like Chan.CH5

    // 2.4 GHz non-overlapping first, then the rest. Dual-band nodes default to a 5 GHz sweep.
    private val plan = intArrayOf(1, 6, 11, 3, 8, 13, 2, 4, 5, 7, 9, 10, 12, 14)
    private val desired = ConcurrentHashMap<String, Int>()

    private val nodes = ArrayList<Pair<SerialNode, SerialInputOutputManager>>()
    private val permissionWaiters = ConcurrentHashMap<Int, CompletableDeferred<Boolean>>()

    private val mergeQ = LinkedBlockingQueue<ByteArray>(20000)
    private val droppedMerge = AtomicLong(0)
    @Volatile private var writerRun = false
    private var writerThread: Thread? = null
    private var out: BufferedOutputStream? = null
    private var rawFos: FileOutputStream? = null        // kept for fd.sync() crash safety
    private var captureFile: File? = null

    private var tickJob: Job? = null
    private var startedAt = 0L

    /** Injected by the Activity: fires the system USB permission dialog for [device]. */
    var requestPermission: ((UsbDevice) -> Unit)? = null

    fun deliverPermission(deviceId: Int, granted: Boolean) {
        permissionWaiters.remove(deviceId)?.complete(granted)
    }

    /** Hot-plug: do NOT tear the capture down. A node that really vanished is flagged by its
     *  own onRunError (connected=false); the single pcap and the other nodes keep going. If no
     *  capture is running yet, a freshly attached node triggers auto-start. */
    fun onDeviceDetached() { /* intentionally minimal: see onRunError + autoStart */ }

    /** Start automatically when at least one candidate USB device is present. */
    fun autoStart() {
        if (_state.value.running || _state.value.scanning) return
        if (SentinelProber.findDrivers(usb).isNotEmpty()) start()
    }

    fun start() {
        if (_state.value.running || _state.value.scanning) return
        _state.value = _state.value.copy(scanning = true, message = "Scanning USB...")
        viewModelScope.launch(Dispatchers.IO) {
            try { discoverAndStart() }
            catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _state.value = _state.value.copy(scanning = false, message = "Error: ${e.message}")
                }
            }
        }
    }

    private suspend fun discoverAndStart() {
        val drivers = SentinelProber.findDrivers(usb)
        if (drivers.isEmpty()) {
            _state.value = _state.value.copy(scanning = false,
                message = "No USB device. Plug the rig into a powered hub.")
            return
        }

        var permissionDenied = 0
        var notSentinel = 0
        val found = ArrayList<SerialNode>()
        for (driver in drivers) {
            val device = driver.device
            if (!usb.hasPermission(device)) {
                val def = CompletableDeferred<Boolean>()
                permissionWaiters[device.deviceId] = def
                withContext(Dispatchers.Main) { requestPermission?.invoke(device) }
                val granted = withTimeoutOrNull(30000) { def.await() } ?: false
                if (!granted) { permissionDenied++; continue }
            }
            val conn = usb.openDevice(device) ?: continue
            val port = driver.ports.firstOrNull() ?: continue
            try {
                port.open(conn)
                port.setParameters(115200, 8, UsbSerialPort.STOPBITS_1, UsbSerialPort.PARITY_NONE)
                try { port.dtr = true; port.rts = true } catch (_: Exception) {}
            } catch (e: Exception) { continue }

            val (ok, dual) = handshake(port)
            if (!ok) { notSentinel++; runCatching { port.close() }; continue }

            val key = device.serialNumber ?: device.deviceName
            val node = SerialNode(key, key, chipOf(device, dual), port) { rec ->
                if (!mergeQ.offer(rec)) droppedMerge.incrementAndGet()
                collector.feed(rec)
                countChannel(rec)
                appendPacket(rec)
            }
            node.dualband = dual
            found.add(node)
        }

        if (found.isEmpty()) {
            val msg = when {
                permissionDenied > 0 -> "USB permission denied. Replug and tap Always allow."
                notSentinel > 0 -> "Found $notSentinel USB device(s), none is a sentinel node. Flash the firmware?"
                else -> "No sentinel node found. Check hub power and cables."
            }
            _state.value = _state.value.copy(scanning = false, message = msg)
            return
        }

        found.sortBy { it.key }
        var si = 0                                   // index into the 2.4 GHz plan (single-band nodes)
        for (node in found) {
            val ch = desired[node.key] ?: if (node.dualband) Chan.HOP5 else plan[si++ % plan.size]
            node.channel = ch
            node.send(Chan.cmd(ch))
            Thread.sleep(80)
            node.send("S".toByteArray())
        }

        for (c in 0 until chan24.length()) chan24.set(c, 0)   // fresh per-channel tally for this run
        for (c in 0 until chan5.length()) chan5.set(c, 0)
        openPcap()
        startWriter()

        nodes.clear()
        for (node in found) {
            val io = SerialInputOutputManager(node.port, object : SerialInputOutputManager.Listener {
                override fun onNewData(data: ByteArray) { node.onData(data) }
                override fun onRunError(e: Exception) { node.connected = false }
            })
            io.start()
            nodes.add(node to io)
        }

        startedAt = System.currentTimeMillis()
        CaptureService.start(getApplication())
        _state.value = _state.value.copy(
            running = true, scanning = false,
            captureFile = captureFile?.absolutePath,
            message = "Capturing ${found.size} node(s)."
        )
        startTicker()
    }

    /** Returns (isSentinel, dualband). Reads the full id line so " dualband" is seen too. */
    private fun handshake(port: UsbSerialPort): Pair<Boolean, Boolean> {
        return try {
            port.write("X".toByteArray(), 300)
            drain(port, 150)
            port.write("id\n".toByteArray(), 300)
            val b = ByteArray(512); val sb = StringBuilder()
            val end = System.currentTimeMillis() + 600
            while (System.currentTimeMillis() < end) {
                val n = port.read(b, 120)
                if (n > 0) sb.append(String(b, 0, n, Charsets.US_ASCII))
            }
            val s = sb.toString()
            Pair(s.contains("sentinel"), s.contains("dualband"))
        } catch (e: Exception) { Pair(false, false) }
    }

    private fun drain(port: UsbSerialPort, ms: Int) {
        val b = ByteArray(1024); val end = System.currentTimeMillis() + ms
        while (System.currentTimeMillis() < end) { try { if (port.read(b, 60) <= 0) {} } catch (_: Exception) { break } }
    }

    private fun chipOf(d: UsbDevice, dual: Boolean): String = when {
        dual -> "C5 dual-band"
        d.vendorId == 0x303a -> "2.4 GHz"
        else -> "bridge"
    }

    fun setChannel(key: String, ch: Int) {
        desired[key] = ch
        val node = nodes.firstOrNull { it.first.key == key }?.first ?: return
        node.channel = ch
        node.send(Chan.cmd(ch))
    }

    fun setFilter(text: String, type: String) {
        filterText = text.trim().lowercase()
        filterType = type
        if (!frozen) recomputePackets()
    }

    private fun recomputePackets() {
        val snap = synchronized(packetLock) { packetRing.toList() }
        ringCount = snap.size
        var m = 0
        val out = ArrayList<PacketRow>(SHOW_MAX)
        for (i in snap.indices.reversed()) {
            val r = snap[i]
            if (matches(r)) { m++; if (out.size < SHOW_MAX) out.add(r) }
        }
        matchCount = m
        out.reverse()   // oldest-first so the live edge sits at the bottom, Wireshark style
        _packets.value = out
    }

    fun setFrozen(f: Boolean) { frozen = f }

    fun clearPackets() { synchronized(packetLock) { packetRing.clear() }; _packets.value = emptyList() }

    /** Tally this frame onto the channel it was actually received on (radiotap), cheap hot-path. */
    private fun countChannel(rec: ByteArray) {
        val ch = Dot11.freqToChannel(Dot11.radiotapFreq(rec))
        if (ch in 1..14) chan24.incrementAndGet(ch)
        else { val idx = Chan.CH5.indexOf(ch); if (idx >= 0) chan5.incrementAndGet(idx) }
    }

    private fun appendPacket(rec: ByteArray) {
        val f = Dot11.describe(rec)
        val ch = Dot11.freqToChannel(Dot11.radiotapFreq(rec))
        val row = PacketRow(
            packetSeq.incrementAndGet(), System.currentTimeMillis(), ch,
            f.type, f.ssid, f.src, f.bssid, rec.size, Dot11.rssi(rec),
        )
        synchronized(packetLock) {
            packetRing.addLast(row)
            while (packetRing.size > RING_MAX) packetRing.removeFirst()
        }
    }

    private fun matches(r: PacketRow): Boolean {
        if (filterType.isNotEmpty()) {
            val ok = if (filterType == "eapol") r.type.startsWith("eapol") else r.type == filterType
            if (!ok) return false
        }
        val ft = filterText
        if (ft.isEmpty()) return true
        return (r.ssid?.lowercase()?.contains(ft) == true) ||
            (r.src?.contains(ft) == true) || (r.bssid?.contains(ft) == true) ||
            r.type.contains(ft) || r.ch.toString() == ft
    }

    // ---- WPA handshake export ----
    /** Write a hashcat 22000 file (all BSSIDs, or just [bssid]) next to the pcap. null if empty. */
    fun exportHandshakes(bssid: String? = null): File? {
        val text = collector.export22000(bssid)
        if (text.isEmpty()) return null
        val dir = File(getApplication<Application>().getExternalFilesDir(null), "captures").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(System.currentTimeMillis())
        val name = if (bssid != null) "sentinel-${bssid.replace(":", "")}-$stamp.hc22000" else "sentinel-$stamp.hc22000"
        val f = File(dir, name)
        f.writeText(text)
        return f
    }

    // ---- in-app WPA dictionary cracker ----
    /** Crack [bssid] against a wordlist: a user-picked file [uri], or the bundled list when null. */
    fun startCrack(bssid: String, uri: Uri?) {
        stopCrack()
        val target = collector.target(bssid)
        if (target == null || (!target.canPmkid && !target.canEapol)) {
            _crack.value = CrackUi(bssid, null, false, 0, 0, null, true, "nothing crackable yet")
            return
        }
        val essidStr = String(target.essid, Charsets.UTF_8).ifEmpty { null }
        if (essidStr == null) {
            _crack.value = CrackUi(bssid, null, false, 0, 0, null, true, "hidden SSID: cannot derive the key")
            return
        }
        val stop = AtomicBoolean(false); crackStop = stop
        _crack.value = CrackUi(bssid, essidStr, true, 0, 0, null, false, "starting...")
        crackJob = viewModelScope.launch(Dispatchers.Default) {
            val ctx = getApplication<Application>()
            val reader: BufferedReader = try {
                val stream = if (uri != null) ctx.contentResolver.openInputStream(uri)
                    else ctx.assets.open("wordlist-top.txt")
                BufferedReader(InputStreamReader(stream))
            } catch (e: Exception) {
                _crack.value = CrackUi(bssid, essidStr, false, 0, 0, null, true, "cannot open wordlist")
                return@launch
            }
            val startMs = System.currentTimeMillis()
            val threads = Runtime.getRuntime().availableProcessors().coerceIn(2, 8)
            val found = try {
                Cracker.crack(target, { reader.readLine() }, threads, { tried ->
                    val secs = ((System.currentTimeMillis() - startMs) / 1000.0).coerceAtLeast(0.001)
                    _crack.value = _crack.value?.copy(tried = tried, rate = (tried / secs).toInt(), message = null)
                }, stop)
            } finally { runCatching { reader.close() } }
            if (found != null) { collector.setCracked(bssid, found); _handshakes.value = collector.snapshot() }
            _crack.value = CrackUi(bssid, essidStr, false, _crack.value?.tried ?: 0, _crack.value?.rate ?: 0,
                found, true, if (found != null) "cracked" else if (stop.get()) "stopped" else "not in wordlist")
        }
    }

    fun stopCrack() { crackStop.set(true); crackJob?.cancel(); crackJob = null }

    fun dismissCrack() { if (_crack.value?.running != true) _crack.value = null }

    // ---- pcap merge writer (crash-safe: periodic flush + fsync) ----
    private fun openPcap() {
        val dir = File(getApplication<Application>().getExternalFilesDir(null), "captures").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(System.currentTimeMillis())
        val f = File(dir, "sentinel-$stamp.pcap")
        val fos = FileOutputStream(f)
        val os = BufferedOutputStream(fos)
        os.write(Pcap.globalHeader())
        rawFos = fos; out = os; captureFile = f
    }

    private fun startWriter() {
        writerRun = true
        writerThread = Thread {
            val os = out ?: return@Thread
            var lastSync = System.currentTimeMillis()
            while (writerRun) {
                val rec = try { mergeQ.poll(300, java.util.concurrent.TimeUnit.MILLISECONDS) }
                catch (e: InterruptedException) { break }
                if (rec != null) {
                    val ms = System.currentTimeMillis()
                    try {
                        os.write(Pcap.recordHeader(ms / 1000, (ms % 1000) * 1000, rec.size, rec.size))
                        os.write(rec)
                    } catch (e: Exception) { break }
                }
                val now = System.currentTimeMillis()
                if (now - lastSync >= 1000) {                 // flush + fsync so a kill keeps the tail
                    lastSync = now
                    try { os.flush(); rawFos?.fd?.sync() } catch (_: Exception) {}
                }
            }
            try { os.flush(); rawFos?.fd?.sync() } catch (_: Exception) {}
        }.apply { isDaemon = true; start() }
    }

    // ---- live stats ----
    private fun startTicker() {
        tickJob?.cancel()
        tickJob = viewModelScope.launch {
            var lastSample = 0L
            while (_state.value.running) {
                val now = System.currentTimeMillis()
                if (now - lastSample >= 1000) { nodes.forEach { it.first.sampleHist() }; lastSample = now }
                // bars reflect real per-channel counts (works for locked and hopping nodes alike)
                val band = LongArray(15) { if (it in 1..14) chan24.get(it) else 0L }
                val band5 = LongArray(Chan.CH5.size) { chan5.get(it) }
                var has5 = false
                val uiNodes = nodes.map { (n, _) ->
                    if (n.dualband || Chan.is5GHz(n.channel) || n.channel == Chan.HOP5 || n.channel == Chan.HOPDUAL) has5 = true
                    NodeUi(n.key, n.displayName, n.chip, n.channel, n.label(),
                        n.fps(), n.total.get(), n.seenChannel(), n.connected, n.dualband,
                        n.dropped.get(), n.hist())
                }
                _handshakes.value = collector.snapshot()
                _state.value = _state.value.copy(
                    nodes = uiNodes,
                    band = band.toList(),
                    band5 = band5.toList(),
                    has5GHz = has5,
                    totalFrames = uiNodes.sumOf { it.total },
                    fpsTotal = uiNodes.sumOf { it.fps },
                    dropped = droppedMerge.get() + uiNodes.sumOf { it.dropped },
                    uptimeSec = (now - startedAt) / 1000,
                    handshakes = collector.count(),
                )
                if (!frozen) recomputePackets()
                delay(300)
            }
        }
    }

    fun stopCapture() {
        tickJob?.cancel()
        for ((node, io) in nodes) {
            runCatching { io.stop() }
            runCatching { node.send("X".toByteArray()) }
            runCatching { node.port.close() }
        }
        nodes.clear()
        writerRun = false
        writerThread?.join(500)
        runCatching { out?.flush(); rawFos?.fd?.sync(); out?.close() }
        out = null; rawFos = null
        CaptureService.stop(getApplication())
        _state.value = _state.value.copy(
            running = false, scanning = false,
            message = captureFile?.let { "Saved ${it.name}" } ?: "Stopped",
        )
    }

    /** Path of the finished (or in-progress) capture, for sharing. */
    fun currentCaptureFile(): File? = captureFile

    override fun onCleared() { stopCapture() }
}
