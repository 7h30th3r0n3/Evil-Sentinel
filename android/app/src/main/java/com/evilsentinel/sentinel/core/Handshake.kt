package com.evilsentinel.sentinel.core

/**
 * Collects WPA material from the live capture and exports hashcat 22000.
 *  - PMKID (WPA*01*) from the RSN PMKID KDE in EAPOL message 1.
 *  - EAPOL (WPA*02*) from the ANonce (message 1) paired with the MIC + frame of message 2.
 * Grouped per BSSID. Fed one raw pcap record (15-byte radiotap + 802.11) at a time; the feed
 * path is cheap for non-EAPOL frames. Thread-safe (the node read threads all call feed()).
 */
class HandshakeCollector {

    private class Entry {
        var essid: ByteArray? = null
        var apMac: ByteArray? = null
        var staMac: ByteArray? = null
        var m1 = false; var m2 = false; var m3 = false; var m4 = false
        var anonce: ByteArray? = null          // from M1
        var m2Frame: ByteArray? = null         // full 802.1X frame of M2, MIC zeroed
        var m2Mic: ByteArray? = null           // MIC from M2
        var pmkid: ByteArray? = null           // from M1 key data
        var lastSeen = 0L                      // ms of the last frame touching this BSSID
    }

    private val lock = Any()
    private val byBssid = LinkedHashMap<String, Entry>()
    private val cracked = HashMap<String, String>()        // bssid -> recovered passphrase

    companion object {
        // Drop a BSSID not seen for this long, unless it already holds crackable material.
        private const val STALE_MS = 120_000L
    }

    fun feed(rec: ByteArray) {
        if (rec.size < 16) return
        val itLen = (rec[2].toInt() and 0xff) or ((rec[3].toInt() and 0xff) shl 8)
        if (itLen < 12 || rec.size <= itLen + 1) return
        val fc = rec[itLen].toInt() and 0xff
        val type = (fc shr 2) and 0x3
        val subtype = (fc shr 4) and 0xf

        if (type == 0 && (subtype == 8 || subtype == 5)) {        // beacon / probe-resp -> learn ESSID
            val bssid = macBytes(rec, itLen + 16) ?: return
            val ssid = ssidBytes(rec, itLen + 24 + 12) ?: return
            val key = hex(bssid)
            synchronized(lock) {
                val e = byBssid.getOrPut(key) { Entry() }
                if (e.essid == null && ssid.isNotEmpty()) e.essid = ssid
                if (e.apMac == null) e.apMac = bssid
                e.lastSeen = System.currentTimeMillis()
            }
            return
        }
        if (type != 2) return                                      // only data frames carry EAPOL
        val p = indexOfEapol(rec, itLen)
        if (p < 0) return
        parseEapol(rec, itLen, p)
    }

    private fun parseEapol(rec: ByteArray, itLen: Int, p: Int) {
        val eap = p + 8                                            // 802.1X version byte
        if (eap + 99 > rec.size) return
        if ((rec[eap + 1].toInt() and 0xff) != 3) return           // EAPOL-Key only
        val ki = ((rec[eap + 5].toInt() and 0xff) shl 8) or (rec[eap + 6].toInt() and 0xff)
        val mic = ki and 0x0100 != 0
        val ack = ki and 0x0080 != 0
        val install = ki and 0x0040 != 0
        val secure = ki and 0x0200 != 0

        val flags = rec[itLen + 1].toInt() and 0xff
        val toDs = flags and 0x01 != 0
        val fromDs = flags and 0x02 != 0
        val a1 = macBytes(rec, itLen + 4) ?: return
        val a2 = macBytes(rec, itLen + 10) ?: return
        val a3 = macBytes(rec, itLen + 16) ?: return
        val ap: ByteArray; val sta: ByteArray
        when {
            fromDs && !toDs -> { ap = a2; sta = a1 }
            toDs && !fromDs -> { ap = a1; sta = a2 }
            else -> { ap = a3; sta = a2 }
        }
        val key = hex(ap)

        val msg = when {
            !mic && ack -> 1
            mic && ack && install -> 3
            mic && !ack && secure -> 4
            mic && !ack -> 2
            else -> 0
        }
        val bodyLen = ((rec[eap + 2].toInt() and 0xff) shl 8) or (rec[eap + 3].toInt() and 0xff)
        val frameLen = (4 + bodyLen).coerceAtMost(rec.size - eap)
        val kdl = ((rec[eap + 97].toInt() and 0xff) shl 8) or (rec[eap + 98].toInt() and 0xff)

        synchronized(lock) {
            val e = byBssid.getOrPut(key) { Entry() }
            e.apMac = ap; e.staMac = sta
            e.lastSeen = System.currentTimeMillis()
            when (msg) {
                1 -> {
                    e.m1 = true
                    e.anonce = rec.copyOfRange(eap + 17, eap + 49)
                    if (kdl > 0 && eap + 99 + kdl <= rec.size)
                        e.pmkid = pmkidFrom(rec, eap + 99, kdl) ?: e.pmkid
                }
                2 -> {
                    e.m2 = true
                    if (eap + frameLen <= rec.size) {
                        val frame = rec.copyOfRange(eap, eap + frameLen)
                        e.m2Mic = frame.copyOfRange(81, 97)        // MIC within the frame
                        for (i in 81 until 97) frame[i] = 0        // zero MIC for hashcat
                        e.m2Frame = frame
                    }
                }
                3 -> e.m3 = true
                4 -> e.m4 = true
            }
        }
    }

    private fun exportable(e: Entry): Boolean =
        e.pmkid != null || (e.anonce != null && e.m2Frame != null && e.m2Mic != null)

    /** Forget BSSIDs not seen for [STALE_MS], but never one that already carries crackable
     *  material (a captured handshake / PMKID stays until the capture is cleared). */
    private fun prune(now: Long) {
        val it = byBssid.values.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (!exportable(e) && now - e.lastSeen > STALE_MS) it.remove()
        }
    }

    fun snapshot(): List<HandshakeUi> = synchronized(lock) {
        prune(System.currentTimeMillis())
        byBssid.map { (k, e) ->
            HandshakeUi(k, e.essid?.let { safeAscii(it) }, e.m1, e.m2, e.m3, e.m4,
                e.pmkid != null, exportable(e), cracked[k])
        }
    }

    fun count(): Int = synchronized(lock) { byBssid.values.count { exportable(it) } }

    /** Record a recovered passphrase for [bssid] (from the in-app cracker). */
    fun setCracked(bssid: String, passphrase: String) = synchronized(lock) { cracked[bssid] = passphrase }

    /** Raw WPA material for one BSSID, or null if nothing crackable is present yet. */
    fun target(bssid: String): CrackTarget? = synchronized(lock) {
        val e = byBssid[bssid] ?: return null
        val ap = e.apMac ?: return null
        val sta = e.staMac ?: return null
        var snonce: ByteArray? = null
        var micVersion = 0
        val f = e.m2Frame
        if (f != null && f.size >= 49) {
            val ki = ((f[5].toInt() and 0xff) shl 8) or (f[6].toInt() and 0xff)
            micVersion = ki and 0x07                       // key-descriptor version -> MIC algorithm
            snonce = f.copyOfRange(17, 49)                 // SNonce lives in the M2 EAPOL-Key frame
        }
        CrackTarget(bssid, e.essid?.copyOf() ?: ByteArray(0), ap.copyOf(), sta.copyOf(),
            e.pmkid?.copyOf(), e.anonce?.copyOf(), snonce, micVersion, e.m2Frame?.copyOf(), e.m2Mic?.copyOf())
    }

    /** hashcat 22000 lines for all BSSIDs (or just [onlyBssid]). Empty if nothing usable. */
    fun export22000(onlyBssid: String? = null): String = synchronized(lock) {
        val sb = StringBuilder()
        for ((k, e) in byBssid) {
            if (onlyBssid != null && k != onlyBssid) continue
            val ap = e.apMac ?: continue
            val sta = e.staMac ?: continue
            val essidHex = hex(e.essid ?: ByteArray(0))
            val pmkid = e.pmkid
            if (pmkid != null)
                sb.append("WPA*01*").append(hex(pmkid)).append('*').append(hex(ap)).append('*')
                    .append(hex(sta)).append('*').append(essidHex).append("***\n")
            val anonce = e.anonce; val m2 = e.m2Frame; val m2mic = e.m2Mic
            if (anonce != null && m2 != null && m2mic != null)
                sb.append("WPA*02*").append(hex(m2mic)).append('*').append(hex(ap)).append('*')
                    .append(hex(sta)).append('*').append(essidHex).append('*')
                    .append(hex(anonce)).append('*').append(hex(m2)).append("*02\n")
        }
        sb.toString()
    }

    // --- helpers ---
    private val EAPOL = byteArrayOf(0xAA.toByte(), 0xAA.toByte(), 0x03, 0, 0, 0, 0x88.toByte(), 0x8E.toByte())
    private fun indexOfEapol(rec: ByteArray, from: Int): Int {
        val end = minOf(rec.size - EAPOL.size, from + 40)
        var i = from
        while (i <= end) {
            var ok = true
            for (j in EAPOL.indices) if (rec[i + j] != EAPOL[j]) { ok = false; break }
            if (ok) return i
            i++
        }
        return -1
    }

    private fun pmkidFrom(rec: ByteArray, start: Int, len: Int): ByteArray? {
        // scan key data for the RSN PMKID KDE: OUI 00-0F-AC, type 04, then 16-byte PMKID
        val end = minOf(start + len, rec.size) - 20
        var i = start
        while (i <= end) {
            if ((rec[i].toInt() and 0xff) == 0x00 && (rec[i + 1].toInt() and 0xff) == 0x0f &&
                (rec[i + 2].toInt() and 0xff) == 0xac && (rec[i + 3].toInt() and 0xff) == 0x04) {
                val pmkid = rec.copyOfRange(i + 4, i + 20)
                if (pmkid.any { it.toInt() != 0 }) return pmkid     // ignore all-zero PMKIDs
            }
            i++
        }
        return null
    }

    private fun macBytes(rec: ByteArray, off: Int): ByteArray? =
        if (off + 6 <= rec.size) rec.copyOfRange(off, off + 6) else null

    private fun ssidBytes(rec: ByteArray, start: Int): ByteArray? {
        var i = start
        while (i + 2 <= rec.size) {
            val tag = rec[i].toInt() and 0xff
            val len = rec[i + 1].toInt() and 0xff
            if (i + 2 + len > rec.size) break
            if (tag == 0) return rec.copyOfRange(i + 2, i + 2 + len)
            i += 2 + len
        }
        return null
    }

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append("%02x".format(x.toInt() and 0xff))
        return sb.toString()
    }

    private fun safeAscii(b: ByteArray): String =
        try { String(b, Charsets.UTF_8) } catch (e: Exception) { hex(b) }
}
