package com.evilsentinel.sentinel.core

/**
 * Minimal 802.11 + radiotap parsing: enough for the dashboard (channel from radiotap,
 * frame type, and SSID from beacons/probe-responses). Not a full dissector.
 */
object Dot11 {

    fun freqToChannel(freqMHz: Int): Int = when {
        freqMHz == 2484 -> 14
        freqMHz in 2412..2472 -> (freqMHz - 2412) / 5 + 1
        freqMHz >= 5000 -> (freqMHz - 5000) / 5
        else -> 0
    }

    fun channelToFreq(ch: Int): Int = if (ch == 14) 2484 else 2412 + (ch - 1) * 5

    /** radiotap it_len is at [2..3] (LE); the sentinel header is 15 bytes with the
     *  Channel frequency at offset 10 (LE). Returns 0 when not parseable. */
    fun radiotapFreq(rec: ByteArray): Int {
        if (rec.size < 12) return 0
        val itLen = (rec[2].toInt() and 0xff) or ((rec[3].toInt() and 0xff) shl 8)
        if (itLen < 12) return 0
        return (rec[10].toInt() and 0xff) or ((rec[11].toInt() and 0xff) shl 8)
    }

    data class Frame(val type: String, val ssid: String?, val src: String?, val bssid: String?)

    /** rssi is the signed dBm antenna signal at radiotap offset 14 in the sentinel header. */
    fun rssi(rec: ByteArray): Int = if (rec.size > 14) rec[14].toInt() else 0

    fun describe(rec: ByteArray): Frame {
        val itLen = if (rec.size >= 4)
            (rec[2].toInt() and 0xff) or ((rec[3].toInt() and 0xff) shl 8) else 0
        if (itLen <= 0 || rec.size <= itLen + 1) return Frame("?", null, null, null)
        val fc = rec[itLen].toInt() and 0xff
        val type = (fc shr 2) and 0x3
        val subtype = (fc shr 4) and 0xf
        val label = when (type) {
            0 -> when (subtype) {
                8 -> "beacon"; 5 -> "probe-resp"; 4 -> "probe-req"
                11 -> "auth"; 12 -> "deauth"; 10 -> "disassoc"
                0 -> "assoc-req"; 1 -> "assoc-resp"
                else -> "mgmt"
            }
            1 -> "ctrl"
            2 -> eapolLabel(rec, itLen) ?: if (subtype and 0x8 != 0) "qos-data" else "data"
            else -> "?"
        }
        // addr2 (transmitter/src) at mac-header+10, addr3 (bssid) at +16
        val src = mac(rec, itLen + 10)
        val bssid = mac(rec, itLen + 16)
        var ssid: String? = null
        if (type == 0 && (subtype == 8 || subtype == 5)) {
            ssid = parseSsid(rec, itLen + 24 + 12)   // mgmt hdr 24 + fixed 12, then tagged IEs
        }
        return Frame(label, ssid, src, bssid)
    }

    // EAPOL rides on LLC/SNAP with ethertype 0x888E: AA AA 03 00 00 00 88 8E.
    // The exact offset varies (QoS / addr4 / protected), so scan the header region for it.
    private val EAPOL = byteArrayOf(0xAA.toByte(), 0xAA.toByte(), 0x03, 0, 0, 0, 0x88.toByte(), 0x8E.toByte())
    private fun indexOfEapol(rec: ByteArray, from: Int): Int {
        val end = minOf(rec.size - EAPOL.size, from + 40)   // SNAP is within ~40 bytes after radiotap
        var i = from
        while (i <= end) {
            var ok = true
            for (j in EAPOL.indices) if (rec[i + j] != EAPOL[j]) { ok = false; break }
            if (ok) return i
            i++
        }
        return -1
    }

    /** null if not EAPOL. Otherwise "eapol" or, for a 4-way handshake key frame, the
     *  message: "eapol M1".."eapol M4", derived from the Key Information bits. */
    private fun eapolLabel(rec: ByteArray, from: Int): String? {
        val p = indexOfEapol(rec, from)
        if (p < 0) return null
        val eap = p + 8                                   // EAPOL header: version, type, length(2)
        if (eap + 7 > rec.size) return "eapol"
        if ((rec[eap + 1].toInt() and 0xff) != 3) return "eapol"   // 3 = EAPOL-Key
        val ki = ((rec[eap + 5].toInt() and 0xff) shl 8) or (rec[eap + 6].toInt() and 0xff)
        val mic = ki and 0x0100 != 0
        val ack = ki and 0x0080 != 0
        val install = ki and 0x0040 != 0
        val secure = ki and 0x0200 != 0
        val kdlOff = eap + 4 + 93                          // key data length, 2 bytes big-endian
        val kdl = if (kdlOff + 1 < rec.size)
            ((rec[kdlOff].toInt() and 0xff) shl 8) or (rec[kdlOff + 1].toInt() and 0xff) else -1
        return when {
            !mic && ack -> "eapol M1"
            mic && ack && install -> "eapol M3"
            mic && !ack && secure && kdl == 0 -> "eapol M4"
            mic && !ack -> "eapol M2"
            else -> "eapol"
        }
    }

    private fun mac(rec: ByteArray, off: Int): String? {
        if (off + 6 > rec.size) return null
        val sb = StringBuilder(17)
        for (i in 0 until 6) {
            if (i > 0) sb.append(':')
            sb.append("%02x".format(rec[off + i].toInt() and 0xff))
        }
        return sb.toString()
    }

    private fun parseSsid(rec: ByteArray, start: Int): String? {
        var i = start
        while (i + 2 <= rec.size) {
            val tag = rec[i].toInt() and 0xff
            val len = rec[i + 1].toInt() and 0xff
            if (i + 2 + len > rec.size) break
            if (tag == 0) {
                if (len == 0) return "<hidden>"
                return try { String(rec, i + 2, len, Charsets.UTF_8) } catch (e: Exception) { null }
            }
            i += 2 + len
        }
        return null
    }
}
