package com.evilsentinel.sentinel.core

/** Channel / hop encoding shared by the node, the controller and the UI.
 *  >= 1 : locked channel (2.4 GHz 1..14, or 5 GHz 36..165 on a dual-band node)
 *    0  : hop 2.4 GHz      -1 : hop 5 GHz      -2 : hop dual-band */
object Chan {
    const val HOP24 = 0
    const val HOP5 = -1
    const val HOPDUAL = -2

    fun cmd(ch: Int): ByteArray = when (ch) {
        HOP24 -> "hop\n"
        HOP5 -> "hop5\n"
        HOPDUAL -> "hopdual\n"
        else -> "ch $ch\n"
    }.toByteArray()

    fun label(ch: Int): String = when (ch) {
        HOP24 -> "HOP"
        HOP5 -> "H5"
        HOPDUAL -> "HD"
        else -> ch.toString()
    }

    fun isHop(ch: Int): Boolean = ch <= 0
    fun is5GHz(ch: Int): Boolean = ch >= 36

    /** 5 GHz 20 MHz channels the ESP32-C5 can actually receive (36..112). Channel 116 and up
     *  (>~5.56 GHz) are not demodulated by the C5 RX, so they are left out everywhere. */
    val CH5 = listOf(36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112)
    val CH24 = (1..13).toList()
}

/** Immutable snapshot of one node for the UI. */
data class NodeUi(
    val key: String,
    val name: String,
    val chip: String,
    val channel: Int,
    val label: String,
    val fps: Int,
    val total: Long,
    val seenCh: Int,
    val connected: Boolean,
    val dualband: Boolean,
    val dropped: Long,
    val hist: List<Int>,
)

/** Per-BSSID handshake progress for the Handshakes view. */
data class HandshakeUi(
    val bssid: String,
    val essid: String?,
    val m1: Boolean,
    val m2: Boolean,
    val m3: Boolean,
    val m4: Boolean,
    val pmkid: Boolean,
    val exportable: Boolean,
    val password: String? = null,   // recovered by the in-app dictionary cracker, if any
)

/** Live state of the in-app dictionary cracker for one target BSSID. */
data class CrackUi(
    val bssid: String,
    val essid: String?,
    val running: Boolean,
    val tried: Long,
    val rate: Int,            // candidates per second
    val found: String?,       // recovered passphrase
    val done: Boolean,
    val message: String? = null,
)

/** One captured frame, for the live packet list. */
data class PacketRow(
    val seq: Long,
    val tMs: Long,
    val ch: Int,
    val type: String,
    val ssid: String?,
    val src: String?,
    val bssid: String?,
    val len: Int,
    val rssi: Int,
)

/** Immutable snapshot of the whole capture for the UI. */
data class UiState(
    val running: Boolean = false,
    val scanning: Boolean = false,
    val nodes: List<NodeUi> = emptyList(),
    val band: List<Long> = List(15) { 0L },   // index = 2.4 GHz channel (1..14) -> total packets
    val band5: List<Long> = List(Chan.CH5.size) { 0L },   // 5 GHz totals, indexed like Chan.CH5
    val has5GHz: Boolean = false,              // any dual-band or 5 GHz-locked node present
    val totalFrames: Long = 0,
    val fpsTotal: Int = 0,
    val dropped: Long = 0,                     // frames the host could not keep up with
    val uptimeSec: Long = 0,
    val handshakes: Int = 0,                   // BSSIDs with a usable handshake or PMKID
    val captureFile: String? = null,
    val message: String? = null,
)
