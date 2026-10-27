package com.evilsentinel.sentinel.core

/** pcap (classic) framing helpers, matching the desktop sentinel tools. */
object Pcap {
    const val LINKTYPE_IEEE802_11_RADIOTAP = 127
    const val GLOBAL_HEADER_LEN = 24
    const val RECORD_HEADER_LEN = 16

    /** pcap magic as it appears on the wire for little-endian files: d4 c3 b2 a1. */
    val MAGIC_LE = byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte())

    private fun le16(v: Int) = byteArrayOf((v and 0xff).toByte(), ((v ushr 8) and 0xff).toByte())
    private fun le32(v: Long) = byteArrayOf(
        (v and 0xff).toByte(), ((v ushr 8) and 0xff).toByte(),
        ((v ushr 16) and 0xff).toByte(), ((v ushr 24) and 0xff).toByte(),
    )

    fun globalHeader(snaplen: Int = 65535): ByteArray {
        val b = ByteArray(GLOBAL_HEADER_LEN)
        le32(0xa1b2c3d4L).copyInto(b, 0)
        le16(2).copyInto(b, 4)    // version major
        le16(4).copyInto(b, 6)    // version minor
        // thiszone (8) + sigfigs (12) stay zero
        le32(snaplen.toLong()).copyInto(b, 16)
        le32(LINKTYPE_IEEE802_11_RADIOTAP.toLong()).copyInto(b, 20)
        return b
    }

    fun recordHeader(tsSec: Long, tsUsec: Long, caplen: Int, origlen: Int): ByteArray {
        val b = ByteArray(RECORD_HEADER_LEN)
        le32(tsSec).copyInto(b, 0)
        le32(tsUsec).copyInto(b, 4)
        le32(caplen.toLong()).copyInto(b, 8)
        le32(origlen.toLong()).copyInto(b, 12)
        return b
    }

    fun readLe32(b: ByteArray, off: Int): Long =
        (b[off].toLong() and 0xff) or
        ((b[off + 1].toLong() and 0xff) shl 8) or
        ((b[off + 2].toLong() and 0xff) shl 16) or
        ((b[off + 3].toLong() and 0xff) shl 24)
}
