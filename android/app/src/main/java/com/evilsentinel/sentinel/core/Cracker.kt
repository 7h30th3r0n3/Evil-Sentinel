package com.evilsentinel.sentinel.core

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Raw WPA/WPA2 material for one BSSID, enough to verify a passphrase offline. */
class CrackTarget(
    val bssid: String,
    val essid: ByteArray,          // SSID bytes, used as the PBKDF2 salt
    val apMac: ByteArray,
    val staMac: ByteArray,
    val pmkid: ByteArray?,         // 16 bytes (WPA*01*) if captured
    val anonce: ByteArray?,        // 32 bytes from M1
    val snonce: ByteArray?,        // 32 bytes from the M2 frame
    val micVersion: Int,           // EAPOL key-descriptor version (1 MD5, 2 SHA1, 3 AES-CMAC)
    val eapolFrame: ByteArray?,    // M2 802.1X frame with the MIC zeroed
    val mic: ByteArray?,           // 16 bytes captured MIC (WPA*02*)
) {
    val canPmkid get() = pmkid != null && essid.isNotEmpty()
    // version 3 is AES-CMAC (802.11w / SHA256), not supported by this CPU verifier
    val canEapol get() = anonce != null && snonce != null && eapolFrame != null &&
        mic != null && micVersion in 1..2 && essid.isNotEmpty()
}

/**
 * Offline dictionary cracker for WPA/WPA2 PSK, PMKID and 4-way handshake.
 * The per-candidate cost is one PBKDF2-HMAC-SHA1 (4096 iterations). We roll PBKDF2 by hand
 * around a single HmacSHA1 Mac keyed once per candidate: the platform SecretKeyFactory PBKDF2
 * is an order of magnitude slower on Android (per-call object churn, no hardware path), whereas
 * Conscrypt's HmacSHA1 uses the ARMv8 SHA1 instructions. Run across all CPU cores. Passive:
 * it only tests passphrases against material already captured, it transmits nothing.
 */
object Cracker {

    private const val BATCH = 256          // wordlist lines pulled per lock acquisition
    private const val REPORT_EVERY = 50L   // candidates between UI progress updates

    /** Returns the recovered passphrase, or null if exhausted / stopped / nothing crackable. */
    fun crack(
        target: CrackTarget,
        nextLine: () -> String?,          // pulls the next wordlist candidate (null at end)
        threads: Int,
        onProgress: (tried: Long) -> Unit,
        stop: AtomicBoolean,
    ): String? {
        if (!target.canPmkid && !target.canEapol) return null
        val found = AtomicReference<String?>(null)
        val tried = AtomicLong(0)
        val lineLock = Any()

        val workers = (0 until threads.coerceAtLeast(1)).map {
            Thread {
                val mac = Mac.getInstance("HmacSHA1")
                val batch = ArrayList<String>(BATCH)
                while (found.get() == null && !stop.get()) {
                    batch.clear()
                    synchronized(lineLock) {
                        var k = 0
                        while (k < BATCH) { val l = nextLine() ?: break; batch.add(l); k++ }
                    }
                    if (batch.isEmpty()) break
                    for (pw in batch) {
                        if (found.get() != null || stop.get()) break
                        val t = tried.incrementAndGet()
                        if (t % REPORT_EVERY == 0L) onProgress(t)   // keep the UI counter live
                        if (pw.length !in 8..63) continue           // WPA PSK length bounds
                        // WPA passphrase is printable ASCII; its UTF-8 bytes equal the JCA char->byte PMK input
                        val pmk = try {
                            pbkdf2Sha1(mac, pw.toByteArray(Charsets.UTF_8), target.essid, 4096, 32)
                        } catch (e: Exception) { null } ?: continue
                        val hit = (target.canPmkid && pmkidMatches(pmk, target)) ||
                            (target.canEapol && micMatches(pmk, target))
                        if (hit) { found.compareAndSet(null, pw); break }
                    }
                    onProgress(tried.get())
                }
            }
        }
        workers.forEach { it.start() }
        workers.forEach { it.join() }
        onProgress(tried.get())
        return found.get()
    }

    private fun pmkidMatches(pmk: ByteArray, t: CrackTarget): Boolean {
        val data = PMK_NAME + t.apMac + t.staMac
        return hmacSha1(pmk, data).copyOfRange(0, 16).contentEquals(t.pmkid)
    }

    private fun micMatches(pmk: ByteArray, t: CrackTarget): Boolean {
        val kck = kck(pmk, t.apMac, t.staMac, t.anonce!!, t.snonce!!)
        val alg = if (t.micVersion == 1) "HmacMD5" else "HmacSHA1"
        val mac = Mac.getInstance(alg)
        mac.init(SecretKeySpec(kck, alg))
        return mac.doFinal(t.eapolFrame).copyOfRange(0, 16).contentEquals(t.mic)
    }

    /** KCK = first 16 bytes of PTK, derived with PRF-512. */
    private fun kck(pmk: ByteArray, ap: ByteArray, sta: ByteArray, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val macLo: ByteArray; val macHi: ByteArray
        if (cmp(ap, sta) < 0) { macLo = ap; macHi = sta } else { macLo = sta; macHi = ap }
        val nLo: ByteArray; val nHi: ByteArray
        if (cmp(anonce, snonce) < 0) { nLo = anonce; nHi = snonce } else { nLo = snonce; nHi = anonce }
        val b = macLo + macHi + nLo + nHi
        val out = ByteArray(64)
        var pos = 0; var i = 0
        while (pos < out.size) {
            val data = PRF_LABEL + byteArrayOf(0) + b + byteArrayOf(i.toByte())
            val d = hmacSha1(pmk, data)
            val n = minOf(d.size, out.size - pos)
            System.arraycopy(d, 0, out, pos, n)
            pos += n; i++
        }
        return out.copyOfRange(0, 16)
    }

    private fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        return mac.doFinal(data)
    }

    /**
     * PBKDF2-HMAC-SHA1 (RFC 2898) with the given Mac reused across candidates. The HMAC key is
     * the passphrase, set once per candidate; every doFinal keeps that key, so each of the 4096
     * iterations costs just two SHA1 compressions on the hardware path. dkLen is in bytes.
     */
    private fun pbkdf2Sha1(mac: Mac, password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        mac.init(SecretKeySpec(password, "HmacSHA1"))
        val hLen = mac.macLength                       // 20
        val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(blocks * hLen)
        val intBlock = ByteArray(4)
        for (i in 1..blocks) {
            intBlock[0] = (i ushr 24).toByte(); intBlock[1] = (i ushr 16).toByte()
            intBlock[2] = (i ushr 8).toByte();  intBlock[3] = i.toByte()
            mac.update(salt)
            var u = mac.doFinal(intBlock)              // U1 = PRF(pw, salt || INT(i))
            val tBlock = u.copyOf()
            for (j in 2..iterations) {
                u = mac.doFinal(u)                     // Uj = PRF(pw, Uj-1), key retained
                for (k in tBlock.indices) tBlock[k] = (tBlock[k].toInt() xor u[k].toInt()).toByte()
            }
            System.arraycopy(tBlock, 0, out, (i - 1) * hLen, hLen)
        }
        return out.copyOf(dkLen)
    }

    private fun cmp(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private val PMK_NAME = "PMK Name".toByteArray(Charsets.US_ASCII)
    private val PRF_LABEL = "Pairwise key expansion".toByteArray(Charsets.US_ASCII)
}
