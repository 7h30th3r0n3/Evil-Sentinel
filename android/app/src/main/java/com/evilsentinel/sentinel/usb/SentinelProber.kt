package com.evilsentinel.sentinel.usb

import android.hardware.usb.UsbManager
import com.hoho.android.usbserial.driver.CdcAcmSerialDriver
import com.hoho.android.usbserial.driver.ProbeTable
import com.hoho.android.usbserial.driver.UsbSerialDriver
import com.hoho.android.usbserial.driver.UsbSerialProber

/**
 * Finds every candidate serial device: Espressif native USB Serial/JTAG (VID 0x303a,
 * handled as CDC-ACM) plus whatever the default prober recognises (CP210x, CH340, FTDI...).
 */
object SentinelProber {

    private val espressif: UsbSerialProber by lazy {
        val t = ProbeTable()
        t.addProduct(0x303a, 0x1001, CdcAcmSerialDriver::class.java)  // C3 / C5 / C6 USB-Serial/JTAG
        t.addProduct(0x303a, 0x0002, CdcAcmSerialDriver::class.java)  // some Espressif CDC variants
        UsbSerialProber(t)
    }

    fun findDrivers(usb: UsbManager): List<UsbSerialDriver> {
        val seen = HashSet<Int>()
        val out = ArrayList<UsbSerialDriver>()
        for (d in espressif.findAllDrivers(usb) + UsbSerialProber.getDefaultProber().findAllDrivers(usb)) {
            if (seen.add(d.device.deviceId)) out.add(d)
        }
        return out
    }
}
