package com.evilsentinel.sentinel

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.evilsentinel.sentinel.ui.AppRoot
import com.evilsentinel.sentinel.ui.EvilSentinelTheme
import java.io.File

class MainActivity : ComponentActivity() {

    private val vm: CaptureViewModel by viewModels()
    private val usb by lazy { getSystemService(Context.USB_SERVICE) as UsbManager }
    private val ACTION_PERM get() = "$packageName.USB_PERMISSION"

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                ACTION_PERM -> {
                    val device: UsbDevice? = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                    device?.let { vm.deliverPermission(it.deviceId, granted) }
                }
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> vm.autoStart()
                UsbManager.ACTION_USB_DEVICE_DETACHED -> vm.onDeviceDetached()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        vm.requestPermission = { device ->
            Toast.makeText(this, "Tap Always allow so it starts by itself next time",
                Toast.LENGTH_LONG).show()
            val pi = PendingIntent.getBroadcast(
                this, device.deviceId,
                Intent(ACTION_PERM).setPackage(packageName),
                if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0,
            )
            usb.requestPermission(device, pi)
        }

        val filter = IntentFilter(ACTION_PERM).apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        setContent {
            EvilSentinelTheme {
                val state by vm.state.collectAsStateWithLifecycle()
                val packets by vm.packets.collectAsStateWithLifecycle()
                val handshakes by vm.handshakes.collectAsStateWithLifecycle()
                val crack by vm.crack.collectAsStateWithLifecycle()
                AppRoot(
                    state = state,
                    packets = packets,
                    ringCount = vm.ringCount,
                    matchCount = vm.matchCount,
                    handshakes = handshakes,
                    crack = crack,
                    onStart = { vm.start() },
                    onStop = { vm.stopCapture() },
                    onShare = { shareFile(vm.currentCaptureFile(), "No capture yet") },
                    onSetChannel = { key, ch -> vm.setChannel(key, ch) },
                    onFilter = { text, type -> vm.setFilter(text, type) },
                    onFreeze = { f -> vm.setFrozen(f) },
                    onClear = { vm.clearPackets() },
                    onExportAllHandshakes = { shareFile(vm.exportHandshakes(null), "No usable handshake yet") },
                    onExportHandshake = { bssid -> shareFile(vm.exportHandshakes(bssid), "Nothing to export for that BSSID") },
                    onCrackStart = { bssid, uri -> vm.startCrack(bssid, uri) },
                    onStopCrack = { vm.stopCrack() },
                    onDismissCrack = { vm.dismissCrack() },
                )
            }
        }

        // auto-start the moment the app opens with the rig already plugged in
        vm.autoStart()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) vm.autoStart()
    }

    private fun shareFile(f: File?, emptyMsg: String) {
        if (f == null || !f.exists()) {
            Toast.makeText(this, emptyMsg, Toast.LENGTH_SHORT).show(); return
        }
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", f)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(send, "Share ${f.name}"))
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { unregisterReceiver(receiver) }
    }
}
