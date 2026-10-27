package com.evilsentinel.sentinel.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.PlatformTextStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import kotlinx.coroutines.launch
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.evilsentinel.sentinel.core.CrackUi
import com.evilsentinel.sentinel.core.HandshakeUi
import com.evilsentinel.sentinel.core.PacketRow
import com.evilsentinel.sentinel.core.UiState

/** Top-level screen: full-bleed dark background behind the system bars, content inside the
 *  safe area, three tabs (Dashboard / Packets / Handshakes). */
@Composable
fun AppRoot(
    state: UiState,
    packets: List<PacketRow>,
    ringCount: Int,
    matchCount: Int,
    handshakes: List<HandshakeUi>,
    crack: CrackUi?,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onShare: () -> Unit,
    onSetChannel: (String, Int) -> Unit,
    onFilter: (String, String) -> Unit,
    onFreeze: (Boolean) -> Unit,
    onClear: () -> Unit,
    onExportAllHandshakes: () -> Unit,
    onExportHandshake: (String) -> Unit,
    onCrackStart: (String, Uri?) -> Unit,
    onStopCrack: () -> Unit,
    onDismissCrack: () -> Unit,
) {
    var tab by remember { mutableStateOf(0) }
    Box(Modifier.fillMaxSize().background(Palette.Bg)) {
        Column(Modifier.fillMaxSize().safeDrawingPadding()) {
            TabBar(tab, state, handshakes.size) { tab = it }
            Box(Modifier.fillMaxSize()) {
                when (tab) {
                    0 -> SentinelDashboard(state, onStart, onStop, onShare, onSetChannel)
                    1 -> PacketScreen(packets, ringCount, matchCount, onFilter, onFreeze, onClear)
                    else -> HandshakeScreen(handshakes, crack, onExportAllHandshakes,
                        onExportHandshake, onCrackStart, onStopCrack, onDismissCrack)
                }
            }
        }
    }
}

@Composable
private fun TabBar(tab: Int, state: UiState, hsCount: Int, onTab: (Int) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TabChip("DASHBOARD", tab == 0) { onTab(0) }
        TabChip("PACKETS", tab == 1) { onTab(1) }
        TabChip(if (hsCount > 0) "HANDSHAKES $hsCount" else "HANDSHAKES", tab == 2) { onTab(2) }
        Spacer(Modifier.weight(1f))
        if (state.running) RecChip()
    }
}

@Composable
private fun RecChip() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(Palette.Red))
        Spacer(Modifier.width(5.dp))
        Text("REC", color = Palette.Red, fontSize = 11.sp, fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace, letterSpacing = 1.sp)
    }
}

@Composable
private fun TabChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Box(
        Modifier.clip(RoundedCornerShape(8.dp))
            .background(if (selected) Palette.Panel else Palette.Bg)
            .border(1.dp, if (selected) Palette.Accent else Palette.Line, RoundedCornerShape(8.dp))
            .clickable { onClick() }
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(label, color = if (selected) Palette.Accent else Palette.Dim,
            fontSize = 11.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, letterSpacing = 1.sp)
    }
}

private val TYPES = listOf("" to "ALL", "eapol" to "EAPOL", "beacon" to "beacon", "data" to "data",
    "qos-data" to "qos", "probe-req" to "probe-req", "probe-resp" to "probe-resp",
    "deauth" to "deauth", "mgmt" to "mgmt")

@Composable
private fun PacketScreen(
    packets: List<PacketRow>, ringCount: Int, matchCount: Int,
    onFilter: (String, String) -> Unit, onFreeze: (Boolean) -> Unit, onClear: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var type by remember { mutableStateOf("") }
    var frozen by remember { mutableStateOf(false) }
    LaunchedEffect(query, type) { onFilter(query, type) }
    LaunchedEffect(frozen) { onFreeze(frozen) }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(Palette.Panel)
                .border(1.dp, Palette.Line, RoundedCornerShape(10.dp)).padding(12.dp),
        ) {
            BasicTextField(
                value = query, onValueChange = { query = it },
                singleLine = true,
                textStyle = TextStyle(color = Palette.Txt, fontFamily = FontFamily.Monospace, fontSize = 14.sp),
                cursorBrush = androidx.compose.ui.graphics.SolidColor(Palette.Accent),
                modifier = Modifier.fillMaxWidth(),
                decorationBox = { inner ->
                    if (query.isEmpty()) Text("filter: SSID / MAC / type / channel",
                        color = Palette.Dim, fontFamily = FontFamily.Monospace, fontSize = 14.sp)
                    inner()
                },
            )
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            for ((value, label) in TYPES) TabChipSmall(label, type == value) { type = value }
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("${packets.size} shown · $matchCount match · buf $ringCount",
                color = Palette.Dim, fontSize = 10.sp, fontFamily = FontFamily.Monospace,
                modifier = Modifier.weight(1f))
            TabChipSmall(if (frozen) "FROZEN" else "LIVE", frozen) { frozen = !frozen }
            Spacer(Modifier.width(6.dp))
            TabChipSmall("CLEAR", false) { onClear() }
        }
        Spacer(Modifier.height(6.dp))
        if (packets.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("no packets (start a capture)", color = Palette.Dim,
                    fontSize = 13.sp, fontFamily = FontFamily.Monospace)
            }
        } else {
            // Wireshark-style live tail: oldest at top, newest at the bottom. The view sticks to
            // the bottom edge while following; scrolling up pauses it and a chip offers to jump back.
            val listState = rememberLazyListState()
            val scope = rememberCoroutineScope()
            var follow by remember { mutableStateOf(true) }
            val atBottom by remember {
                derivedStateOf {
                    val info = listState.layoutInfo
                    val last = info.visibleItemsInfo.lastOrNull()
                    last == null || last.index >= info.totalItemsCount - 1
                }
            }
            // resume following once the user is back at the live edge
            LaunchedEffect(atBottom) { if (atBottom) follow = true }
            // a user-driven scroll away from the bottom pauses following
            LaunchedEffect(listState.isScrollInProgress) {
                if (listState.isScrollInProgress && !atBottom) follow = false
            }
            // new frames arrive -> stay pinned to the live edge while following
            LaunchedEffect(packets.size) {
                if (follow && packets.isNotEmpty()) listState.scrollToItem(packets.size - 1)
            }
            Box(Modifier.fillMaxSize()) {
                LazyColumn(state = listState, modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    items(packets, key = { it.seq }) { PacketRowView(it) }
                }
                if (!follow) {
                    Box(
                        Modifier.align(Alignment.BottomCenter).padding(bottom = 12.dp)
                            .clip(RoundedCornerShape(16.dp)).background(Palette.Accent)
                            .clickable {
                                follow = true
                                scope.launch { listState.scrollToItem(packets.size - 1) }
                            }
                            .padding(horizontal = 16.dp, vertical = 9.dp),
                    ) {
                        Text("JUMP TO LIVE ▾", color = Palette.Bg, fontSize = 11.sp,
                            fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, letterSpacing = 1.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun TabChipSmall(label: String, selected: Boolean, onClick: () -> Unit) {
    Box(
        Modifier.clip(RoundedCornerShape(7.dp))
            .background(if (selected) Palette.Panel else Palette.Bg)
            .border(1.dp, if (selected) Palette.Accent else Palette.Line, RoundedCornerShape(7.dp))
            .clickable { onClick() }.padding(horizontal = 10.dp, vertical = 6.dp),
    ) {
        Text(label, color = if (selected) Palette.Accent else Palette.Dim,
            fontSize = 11.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun PacketRowView(p: PacketRow) {
    val typeColor = when {
        p.type.startsWith("eapol") -> Palette.Amber
        p.type == "deauth" || p.type == "disassoc" -> Palette.Red
        p.type == "beacon" || p.type == "probe-resp" -> Palette.Accent
        p.type == "data" || p.type == "qos-data" -> Palette.Green
        else -> Palette.Txt
    }
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Palette.PanelHi)
            .border(1.dp, Palette.Line, RoundedCornerShape(8.dp)),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // left color rail by frame type: scan the list for attacks/handshakes at a glance
        Box(Modifier.width(3.dp).height(34.dp).background(typeColor))
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 7.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.width(54.dp)) {
                Text(fmtTime(p.tMs), color = Palette.Dim, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                Text(if (p.ch > 0) "ch${p.ch}" else "-", color = Palette.Dim, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
            }
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(p.type, color = typeColor, fontSize = 12.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                val line2 = p.ssid?.let { "\"$it\"" } ?: (p.src ?: p.bssid ?: "")
                if (line2.isNotEmpty())
                    Text(line2, color = Palette.Txt, fontSize = 10.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text("${p.rssi} dBm", color = rssiColor(p.rssi), fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                Text("${p.len} B", color = Palette.Dim, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
            }
        }
    }
}

// ---- Handshakes tab ----
@Composable
private fun HandshakeScreen(
    handshakes: List<HandshakeUi>, crack: CrackUi?,
    onExportAll: () -> Unit, onExportOne: (String) -> Unit,
    onCrackStart: (String, Uri?) -> Unit, onStopCrack: () -> Unit, onDismissCrack: () -> Unit,
) {
    // Networks with a crackable (exportable) handshake first, then by how much was captured,
    // so the most complete captures bubble to the top of the list.
    val sorted = handshakes.sortedWith(
        compareByDescending<HandshakeUi> { it.exportable }
            .thenByDescending { listOf(it.m1, it.m2, it.m3, it.m4, it.pmkid).count { b -> b } }
    )
    val valid = handshakes.count { it.exportable }

    // wordlist source chooser + SAF file picker for the dictionary attack
    var chooseFor by remember { mutableStateOf<String?>(null) }
    var pickFor by remember { mutableStateOf<String?>(null) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val b = pickFor; pickFor = null
        if (uri != null && b != null) onCrackStart(b, uri)
    }
    chooseFor?.let { b ->
        AlertDialog(
            onDismissRequest = { chooseFor = null },
            containerColor = Palette.Panel,
            title = { Text("DICTIONARY ATTACK", color = Palette.Accent, fontSize = 14.sp,
                fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, letterSpacing = 1.sp) },
            text = { Text("Pick the wordlist to run against this network.", color = Palette.Dim,
                fontSize = 13.sp, fontFamily = FontFamily.Monospace) },
            confirmButton = {
                TextButton(onClick = { chooseFor = null; onCrackStart(b, null) }) {
                    Text("BUILT-IN LIST", color = Palette.Accent, fontFamily = FontFamily.Monospace)
                }
            },
            dismissButton = {
                TextButton(onClick = { chooseFor = null; pickFor = b; picker.launch(arrayOf("text/plain", "*/*")) }) {
                    Text("PICK FILE", color = Palette.Accent, fontFamily = FontFamily.Monospace)
                }
            },
        )
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(Modifier.fillMaxWidth().padding(bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Row(Modifier.weight(1f), verticalAlignment = Alignment.Bottom) {
                Text("$valid/${handshakes.size}", color = if (valid > 0) Palette.Amber else Palette.Txt,
                    fontSize = 18.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(8.dp))
                Text("valid / seen networks", color = Palette.Dim, fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace, modifier = Modifier.padding(bottom = 2.dp))
            }
            TabChipSmall("EXPORT ALL (hc22000)", false) { onExportAll() }
        }
        if (sorted.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("no handshakes yet", color = Palette.Dim, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
            }
        } else {
            LazyColumn(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(sorted, key = { it.bssid }) { h ->
                    HandshakeRow(h, crack?.takeIf { c -> c.bssid == h.bssid },
                        onExportOne, onCrack = { chooseFor = h.bssid }, onStopCrack, onDismissCrack)
                }
            }
        }
    }
}

@Composable
private fun HandshakeRow(
    h: HandshakeUi, crack: CrackUi?,
    onExportOne: (String) -> Unit, onCrack: () -> Unit, onStopCrack: () -> Unit, onDismissCrack: () -> Unit,
) {
    val running = crack?.running == true
    val rail = when { h.password != null -> Palette.Green; h.exportable -> Palette.Amber; else -> Palette.Line }
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(Palette.PanelHi)
            .border(1.dp, rail, RoundedCornerShape(10.dp)).padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(h.essid ?: "<hidden>", color = Palette.Txt, fontSize = 13.sp,
                fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, maxLines = 1)
            Text(h.bssid, color = Palette.Dim, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                MsgBox("M1", h.m1); MsgBox("M2", h.m2); MsgBox("M3", h.m3); MsgBox("M4", h.m4)
                if (h.pmkid) {
                    Spacer(Modifier.width(4.dp))
                    Box(Modifier.clip(RoundedCornerShape(4.dp)).background(Palette.Amber)
                        .padding(horizontal = 6.dp, vertical = 2.dp)) {
                        Text("PMKID", color = Palette.Bg, fontSize = 9.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                    }
                }
            }
            // crack status: recovered key, live progress, or the finished message
            when {
                h.password != null -> {
                    Spacer(Modifier.height(8.dp))
                    Text("KEY  ${h.password}", color = Palette.Green, fontSize = 14.sp,
                        fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                }
                running -> {
                    Spacer(Modifier.height(8.dp))
                    Text("cracking  ${fmtN(crack!!.tried)} tried · ${fmtN(crack.rate.toLong())}/s",
                        color = Palette.Accent, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                }
                crack != null && crack.done -> {
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(crack.message ?: "done", color = Palette.Dim, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        Spacer(Modifier.width(8.dp))
                        Text("✕", color = Palette.Dim, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                            modifier = Modifier.clickable { onDismissCrack() })
                    }
                }
            }
        }
        Spacer(Modifier.width(10.dp))
        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(6.dp)) {
            ActionChip("EXPORT", filled = h.exportable, enabled = h.exportable,
                color = Palette.Accent) { onExportOne(h.bssid) }
            when {
                running -> ActionChip("STOP", filled = true, color = Palette.Red) { onStopCrack() }
                h.exportable && h.password == null -> ActionChip("CRACK", filled = true, color = Palette.Amber) { onCrack() }
            }
        }
    }
}

@Composable
private fun ActionChip(label: String, filled: Boolean, enabled: Boolean = true, color: androidx.compose.ui.graphics.Color, onClick: () -> Unit) {
    Box(
        Modifier.clip(RoundedCornerShape(7.dp))
            .background(if (filled && enabled) color else Palette.Panel)
            .border(1.dp, if (enabled) color else Palette.Line, RoundedCornerShape(7.dp))
            .clickable(enabled = enabled) { onClick() }
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(label, color = if (filled && enabled) Palette.Bg else if (enabled) color else Palette.Dim,
            fontSize = 10.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
    }
}

/** Compact integer: 1234 -> "1.2k", 2_300_000 -> "2.3M". */
private fun fmtN(v: Long): String = when {
    v >= 1_000_000 -> "%.1fM".format(v / 1_000_000.0)
    v >= 1_000 -> "%.1fk".format(v / 1_000.0)
    else -> v.toString()
}

@Composable
private fun MsgBox(label: String, on: Boolean) {
    Box(
        Modifier.size(width = 26.dp, height = 18.dp).clip(RoundedCornerShape(4.dp))
            .background(if (on) Palette.Green else Palette.Panel)
            .border(1.dp, if (on) Palette.Green else Palette.Line, RoundedCornerShape(4.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Text(label, color = if (on) Palette.Bg else Palette.Dim,
            fontSize = 9.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace,
            textAlign = TextAlign.Center,
            // drop the default font padding so the glyphs sit truly centered in the small cell
            style = TextStyle(platformStyle = PlatformTextStyle(includeFontPadding = false)))
    }
}

private fun rssiColor(rssi: Int) = when {
    rssi >= -60 -> Palette.Green
    rssi >= -75 -> Palette.Amber
    else -> Palette.Red
}

private fun fmtTime(ms: Long): String {
    val s = ms / 1000
    val h = (s / 3600) % 24; val m = (s / 60) % 60; val sec = s % 60
    return "%02d:%02d:%02d".format(h, m, sec)
}
