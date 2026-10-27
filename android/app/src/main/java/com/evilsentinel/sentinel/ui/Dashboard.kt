package com.evilsentinel.sentinel.ui

import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.evilsentinel.sentinel.core.Chan
import com.evilsentinel.sentinel.core.NodeUi
import com.evilsentinel.sentinel.core.UiState

@Composable
fun SentinelDashboard(
    state: UiState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onShare: () -> Unit,
    onSetChannel: (String, Int) -> Unit,
) {
    // The header, band strips and node list all live in one scrolling LazyColumn so a tall
    // layout (e.g. the extra 5 GHz strip on a small screen) never pushes content off-screen.
    // The BottomBar is pinned below it, so START/STOP is always reachable without scrolling.
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        LazyColumn(Modifier.weight(1f)) {
            item {
                Header(state)
                Spacer(Modifier.height(14.dp))
                BandStrip("2.4 GHz · PACKETS / CHANNEL", state.band.drop(1).take(13),
                    (1..13).map { it.toString() }, Palette.Accent)
                if (state.has5GHz) {
                    Spacer(Modifier.height(10.dp))
                    BandStrip("5 GHz · PACKETS / CHANNEL", state.band5, Chan.CH5.map { it.toString() }, Palette.Accent5)
                }
                Spacer(Modifier.height(16.dp))
                Text("NODES", color = Palette.Dim, fontSize = 11.sp, fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace, letterSpacing = 3.sp)
                Spacer(Modifier.height(8.dp))
            }
            if (state.nodes.isEmpty()) {
                item { EmptyHint(state, Modifier.fillParentMaxHeight(0.4f)) }
            } else {
                items(state.nodes, key = { it.key }) { n ->
                    NodeCard(n) { ch -> onSetChannel(n.key, ch) }
                    Spacer(Modifier.height(10.dp))
                }
            }
        }
        BottomBar(state, onStart, onStop, onShare)
    }
}

@Composable
private fun Header(state: UiState) {
    // Title row: identity on the left, uptime on the right (REC lives in the tab bar).
    Row(Modifier.fillMaxWidth().padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("⬢", color = Palette.Accent, fontSize = 20.sp)   // hexagon
        Spacer(Modifier.width(8.dp))
        Text("EVIL-SENTINEL", color = Palette.Accent, fontSize = 18.sp, fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace, letterSpacing = 2.sp)
        Spacer(Modifier.weight(1f))
        Text(fmtUp(state.uptimeSec), color = Palette.Dim, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
    }
    Spacer(Modifier.height(10.dp))
    // One tidy row of equal-width stat tiles, no numbers repeated elsewhere.
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        KpiTile("NODES", "${state.nodes.size}", Palette.Txt, Modifier.weight(1f))
        KpiTile("F/S", "${state.fpsTotal}", Palette.Accent, Modifier.weight(1f))
        KpiTile("FRAMES", fmtCount(state.totalFrames), Palette.Txt, Modifier.weight(1f))
        KpiTile("DROP", fmtCount(state.dropped),
            if (state.dropped > 0) Palette.Red else Palette.Dim, Modifier.weight(1f))
    }
}

@Composable
private fun KpiTile(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Column(
        modifier.clip(RoundedCornerShape(8.dp)).background(Palette.Panel)
            .border(1.dp, Palette.Line, RoundedCornerShape(8.dp)).padding(horizontal = 10.dp, vertical = 6.dp),
    ) {
        Text(value, color = color, fontSize = 16.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
        Text(label, color = Palette.Dim, fontSize = 8.sp, fontFamily = FontFamily.Monospace, letterSpacing = 1.sp)
    }
}

/** A band strip: rounded, gradient-filled, softly glowing bars, one per channel. */
@Composable
private fun BandStrip(title: String, values: List<Long>, labels: List<String>, accent: Color) {
    val peak = (values.maxOrNull() ?: 1L).coerceAtLeast(1L)
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(Palette.Panel)
            .border(1.dp, Palette.Line, RoundedCornerShape(12.dp)).padding(12.dp)
    ) {
        Text(title, color = Palette.Dim, fontSize = 10.sp,
            fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, letterSpacing = 1.sp)
        Spacer(Modifier.height(8.dp))
        Canvas(Modifier.fillMaxWidth().height(88.dp)) {
            val n = values.size.coerceAtLeast(1)
            val gap = (if (n > 15) 3.dp else 6.dp).toPx()
            val colW = ((size.width - gap * (n - 1)) / n).coerceAtLeast(1f)
            val radius = CornerRadius(3f, 3f)
            for (c in 0 until n) {
                val v = values[c]
                val load = (v.toFloat() / peak).coerceIn(0f, 1f)
                val h = (size.height * load).coerceAtLeast(if (v > 0) 3f else 2f)
                val x = c * (colW + gap)
                val top = size.height - h
                if (v > 0) {
                    val base = Palette.loadColor(load)
                    // soft glow behind
                    drawRoundRect(
                        color = base.copy(alpha = 0.25f),
                        topLeft = Offset(x - 1.5f, top - 1.5f),
                        size = Size(colW + 3f, h + 1.5f), cornerRadius = radius,
                    )
                    // gradient bar
                    drawRoundRect(
                        brush = Brush.verticalGradient(
                            listOf(base, base.copy(alpha = 0.45f)), startY = top, endY = size.height),
                        topLeft = Offset(x, top), size = Size(colW, h), cornerRadius = radius,
                    )
                } else {
                    drawRoundRect(color = Palette.Line, topLeft = Offset(x, top),
                        size = Size(colW, h), cornerRadius = radius)
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        // Mirror the Canvas grid exactly: equal-width columns with the same gap as the bars, so
        // each channel label (and its count) sits centered under its own bar.
        val gapDp = if (labels.size > 15) 3.dp else 6.dp
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(gapDp)) {
            // label every channel for 2.4, every other for the denser 5 GHz lane; show the
            // per-channel packet count under each labelled channel that has traffic
            labels.forEachIndexed { i, s ->
                val show = labels.size <= 14 || i % 2 == 0
                Column(Modifier.weight(1f), horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(if (show) s else " ", color = if (values[i] > 0) accent else Palette.Dim,
                        fontSize = 8.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
                    if (show && values[i] > 0)
                        Text(fmtCount(values[i]), color = Palette.Dim, fontSize = 7.sp,
                            fontFamily = FontFamily.Monospace, maxLines = 1)
                }
            }
        }
    }
}

/** Compact packet count: 1234 -> "1.2k", 2_300_000 -> "2.3M". */
private fun fmtCount(v: Long): String = when {
    v >= 1_000_000 -> "%.1fM".format(v / 1_000_000.0)
    v >= 1_000 -> "%.1fk".format(v / 1_000.0)
    else -> v.toString()
}

@Composable
private fun NodeCard(n: NodeUi, onSetChannel: (Int) -> Unit) {
    val band5 = n.dualband || Chan.is5GHz(n.channel) || n.channel == Chan.HOP5 || n.channel == Chan.HOPDUAL
    val accent = if (band5) Palette.Accent5 else Palette.Accent
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(Palette.PanelHi)
            .border(1.dp, Palette.Line, RoundedCornerShape(12.dp)).padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        var menu by remember { mutableStateOf(false) }
        Box {
            Box(
                Modifier.size(52.dp).clip(RoundedCornerShape(10.dp))
                    .background(Palette.Panel).border(1.dp, accent, RoundedCornerShape(10.dp))
                    .clickable { menu = true },
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(n.label,
                        color = accent, fontSize = if (n.channel in 1..14) 20.sp else 14.sp,
                        fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                    Text(if (n.channel >= 1) (if (Chan.is5GHz(n.channel)) "5G ▾" else "CHAN ▾") else "SWEEP ▾",
                        color = Palette.Dim, fontSize = 7.sp, fontFamily = FontFamily.Monospace, letterSpacing = 1.sp)
                }
            }
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false },
                modifier = Modifier.background(Palette.Panel)) {
                ChannelItem("HOP 2.4 GHz", n.channel == Chan.HOP24) { onSetChannel(Chan.HOP24); menu = false }
                if (n.dualband) {
                    ChannelItem("HOP 5 GHz", n.channel == Chan.HOP5) { onSetChannel(Chan.HOP5); menu = false }
                    ChannelItem("HOP dual-band", n.channel == Chan.HOPDUAL) { onSetChannel(Chan.HOPDUAL); menu = false }
                }
                for (c in Chan.CH24) ChannelItem("2.4 GHz  ch $c", n.channel == c) { onSetChannel(c); menu = false }
                if (n.dualband) for (c in Chan.CH5) ChannelItem("5 GHz  ch $c", n.channel == c) { onSetChannel(c); menu = false }
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(n.name, color = Palette.Txt, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
            val warn = n.seenCh != 0 && n.channel >= 1 && n.seenCh != n.channel
            Text(
                buildString {
                    append(n.chip).append(" · ").append(fmtCount(n.total)).append(" fr")
                    if (!n.connected) append("  ⚠ lost")
                    else if (warn) append("  ⚠ on ch${n.seenCh}")
                },
                color = if (!n.connected || warn) Palette.Red else Palette.Dim,
                fontSize = 10.sp, fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.height(6.dp))
            Sparkline(n.hist, accent)
        }
        Spacer(Modifier.width(10.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text("${n.fps}", color = Palette.Txt, fontSize = 24.sp, fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace)
            Text("F/S", color = Palette.Dim, fontSize = 9.sp, fontFamily = FontFamily.Monospace, letterSpacing = 2.sp)
        }
    }
}

@Composable
private fun Sparkline(hist: List<Int>, accent: Color) {
    val peak = (hist.maxOrNull() ?: 1).coerceAtLeast(1)
    Canvas(Modifier.fillMaxWidth().height(26.dp)) {
        if (hist.size < 2) return@Canvas
        val step = size.width / (hist.size - 1)
        val path = Path()
        hist.forEachIndexed { i, v ->
            val x = i * step
            val y = size.height - (v.toFloat() / peak) * (size.height - 2f) - 1f
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path, color = accent, style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2f))
    }
}

@Composable
private fun EmptyHint(state: UiState, modifier: Modifier = Modifier) {
    Column(
        modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text("⬢", color = Palette.Accent, fontSize = 48.sp)
        Spacer(Modifier.height(12.dp))
        Text(state.message ?: "Plug in the rig, it captures by itself.", color = Palette.Dim,
            fontSize = 13.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun BottomBar(state: UiState, onStart: () -> Unit, onStop: () -> Unit, onShare: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 14.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (state.running) {
            Button(onClick = onStop, Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Palette.Red)) {
                Text("STOP", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Palette.Bg)
            }
            Button(onClick = onShare,
                colors = ButtonDefaults.buttonColors(containerColor = Palette.Panel)) {
                Text("SHARE PCAP", fontFamily = FontFamily.Monospace, color = Palette.Accent)
            }
        } else if (state.scanning) {
            CircularProgressIndicator(color = Palette.Accent, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(10.dp))
            Text(state.message ?: "Scanning...", color = Palette.Dim, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        } else {
            Button(onClick = onStart, Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Palette.Accent)) {
                Text("START CAPTURE", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Palette.Bg)
            }
            if (state.captureFile != null) {
                Button(onClick = onShare,
                    colors = ButtonDefaults.buttonColors(containerColor = Palette.Panel)) {
                    Text("SHARE", fontFamily = FontFamily.Monospace, color = Palette.Accent)
                }
            }
        }
    }
}

@Composable
private fun ChannelItem(label: String, selected: Boolean, onClick: () -> Unit) {
    DropdownMenuItem(
        text = {
            Text(
                (if (selected) "✓ " else "   ") + label,
                color = if (selected) Palette.Accent else Palette.Txt,
                fontFamily = FontFamily.Monospace, fontSize = 13.sp,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            )
        },
        onClick = onClick,
    )
}

private fun fmtUp(sec: Long): String = if (sec >= 60) "${sec / 60}m${(sec % 60).toString().padStart(2, '0')}s" else "${sec}s"
