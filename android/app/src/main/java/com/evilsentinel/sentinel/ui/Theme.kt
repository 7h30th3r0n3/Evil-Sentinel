package com.evilsentinel.sentinel.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

object Palette {
    val Bg = Color(0xFF070B0F)
    val Panel = Color(0xFF0D141B)
    val PanelHi = Color(0xFF0E171F)
    val Line = Color(0xFF1C2A36)
    val Txt = Color(0xFFCFE9E0)
    val Dim = Color(0xFF5F7D78)
    val Green = Color(0xFF39D98A)
    val Amber = Color(0xFFF2C744)
    val Red = Color(0xFFFF5D5D)
    val Accent = Color(0xFF2DE0C8)
    val Accent5 = Color(0xFF8B7CFF)   // distinct accent for 5 GHz nodes/lane

    /** load 0..1 -> green / amber / red, like the desktop dashboard. */
    fun loadColor(load: Float): Color = when {
        load > 0.66f -> Red
        load > 0.33f -> Amber
        else -> Green
    }
}

private val DarkColors = darkColorScheme(
    primary = Palette.Accent,
    onPrimary = Palette.Bg,
    background = Palette.Bg,
    onBackground = Palette.Txt,
    surface = Palette.Panel,
    onSurface = Palette.Txt,
    surfaceVariant = Palette.PanelHi,
    error = Palette.Red,
)

@Composable
fun EvilSentinelTheme(content: @Composable () -> Unit) {
    // always dark; this is a radio tool
    MaterialTheme(colorScheme = DarkColors, content = content)
}
