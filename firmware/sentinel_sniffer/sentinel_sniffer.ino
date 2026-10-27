// ============================================================================
//  sentinel_sniffer.ino  -  ESP32-C3/C5/C6 passive 802.11 sniffer -> pcap over USB-CDC
//
//  ONE firmware, every mode chosen at runtime by the host:
//    - LOCK  : "ch N\n"  park on one channel, no hopping. 2.4 GHz (1..14) on any chip;
//              5 GHz (36..165) only on dual-band chips (ESP32-C5).
//    - HOP   : "hop\n"     sweep 2.4 GHz (weighted 1/6/11)
//              "hop5\n"    sweep 5 GHz           (C5 only)
//              "hopdual\n" sweep 2.4 + 5 GHz     (C5 only)
//  Boots in its last saved mode (NVS), else 2.4 GHz hop so it is useful standalone.
//
//  The band is selected automatically by the channel number: esp_wifi_set_channel()
//  switches to 5 GHz when given a 5 GHz channel. 5 GHz capability is detected once at
//  boot (set_channel(36) succeeds only on a dual-band radio) and reported in "id".
//
//  Streams pcap (LINKTYPE_IEEE802_11_RADIOTAP, 127) over native USB-CDC. 100% PASSIVE.
//  The 15-byte radiotap header carries the real RX channel (2.4 or 5 GHz) and RSSI.
//
//  Serial (USB-CDC) protocol:
//    "S" start stream   "X" stop   "ping"->pong
//    "id"   -> "sentinel v<ver> <chip> <bands> up<sec>" (keeps "sentinel"/"dualband" tokens)
//    "stat" -> "stat drops=.. qhigh=.. sent=.. up=.. ch=.. mode=.. tunefail=.. fcs=.."
//    "ch N\n"   lock channel N  (1..14 = 2.4 GHz, 36..165 = 5 GHz on C5)
//    "hop\n"    sweep 2.4 GHz    "hop5\n" sweep 5 GHz    "hopdual\n" sweep both
//    "fcs on|off\n"  keep the trailing FCS + flag it (on, default), or strip it (off)
//
//  Boards: ESP32-C3 / C6 (2.4 GHz), ESP32-C5 (dual-band). arduino-esp32 core 3.1+.
//  An RGB status LED is driven when the board exposes RGB_BUILTIN (no-op otherwise).
//  SPDX-License-Identifier: GPL-3.0-or-later  -  Copyright (c) 7h30th3r0n3
// ============================================================================
#include <WiFi.h>
#include <esp_wifi.h>
#include <freertos/queue.h>
#include <Preferences.h>
// Optional local status screen. Compiled in only for a board that has one, selected at build
// time: -DSENTINEL_TDONGLE (LilyGO T-Dongle-S3, ST7735 160x80) or -DSENTINEL_ATOMS3R
// (M5Stack AtomS3R, GC9107 128x128). Every other board builds exactly as before.
#if defined(SENTINEL_TDONGLE) || defined(SENTINEL_ATOMS3R)
  #define SENTINEL_DISPLAY 1
#endif
// Both screens use LovyanGFX. The AtomS3R deliberately does NOT use M5GFX: on this ESP32-S3,
// linking M5GFX kills the USB-Serial-JTAG CDC (the node stops answering "id" and streaming),
// while the identical LovyanGFX stack that drives the T-Dongle-S3 coexists with HWCDC fine.
#if defined(SENTINEL_TDONGLE) || defined(SENTINEL_ATOMS3R)
  #include <LovyanGFX.hpp>
#endif
#if defined(SENTINEL_ATOMS3R) && !defined(SENTINEL_NO_BL)
  #include <Wire.h>                             // AtomS3R backlight is an I2C LED driver (timeout)
#endif

#define FW_VERSION "1.0.0"

#if   defined(CONFIG_IDF_TARGET_ESP32C5)
  #define CHIP_STR "c5"
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
  #define CHIP_STR "c6"
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
  #define CHIP_STR "c3"
#else
  #define CHIP_STR "esp32"
#endif

#define CAP        512         // bytes captured per frame (full mgmt frames; data clipped)
#define QDEPTH     64          // RTOS queue depth (~33KB)
#define DWELL_MIN  110         // ms: minimum dwell before leaving a channel
#define DWELL_MAX  250         // ms: cap even if traffic keeps arriving
#define DWELL_QUIET 40         // ms of silence after the minimum before hopping early

struct Pkt { uint16_t len; uint16_t orig; int8_t rssi; uint8_t ch; uint8_t data[CAP]; };

static QueueHandle_t   q = nullptr;
static volatile bool   streaming = false;
static volatile bool   hdrSent   = false;
static uint8_t         channel = 1;
static bool            dualband = false;      // true on ESP32-C5 (5 GHz capable)
static bool            fcsAtEnd = true;       // keep + flag the trailing FCS (Wireshark validates CRC)

// health counters (surfaced via "stat")
static volatile uint32_t dropped   = 0;       // frames lost: queue full or TX buffer full
static volatile uint32_t sent      = 0;       // records written to the host
static volatile uint32_t qHigh     = 0;       // queue high-water mark
static volatile uint32_t tuneFails = 0;       // esp_wifi_set_channel failures (bad 5 GHz/DFS)
static volatile uint32_t lastFrameMs = 0;     // millis() of the most recent RX frame
static volatile uint32_t rxTotal   = 0;       // every RX frame (local display, independent of streaming)
static volatile int8_t   lastRssi  = 0;       // RSSI of the most recent RX frame (for the screen)

enum HopMode { HOP_NONE, HOP_24, HOP_5, HOP_DUAL };
static HopMode         hopMode = HOP_24;      // default: sweep 2.4 GHz (safe on every chip)

static Preferences     prefs;

// weighted 2.4 GHz schedule: 1/6/11 visited ~3x more often than the overlapping channels
static const uint8_t HOP24[] = {
  1,6,11, 2, 1,6,11, 3, 1,6,11, 4, 1,6,11, 5, 1,6,11, 7,
  1,6,11, 8, 1,6,11, 9, 1,6,11, 10, 1,6,11, 12, 1,6,11, 13 };
// 5 GHz 20 MHz channels the ESP32-C5 can actually RECEIVE (UNII-1/2A + low UNII-2C, 36..112).
// Above ~5.56 GHz (channel 116+) the C5 RX AGC/DC-offset is calibrated out of range and no
// frames are demodulated, so those channels are omitted from hopping and from channel locks.
static const uint8_t HOP5[] = {
  36,40,44,48, 52,56,60,64, 100,104,108,112 };

static inline bool valid24(int n) { return n >= 1 && n <= 14; }
static bool valid5(int n) { for (uint8_t c : HOP5) if (c == n) return true; return false; }
static inline void tune(uint8_t ch) {
  if (esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE) != ESP_OK) tuneFails++;
}
static const char* modeStr() {
  switch (hopMode) { case HOP_NONE: return "lock"; case HOP_24: return "hop";
                     case HOP_5: return "hop5"; default: return "hopdual"; }
}

// ---------------------------------------------------------------- RGB status LED
// plain int + #define (not an enum) to avoid Arduino auto-prototype ordering issues
#define LED_BOOT   0
#define LED_IDLE   1
#define LED_STREAM 2
#define LED_HOP    3
#define LED_DROP   4
#ifdef RGB_BUILTIN
static void ledSet(int s) {
  switch (s) {
    case LED_BOOT:   rgbLedWrite(RGB_BUILTIN,  0,  0, 40); break;  // blue
    case LED_IDLE:   rgbLedWrite(RGB_BUILTIN, 10, 10, 10); break;  // dim white
    case LED_STREAM: rgbLedWrite(RGB_BUILTIN,  0, 40,  0); break;  // green (locked, streaming)
    case LED_HOP:    rgbLedWrite(RGB_BUILTIN,  0, 28, 30); break;  // cyan (hopping, streaming)
    case LED_DROP:   rgbLedWrite(RGB_BUILTIN, 55,  0,  0); break;  // red (heavy drop)
  }
}
#else
static inline void ledSet(int) {}             // no-op on boards without a built-in RGB LED
#endif

static void updateLed() {
  static uint32_t last = 0, lastDrops = 0;
  uint32_t now = millis();
  if (now - last < 300) return;
  uint32_t delta = dropped - lastDrops;
  lastDrops = dropped; last = now;
  if (!streaming)              ledSet(LED_IDLE);
  else if (delta > 20)        ledSet(LED_DROP);     // > ~65 drops/s
  else if (hopMode != HOP_NONE) ledSet(LED_HOP);
  else                        ledSet(LED_STREAM);
}

// ---------------------------------------------------------------- capture
static void sniff_cb(void* buf, wifi_promiscuous_pkt_type_t t) {
  const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
  int len = p->rx_ctrl.sig_len;
  if (len < 10) return;
  lastFrameMs = millis();                 // feeds adaptive dwell even when not streaming
  rxTotal++; lastRssi = p->rx_ctrl.rssi;  // local display counters, counted for every frame
  if (!q || !streaming) return;
  // sig_len INCLUDES the 4-byte FCS. We keep it and flag "FCS at end" in radiotap so
  // Wireshark validates the CRC and parses IEs up to len-4 (unless "fcs off").
  uint16_t flen = (uint16_t)len;
  Pkt pk;
  pk.orig = flen;
  pk.len  = (flen < CAP) ? flen : CAP;
  pk.rssi = p->rx_ctrl.rssi;
  pk.ch   = p->rx_ctrl.channel;
  memcpy(pk.data, p->payload, pk.len);
  if (xQueueSend(q, &pk, 0) != pdTRUE) { dropped++; return; }
  uint32_t w = uxQueueMessagesWaiting(q);
  if (w > qHigh) qHigh = w;
}

static inline void le16(uint8_t* b, uint16_t v) { b[0]=v; b[1]=v>>8; }
static inline void le32(uint8_t* b, uint32_t v) { b[0]=v; b[1]=v>>8; b[2]=v>>16; b[3]=v>>24; }

#define RT_LEN 15                                   // radiotap: Flags + Channel + dBm antenna signal
static void sendHeader() {
  uint8_t g[24];
  le32(g+0,0xa1b2c3d4); le16(g+4,2); le16(g+6,4);
  le32(g+8,0); le32(g+12,0); le32(g+16,CAP+RT_LEN); le32(g+20,127);   // linktype 127 = radiotap
  Serial.write(g, 24);
}
static void sendRecord(const Pkt& pk) {
  // "fcs off" strips the trailing 4-byte FCS (only when the whole frame was captured) and
  // clears the radiotap FCS flag, for Wireshark builds that mis-handle a trailing FCS.
  uint16_t capOut  = pk.len;
  uint16_t origOut = pk.orig;
  if (!fcsAtEnd) {
    if (pk.orig >= 4) origOut = pk.orig - 4;
    if (pk.len == pk.orig && pk.len >= 4) capOut = pk.len - 4;   // FCS only present if not clipped
  }
  int total = 16 + RT_LEN + capOut;
  // never emit a PARTIAL record: drop the whole frame if the USB-CDC TX buffer lacks room,
  // so the pcap stream stays record-aligned (a partial write desyncs Wireshark).
  if (Serial.availableForWrite() < total) { dropped++; return; }
  uint32_t ms = millis();
  static uint8_t b[16 + RT_LEN + CAP];
  le32(b+0, ms/1000); le32(b+4, (ms%1000)*1000);
  le32(b+8, RT_LEN + capOut); le32(b+12, RT_LEN + origOut);   // caplen vs origlen (truncation-aware)
  uint8_t* rt = b + 16;                     // radiotap header, 15 bytes
  rt[0]=0; rt[1]=0; le16(rt+2, RT_LEN);
  le32(rt+4, 0x2A);                         // present: Flags(0x02) | Channel(0x08) | dBm antenna signal(0x20)
  rt[8] = fcsAtEnd ? 0x10 : 0x00;           // Flags: FCS present at end of frame
  rt[9] = 0;                                // pad so Channel is 2-byte aligned
  uint8_t ch = pk.ch >= 1 ? pk.ch : 1;
  uint16_t freq, chFlags;
  if (ch >= 36) { freq = 5000 + (uint16_t)ch * 5; chFlags = 0x0100; }        // 5 GHz
  else          { freq = (ch == 14) ? 2484 : 2412 + (ch - 1) * 5; chFlags = 0x0080; } // 2.4 GHz
  le16(rt+10, freq); le16(rt+12, chFlags);
  rt[14] = (uint8_t)pk.rssi;                // dBm antenna signal (signed)
  memcpy(b + 16 + RT_LEN, pk.data, capOut);
  Serial.write(b, 16 + RT_LEN + capOut);
  sent++;
}

static void startSniffer() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(50);
  if (!q) q = xQueueCreate(QDEPTH, sizeof(Pkt));
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniff_cb);
  tune(channel);
  // detect 5 GHz support once: set_channel to a 5 GHz channel succeeds only on a dual-band radio
  dualband = (esp_wifi_set_channel(36, WIFI_SECOND_CHAN_NONE) == ESP_OK);
  tune(channel);
}

// ---------------------------------------------------------------- persistence
static void saveState() {
  prefs.putUChar("mode", (uint8_t)hopMode);
  if (hopMode == HOP_NONE) prefs.putUChar("ch", channel);
}
static void loadState() {
  // Always boot in hopping, matching the "allhop" split: dual-band (C5) sweeps 5 GHz, the
  // rest sweep 2.4 GHz. A "ch N" lock applies live but does not survive a reboot by design.
  hopMode = dualband ? HOP_5 : HOP_24;
}

// ---------------------------------------------------------------- local status screen
#ifdef SENTINEL_DISPLAY

#if defined(SENTINEL_TDONGLE)
// LilyGO T-Dongle-S3: ST7735S 80x160 over SPI, backlight on GPIO38 (manual panel config).
class LGFX_TDongleS3 : public lgfx::LGFX_Device {
  lgfx::Panel_ST7735S _panel;
  lgfx::Bus_SPI       _bus;
  lgfx::Light_PWM     _light;
public:
  LGFX_TDongleS3() {
    { auto c = _bus.config();
      c.spi_host   = SPI2_HOST; c.spi_mode = 0; c.freq_write = 27000000;
      c.pin_sclk = 5; c.pin_mosi = 3; c.pin_miso = -1; c.pin_dc = 2;
      _bus.config(c); _panel.setBus(&_bus); }
    { auto c = _panel.config();
      c.pin_cs = 4; c.pin_rst = 1; c.pin_busy = -1;
      c.memory_width = 132; c.memory_height = 162;
      c.panel_width = 80;   c.panel_height = 160;
      c.offset_x = 26;      c.offset_y = 1;
      c.offset_rotation = 0; c.invert = true; c.rgb_order = false;
      _panel.config(c); }
    { auto c = _light.config(); c.pin_bl = 38; _light.config(c); _panel.setLight(&_light); }
    setPanel(&_panel);
  }
};
static LGFX_TDongleS3 tft;
static LGFX_Sprite    canvas(&tft);
static uint8_t        dispRot = 3;           // landscape 160x80; button toggles 3<->1 (flip 180)
#define DISP_BTN_PIN  0                       // BOOT button on the T-Dongle-S3
#elif defined(SENTINEL_ATOMS3R)
// M5Stack AtomS3R: GC9107 128x128 on SPI3, same explicit-config approach as the T-Dongle above.
// We drive it with LovyanGFX (not M5GFX): on this ESP32-S3, linking M5GFX kills the USB-Serial-JTAG
// CDC so the node never answers "id", whereas the LovyanGFX stack coexists with HWCDC. Pins and
// panel offsets match the AtomS3R hardware; the backlight is an I2C LED driver at 0x30 on
// SDA=GPIO45 / SCL=GPIO0, driven over Wire with a hard timeout so init can never block.
class AtomS3R_Backlight : public lgfx::ILight {
public:
  bool init(uint8_t brightness) override {
#ifndef SENTINEL_NO_BL
    Wire1.begin(45, 0, 400000);      // SDA=45, SCL=0
    Wire1.setTimeOut(50);            // ms: endTransmission returns on NAK/stuck bus, never hangs
    wr(0x00, 0b01000000); delay(1);  // chip enable
    wr(0x08, 0b00000001);            // enable the backlight channel
    wr(0x70, 0b00000000);
    setBrightness(brightness);
#endif
    return true;
  }
  void setBrightness(uint8_t brightness) override { wr(0x0e, brightness); }
private:
  static void wr(uint8_t reg, uint8_t val) {
#ifndef SENTINEL_NO_BL
    Wire1.beginTransmission(0x30);
    Wire1.write(reg); Wire1.write(val);
    Wire1.endTransmission();         // bounded by setTimeOut; return code ignored (passive, best-effort)
#else
    (void)reg; (void)val;
#endif
  }
};
class AtomS3R_GFX : public lgfx::LGFX_Device {
  lgfx::Panel_GC9107 _panel;
  lgfx::Bus_SPI      _bus;
  AtomS3R_Backlight  _light;
public:
  AtomS3R_GFX() {
    { auto c = _bus.config();
      c.spi_host = SPI3_HOST; c.spi_mode = 0;
      c.freq_write = 40000000; c.freq_read = 16000000; c.spi_3wire = true;
      c.pin_sclk = 15; c.pin_mosi = 21; c.pin_miso = -1; c.pin_dc = 42;
      _bus.config(c); _panel.setBus(&_bus); }
    { auto c = _panel.config();
      c.pin_cs = 14; c.pin_rst = 48; c.pin_busy = -1;
      c.panel_width = 128; c.panel_height = 128;
      c.offset_y = 32; c.readable = false; c.bus_shared = false;
      _panel.config(c); }
    _panel.setLight(&_light);
    setPanel(&_panel);
  }
};
static AtomS3R_GFX       tft;
static lgfx::LGFX_Sprite canvas(&tft);
static uint8_t dispRot = 0;                   // 128x128; button steps 90 per press
#define DISP_BTN_PIN  41                       // front display button on the AtomS3R
#endif
#ifndef DISP_BTN_PIN
#define DISP_BTN_PIN -1                        // boards without a rotate button
#endif

// palette mirrors the app/dashboard: near-black bg, cyan accent, green/amber/red load
static constexpr uint16_t C_BG = 0x0861, C_ACC = 0x2ED9, C_DIM = 0x4A69,
                          C_TXT = 0xDEFB, C_GRN = 0x2667, C_AMB = 0xFD20, C_RED = 0xF9A6;

static uint8_t spark[48];           // activity history (fps samples), oldest first
static uint8_t sparkN = 0;

static void displayInit() {
  tft.init();
  tft.setRotation(dispRot);
  tft.setBrightness(150);
  canvas.setColorDepth(16);
  canvas.createSprite(tft.width(), tft.height());
  canvas.fillScreen(C_BG);
  canvas.pushSprite(0, 0);
  if (DISP_BTN_PIN >= 0) pinMode(DISP_BTN_PIN, INPUT_PULLUP);
}

// Rotate the screen on a button press (debounced falling edge). No-op where there is no button.
// Square panels (AtomS3R) step 90 through all four orientations; the rectangular T-Dongle
// flips 180 so the aspect ratio stays landscape.
static void displayButtonPoll() {
  if (DISP_BTN_PIN < 0) return;
  static bool wasDown = false; static uint32_t tLast = 0;
  bool down = (digitalRead(DISP_BTN_PIN) == LOW);   // active-low
  uint32_t now = millis();
  if (down && !wasDown && (now - tLast) > 250) {    // fresh press
    tLast = now;
#if defined(SENTINEL_ATOMS3R)
    dispRot = (dispRot + 1) & 3;                    // square: 0->1->2->3->0, 90 per press
#else
    dispRot ^= 2;                                   // rectangular: 3<->1, flip 180, keep aspect
#endif
    tft.setRotation(dispRot);
    canvas.fillScreen(C_BG); canvas.pushSprite(0, 0);
  }
  wasDown = down;
}

static void displayUpdate() {
  static uint32_t last = 0, lastRx = 0;
  uint32_t now = millis();
  if (now - last < 250) return;
  uint32_t dt = now - last; last = now;
  uint32_t rx = rxTotal;
  uint32_t fps = (dt > 0) ? ((rx - lastRx) * 1000UL) / dt : 0;
  lastRx = rx;

  uint8_t s = (uint8_t)(fps > 255 ? 255 : fps);
  if (sparkN < sizeof(spark)) spark[sparkN++] = s;
  else { memmove(spark, spark + 1, sizeof(spark) - 1); spark[sizeof(spark) - 1] = s; }

  // shared text bits
  char chTxt[16];
  if (hopMode == HOP_NONE) snprintf(chTxt, sizeof(chTxt), "ch%u", channel);
  else                     snprintf(chTxt, sizeof(chTxt), "%s%u", modeStr(), channel);
  char fpsTxt[16]; snprintf(fpsTxt, sizeof(fpsTxt), "%lu", (unsigned long)fps);
  char totTxt[20]; uint32_t tot = rx;
  if (tot >= 1000) snprintf(totTxt, sizeof(totTxt), "tot %lu.%luk", (unsigned long)(tot / 1000), (unsigned long)((tot % 1000) / 100));
  else             snprintf(totTxt, sizeof(totTxt), "tot %lu", (unsigned long)tot);
  uint32_t up = millis() / 1000; char upTxt[20];
  if (up >= 60) snprintf(upTxt, sizeof(upTxt), "up %lum%02lus", (unsigned long)(up / 60), (unsigned long)(up % 60));
  else          snprintf(upTxt, sizeof(upTxt), "up %lus", (unsigned long)up);
  char rsTxt[16]; snprintf(rsTxt, sizeof(rsTxt), "rssi %d", (int)lastRssi);

  const int W = canvas.width(), H = canvas.height();
  const uint16_t loadCol = fps > 120 ? C_RED : fps > 40 ? C_AMB : C_GRN;
  canvas.fillScreen(C_BG);
  canvas.setTextSize(1);

  if (W >= H + H / 2) {
    // ---- wide layout (T-Dongle 160x80): two columns ----
    canvas.fillTriangle(3, 5, 8, 2, 8, 8, C_ACC);
    canvas.setFont(&fonts::Font0);
    canvas.setTextColor(C_ACC); canvas.setTextDatum(textdatum_t::top_left);
    canvas.drawString("EVIL-SENTINEL", 13, 1);
    canvas.setTextColor(C_TXT); canvas.setTextDatum(textdatum_t::top_right);
    canvas.drawString(chTxt, W - 2, 1);
    canvas.drawFastHLine(2, 12, W - 4, C_DIM);
    canvas.setTextDatum(textdatum_t::top_left);
    canvas.setTextColor(loadCol); canvas.setFont(&fonts::Font4);
    canvas.drawString(fpsTxt, 6, 17);
    canvas.setFont(&fonts::Font0); canvas.setTextColor(C_DIM);
    canvas.drawString("FRAMES/S", 7, 45);
    canvas.setTextColor(C_TXT); canvas.drawString(totTxt, 88, 18);
    canvas.setTextColor(C_DIM); canvas.drawString(upTxt, 88, 30);
    canvas.drawString(rsTxt, 88, 42);
    const int baseY = H - 6, bh_max = 20, x0 = 4, w = W - 8;
    uint8_t peak = 1; for (uint8_t i = 0; i < sparkN; i++) if (spark[i] > peak) peak = spark[i];
    int step = w / (int)sizeof(spark); if (step < 2) step = 2;
    for (int i = 0; i < sparkN; i++) {
      int bh = (spark[i] * bh_max) / peak; if (bh < 1 && spark[i] > 0) bh = 1;
      canvas.fillRect(x0 + i * step, baseY - bh, step - 1, bh, C_ACC);
    }
    canvas.drawFastHLine(2, H - 4, W - 4, C_DIM);
  } else {
    // ---- square layout (AtomS3R 128x128): stacked ----
    canvas.fillTriangle(4, 7, 10, 3, 10, 11, C_ACC);
    canvas.setFont(&fonts::Font0);
    canvas.setTextColor(C_ACC); canvas.setTextDatum(textdatum_t::top_left);
    canvas.drawString("EVIL-SENTINEL", 15, 3);
    canvas.setTextColor(C_TXT); canvas.setTextDatum(textdatum_t::top_right);
    canvas.drawString(chTxt, W - 4, 16);
    canvas.setTextColor(C_DIM); canvas.setTextDatum(textdatum_t::top_left);
    canvas.drawString(modeStr(), 4, 16);
    canvas.drawFastHLine(4, 28, W - 8, C_DIM);
    canvas.setTextColor(loadCol); canvas.setFont(&fonts::Font6);   // big numerals
    canvas.setTextDatum(textdatum_t::top_left);
    canvas.drawString(fpsTxt, 6, 34);
    canvas.setFont(&fonts::Font0); canvas.setTextColor(C_DIM);
    canvas.drawString("FRAMES / S", 6, 74);
    canvas.setTextColor(C_TXT); canvas.drawString(totTxt, 6, 90);
    canvas.setTextColor(C_DIM); canvas.drawString(upTxt, 6, 102);
    canvas.drawString(rsTxt, 76, 102);
    const int baseY = H - 6, bh_max = 14, x0 = 4, w = W - 8;
    uint8_t peak = 1; for (uint8_t i = 0; i < sparkN; i++) if (spark[i] > peak) peak = spark[i];
    int step = w / (int)sizeof(spark); if (step < 2) step = 2;
    for (int i = 0; i < sparkN; i++) {
      int bh = (spark[i] * bh_max) / peak; if (bh < 1 && spark[i] > 0) bh = 1;
      canvas.fillRect(x0 + i * step, baseY - bh, step - 1, bh, C_ACC);
    }
    canvas.drawFastHLine(4, H - 4, W - 8, C_DIM);
  }
  canvas.pushSprite(0, 0);
}

// Run the whole screen in its own task pinned to core 0. A passive capture node must keep
// answering "id" and streaming pcap no matter what the panel driver does, so the display never
// runs on the main task: if a display call ever stalls, it stalls only this task, not capture or
// the USB-CDC command loop. The task also owns every tft/canvas access, so there is no cross-core
// contention on the SPI bus.
static void displayTask(void*) {
  displayInit();
  for (;;) {
    displayButtonPoll();
    displayUpdate();
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}
static void displayStart() {
#ifndef SENTINEL_NO_DISP_TASK
  xTaskCreatePinnedToCore(displayTask, "disp", 8192, nullptr, 1, nullptr, 0);
#endif
}
#else
static inline void displayStart()      {}
#endif

void setup() {
  ledSet(LED_BOOT);
  Serial.setTxBufferSize(32768);  // HWCDC: large TX buffer to absorb busy-channel bursts
  Serial.begin(115200);           // baud ignored on native USB-CDC
  startSniffer();
  prefs.begin("sentinel", false);
  loadState();
  displayStart();                 // launch the screen last, in its own core-0 task (never blocks)
}

static void printId() {
  Serial.print("sentinel v" FW_VERSION " " CHIP_STR " ");
  Serial.print(dualband ? "dualband" : "2.4ghz");   // keeps the "dualband" discovery token
  Serial.print(" up"); Serial.print(millis() / 1000);
  Serial.println();
}
static void printStat() {
  Serial.print("stat drops="); Serial.print(dropped);
  Serial.print(" qhigh=");     Serial.print(qHigh);
  Serial.print(" sent=");      Serial.print(sent);
  Serial.print(" up=");        Serial.print(millis() / 1000);
  Serial.print(" ch=");        Serial.print(channel);
  Serial.print(" mode=");      Serial.print(modeStr());
  Serial.print(" tunefail=");  Serial.print(tuneFails);
  Serial.print(" fcs=");       Serial.print(fcsAtEnd ? "on" : "off");
  Serial.println();
}

void loop() {
  static char line[24]; static int li = 0;
  while (Serial.available()) {
    int c = Serial.read();
    if (c == 'S') { if (q) xQueueReset(q); hdrSent = false; streaming = true; li = 0; }
    else if (c == 'X') { streaming = false; li = 0; }
    else if (c == '\n' || c == '\r') {
      line[li] = 0;
      if (!strncmp(line, "ch ", 3) || (!strncmp(line, "ch", 2) && line[2] >= '0' && line[2] <= '9')) {
        int n = atoi(line + 2);                 // accepts "ch 36" (space) and "ch36"
        if (valid24(n) || (dualband && valid5(n))) { channel = (uint8_t)n; hopMode = HOP_NONE; tune(channel); saveState(); }
      }
      else if (!strcmp(line, "hopdual")) { if (dualband) { hopMode = HOP_DUAL; saveState(); } }
      else if (!strcmp(line, "hop5"))    { if (dualband) { hopMode = HOP_5; saveState(); } }
      else if (!strcmp(line, "hop"))     { hopMode = HOP_24; saveState(); }
      else if (!strcmp(line, "fcs on"))  { fcsAtEnd = true; }
      else if (!strcmp(line, "fcs off")) { fcsAtEnd = false; }
      else if (!strcmp(line, "ping"))    { Serial.println("pong"); }
      else if (!strcmp(line, "id"))      { printId(); }
      else if (!strcmp(line, "stat"))    { printStat(); }
      li = 0;
    } else if (li < (int)sizeof(line) - 1) { line[li++] = (char)c; }
  }

  // channel hopping (when not locked), with adaptive dwell:
  // leave early after DWELL_MIN once the channel goes quiet, but keep listening up to
  // DWELL_MAX while frames keep arriving; silent 5 GHz/DFS channels are skipped fast.
  static uint32_t last = 0; static int si = 0;
  if (hopMode != HOP_NONE) {
    uint32_t now = millis();
    uint32_t onCh = now - last;
    bool quiet = (now - lastFrameMs) >= DWELL_QUIET;
    if (onCh >= DWELL_MAX || (onCh >= DWELL_MIN && quiet)) {
      last = now;
      if (hopMode == HOP_24)      { si = (si + 1) % (int)sizeof(HOP24); channel = HOP24[si]; }
      else if (hopMode == HOP_5)  { si = (si + 1) % (int)sizeof(HOP5);  channel = HOP5[si]; }
      else {                       // HOP_DUAL: walk 2.4 list then 5 GHz list
        int tot = (int)sizeof(HOP24) + (int)sizeof(HOP5);
        si = (si + 1) % tot;
        channel = (si < (int)sizeof(HOP24)) ? HOP24[si] : HOP5[si - (int)sizeof(HOP24)];
      }
      tune(channel);
    }
  }

  if (streaming) {
    if (!hdrSent) { sendHeader(); hdrSent = true; }
    // drain the whole queue each pass (bounded by QDEPTH); sendRecord self-limits on TX backpressure
    Pkt pk;
    while (xQueueReceive(q, &pk, 0) == pdTRUE) sendRecord(pk);
  }

  updateLed();                              // the screen runs in its own task (see displayStart)
  delay(2);
}
