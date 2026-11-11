/*
 * MXR4000GT to MQTT Gateway
 * =========================
 * Zugangsdaten (WLAN, Tuya local_key ...) stehen in secrets.h
 * -> secrets.example.h nach secrets.h kopieren und ausfuellen.
 *
 * Hardware:   AZDelivery ESP32 D1 Mini NodeMCU (ESP32-WROOM-32)
 *             (laeuft auch auf ESP32-S3/C3 – alle ESP32 mit BLE)
 * Generator:  MaXpeedingRods MXR4000GT (Bluetooth-Modul "MXR4000GT-BL")
 *
 * Protokoll:  Tuya BLE (Protokoll v3)
 *             Service 0x1910, Write 0x2B11 (ohne Response), Notify 0x2B10
 *             AES-128-CBC, Login-Key = MD5(local_key[0..5]),
 *             Session-Key = MD5(local_key[0..5] + srand)
 *
 * Datenpunkte (aus Tuya-Datenmodell, Produkt jlblyn8z):
 *   101 switch            bool   Start/Stop
 *   102 percent_state     value  Tankfuellstand %
 *   103 power_on_time     value  Laufzeit aktuell min
 *   104 power_current     value  Ausgangsleistung W
 *   105 time_total        value  Gesamtlaufzeit min
 *   106 online_state      enum   0=offline(gestoppt) 1=online(laeuft) 2=protected
 *   107 fault             bitmap Fehler
 *   108 eco_switch        bool   ECO
 *   109 area_clean_alarm  bool   Oelwechsel faellig
 *   110 voltage           value  V
 *   111 frequency         value  Hz
 *   112 rev               value  rpm
 *   113 area_clean_alarm_reset string (nicht verwendet)
 *   114 generator_sn      string Seriennummer
 *   115 battery_level     value  %
 *   116 charging_capacity value  -1..5 Ladestatus
 *
 * Bibliotheken:
 *   - PubSubClient von Nick O'Leary
 *   - NimBLE-Arduino von h2zero (Version 2.x)
 *   (alle anderen im ESP32 Core enthalten, getestet mit Core 3.x)
 *
 * Board:      "ESP32 Dev Module" (oder "WEMOS D1 MINI ESP32")
 * Partition:  "Minimal SPIFFS (1.9MB APP with OTA)"  (BLE + WiFi braucht > 1.3 MB)
 * CPU:        80 MHz (WiFi + BLE)
 *
 * Changelog:
 *   1.6.1  Zugangsdaten in secrets.h ausgelagert (GitHub-Veroeffentlichung)
 *   1.6.0  Laufzeit-Timer: Generator wird nach max. Laufzeit gestoppt (Standard 2 h,
 *          waehlbar Aus/30 min..8 h, wahlweise nur fuer Starts ueber Gateway),
 *          Restzeit + "+30 min" im Dashboard, Select/Sensor/Button in HA
 *   1.5.2  Zweites Fallback-WLAN; Sketch umbenannt in Stromaggregat_Bluetooth.ino
 *   1.5.1  FIX: Gespeicherte (retained) MQTT-Befehle schalteten bei jedem
 *          MQTT-Reconnect BLE/Generator ab. Jetzt: retained Befehle werden beim
 *          Verbinden geloescht und 5 s lang ignoriert, nur exakt ON/OFF wird
 *          ausgefuehrt (leere/unbekannte Payloads ignoriert).
 *          Ereignisprotokoll (letzte 30 Ereignisse) auf der Diagnose-Seite
 *   1.5.0  Diagnose-Seite /dp: alle empfangenen Datenpunkte roh (auch unbekannte),
 *          neue DPs werden seriell geloggt
 *   1.4.0  Auto-ECO-Verzoegerung waehlbar (5/10/15/20 s) in Dashboard, Config, HA;
 *          Dauerbetrieb: Hardware-Watchdog (90 s), Neustart wenn Generator 2 h
 *          nicht erreichbar bzw. Heap knapp, "BLE trennen" endet nach 30 min
 *          automatisch, BLE nach fehlgeschlagenem OTA wieder aktiv,
 *          Neustartgrund + BLE-Statistik im Dashboard
 *   1.3.0  Auto-ECO: laeuft der Generator mit ECO aus, wird nach 5 s ECO
 *          eingeschaltet (Standard: an, Config/MQTT/Dashboard schaltbar);
 *          Schnellzugriff mit ECO-Schalter inkl. Statusanzeige
 *   1.2.1  Fix: Ausblenden nicht unterstuetzter Werte funktionierte nur mit
 *          MQTT-Verbindung; jetzt im BLE-Task, nach 60 s Verbindung
 *   1.2.0  Nicht unterstuetzte DPs (z.B. Drehzahl, Batterie) werden nach 2 min
 *          Verbindung im Dashboard ausgeblendet und aus HA entfernt; HA-Discovery
 *          nur fuer tatsaechlich gemeldete Werte
 *   1.1.1  Systemwerte (Uptime, RSSI, Heap, MQTT) live im Dashboard
 *   1.1.0  Live-Dashboard: Gauges Leistung/Tank, Kraftstoffanzeige, Kacheln,
 *          Schnellzugriff, JSON-API /api (Update alle 2s)
 *   1.0.2  Backup-WLAN (FIXED_SSID2), WLAN-Reihenfolge Config -> FIXED_SSID -> FIXED_SSID2,
 *          AP-Watchdog repariert (AP bleibt erhalten, Versuch alle 5 min)
 *   1.0.1  AP-SSID ohne MAC-Anhang ("MXR4000"), Board D1 Mini ESP32
 *   1.0.0  Erste Version: Tuya BLE, MQTT/HA-Discovery, Web, OTA
 */


#define FW_VERSION "1.6.1"


#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <Update.h>
#include <PubSubClient.h>
#include <Preferences.h>
#include <MD5Builder.h>
#include <NimBLEDevice.h>
#include <time.h>
#include <sys/time.h>
#include "mbedtls/aes.h"
#include "esp_random.h"
#include "esp_task_wdt.h"

// ============================================================
//  Zugangsdaten: WLAN-Fallback + Generator (Tuya) -> secrets.h
// ============================================================
#if __has_include("secrets.h")
  #include "secrets.h"
#else
  #warning "secrets.h fehlt - verwende Platzhalter aus secrets.example.h (Einrichtung dann per AP 'MXR4000' + Web-Config)"
  #include "secrets.example.h"
#endif

#define DEFAULT_HOSTNAME          "MXR4000GT_Gateway"
#define DEFAULT_MQTT_PORT         1883
#define DEFAULT_MQTT_TOPIC        "MXR4000GT"
#define DEFAULT_PUBLISH_INTERVAL  30

#define TZ_INFO             "CET-1CEST,M3.5.0,M10.5.0/3"   // Europa/Wien
#define NTP_SERVER          "pool.ntp.org"

// Dauerbetrieb
#define WDT_TIMEOUT_S        90                 // Hardware-Watchdog
#define BLE_LOST_REBOOT_MS   (2UL * 3600000UL)  // Neustart wenn Generator so lange nicht erreichbar
#define BLE_OFF_MAX_MS       (30UL * 60000UL)   // "BLE trennen" endet automatisch
#define HEAP_MIN_BYTES       25000              // darunter Neustart

#define CFG_SSID_LEN      64
#define MAX_PASS_LEN      64
#define MAX_MQTT_HOST_LEN 64
#define MAX_MQTT_USER_LEN 32
#define MAX_MQTT_PASS_LEN 64
#define MAX_HOSTNAME_LEN  32
#define MAX_TOPIC_LEN     32
#define MAX_MAC_LEN       18
#define MAX_KEY_LEN       24
#define MAX_UUID_LEN      24
#define MAX_DEVID_LEN     32

// ============================================================
//  Tuya BLE
// ============================================================
#define TUYA_SERVICE_UUID   ((uint16_t)0x1910)
#define TUYA_WRITE_UUID     ((uint16_t)0x2B11)
#define TUYA_NOTIFY_UUID    ((uint16_t)0x2B10)
#define TUYA_FRAG_SIZE      20     // GATT_MTU 23 - 3
#define TUYA_PROTO_HDR      0x20   // Protokollversion 2 << 4 (wie Original-App)

#define TUYA_DEVICE_INFO    0x0000
#define TUYA_PAIR           0x0001
#define TUYA_SEND_DPS       0x0002
#define TUYA_DEVICE_STATUS  0x0003
#define TUYA_RECV_DP        0x8001
#define TUYA_RECV_TIME_DP   0x8003
#define TUYA_RECV_SIGN_DP   0x8004
#define TUYA_RECV_SIGN_TDP  0x8005
#define TUYA_TIME1_REQ      0x8011
#define TUYA_TIME2_REQ      0x8012

#define DP_TYPE_RAW     0
#define DP_TYPE_BOOL    1
#define DP_TYPE_VALUE   2
#define DP_TYPE_STRING  3
#define DP_TYPE_ENUM    4
#define DP_TYPE_BITMAP  5

#define DP_SWITCH       101
#define DP_TANK         102
#define DP_RUN_MIN      103
#define DP_POWER        104
#define DP_TOTAL_MIN    105
#define DP_STATE        106
#define DP_FAULT        107
#define DP_ECO          108
#define DP_OIL_ALARM    109
#define DP_VOLTAGE      110
#define DP_FREQ         111
#define DP_RPM          112
#define DP_SN           114
#define DP_BATTERY      115
#define DP_CHARGING     116

#define HAVE(dp)        (1UL << ((dp) - 101))

// ============================================================
//  Datenstrukturen
// ============================================================
struct Config {
  char ssid[CFG_SSID_LEN];
  char wifi_pass[MAX_PASS_LEN];
  char mqtt_host[MAX_MQTT_HOST_LEN];
  uint16_t mqtt_port;
  char mqtt_user[MAX_MQTT_USER_LEN];
  char mqtt_pass[MAX_MQTT_PASS_LEN];
  char hostname[MAX_HOSTNAME_LEN];
  char mqtt_topic[MAX_TOPIC_LEN];
  uint16_t publish_interval;
  char ble_mac[MAX_MAC_LEN];
  char local_key[MAX_KEY_LEN];
  char uuid[MAX_UUID_LEN];
  char dev_id[MAX_DEVID_LEN];
  bool allow_start;     // Fernstart ueber MQTT/Web erlaubt
  bool ble_autostart;   // BLE beim Booten aktiv
  bool auto_eco;        // laufender Generator wird automatisch auf ECO gestellt
  uint8_t eco_delay;    // Verzoegerung Auto-ECO in s (5/10/15/20)
  uint16_t max_run_min; // Laufzeit-Timer in min (0 = aus)
  bool timer_all;       // Timer fuer alle Starts (sonst nur Starts ueber Gateway)
};

struct GenData {
  uint32_t have;        // Bitmaske: welche DPs schon empfangen
  bool     running;
  int32_t  tank;
  int32_t  run_min;
  int32_t  power_w;
  int32_t  total_min;
  uint8_t  state;
  uint32_t fault;
  bool     eco;
  bool     oil_alarm;
  int32_t  voltage;
  int32_t  freq;
  int32_t  rpm;
  int32_t  battery;
  int32_t  charging;
  char     sn[24];
};

struct Frag     { uint8_t len; uint8_t d[64]; };
struct TuyaCmd  { uint8_t dp; uint8_t type; int32_t value; };

// ============================================================
//  Globale Variablen
// ============================================================
Config       cfg;
Preferences  prefs;
GenData      gen;
portMUX_TYPE gen_mux = portMUX_INITIALIZER_UNLOCKED;

WiFiClient   wifi_client;
PubSubClient mqtt(wifi_client);
WebServer    web_server(80);

bool     wifi_connected    = false;
bool     ap_mode           = false;
bool     ha_discovery_done = false;
uint32_t last_reconnect_ms = 0;
uint32_t mqtt_connected_ms = 0;
int      last_ble_online   = -1;
uint32_t disc_mask         = 0;      // DPs, fuer die HA-Discovery gesendet wurde
bool     dp_list_final     = false;  // nach 2 min Verbindung: nie gemeldete DPs entfernen
uint32_t online_since_ms   = 0;
uint32_t ble_connect_count = 0;      // erfolgreiche Logins seit Boot
uint32_t ble_fail_count    = 0;      // fehlgeschlagene Verbindungsversuche
uint32_t last_paired_ms    = 0;      // zuletzt mit Generator verbunden

// BLE / Tuya Zustand
NimBLEClient*               ble_client = nullptr;
NimBLERemoteCharacteristic* ble_wr     = nullptr;
NimBLERemoteCharacteristic* ble_nt     = nullptr;
QueueHandle_t frag_q = nullptr;
QueueHandle_t cmd_q  = nullptr;

volatile bool     ble_enabled    = true;
volatile bool     ble_connected  = false;
volatile bool     tuya_paired    = false;
volatile int      ble_rssi       = 0;
volatile uint32_t last_rx_ms     = 0;
char              ble_state_txt[48] = "Start";

uint8_t  lk6[6];
uint8_t  login_key[16];
uint8_t  session_key[16];
bool     have_session = false;
uint32_t tuya_seq     = 1;

uint8_t  rx_buf[512];
size_t   rx_len       = 0;
size_t   rx_expected  = 0;
uint32_t rx_next_num  = 0;

static const char* FAULT_TXT[16] = {
  "Kein Fehler", "Überlast", "Kurzschluss", "Unterspannung",
  "Zwischenkreis zu hoch", "Zwischenkreis zu niedrig", "Nulldurchgang-Fehler",
  "Übertemperatur", "Hardware-Überstrom", "Frequenz passt nicht",
  "Drehzahl zu niedrig", "Spannung asymmetrisch", "Per Befehl abgeschaltet",
  "Verschlüsselungsfehler", "Master/Slave-Kommunikation", "Reserviert"
};

// ============================================================
//  Konfiguration
// ============================================================
void config_defaults() {
  memset(&cfg, 0, sizeof(cfg));
  strlcpy(cfg.hostname,   DEFAULT_HOSTNAME,   MAX_HOSTNAME_LEN);
  strlcpy(cfg.mqtt_topic, DEFAULT_MQTT_TOPIC, MAX_TOPIC_LEN);
  cfg.mqtt_port        = DEFAULT_MQTT_PORT;
  cfg.publish_interval = DEFAULT_PUBLISH_INTERVAL;
  strlcpy(cfg.ble_mac,   DEFAULT_BLE_MAC,   MAX_MAC_LEN);
  strlcpy(cfg.uuid,      DEFAULT_UUID,      MAX_UUID_LEN);
  strlcpy(cfg.dev_id,    DEFAULT_DEVICE_ID, MAX_DEVID_LEN);
  strlcpy(cfg.local_key, DEFAULT_LOCAL_KEY, MAX_KEY_LEN);
  cfg.allow_start   = false;
  cfg.ble_autostart = true;
  cfg.auto_eco      = true;
  cfg.eco_delay     = 5;
  cfg.max_run_min   = 120;
  cfg.timer_all     = true;
}

void config_load() {
  config_defaults();
  prefs.begin("mxr4000", true);
  prefs.getString("ssid",      cfg.ssid,       CFG_SSID_LEN);
  prefs.getString("wifi_pass", cfg.wifi_pass,  MAX_PASS_LEN);
  prefs.getString("mqtt_host", cfg.mqtt_host,  MAX_MQTT_HOST_LEN);
  cfg.mqtt_port        = prefs.getUShort("mqtt_port", DEFAULT_MQTT_PORT);
  prefs.getString("mqtt_user", cfg.mqtt_user,  MAX_MQTT_USER_LEN);
  prefs.getString("mqtt_pass", cfg.mqtt_pass,  MAX_MQTT_PASS_LEN);
  prefs.getString("hostname",  cfg.hostname,   MAX_HOSTNAME_LEN);
  prefs.getString("mtopic",    cfg.mqtt_topic, MAX_TOPIC_LEN);
  cfg.publish_interval = prefs.getUShort("pub_iv", DEFAULT_PUBLISH_INTERVAL);
  if (prefs.isKey("ble_mac")) prefs.getString("ble_mac", cfg.ble_mac,   MAX_MAC_LEN);
  if (prefs.isKey("uuid"))    prefs.getString("uuid",    cfg.uuid,      MAX_UUID_LEN);
  if (prefs.isKey("dev_id"))  prefs.getString("dev_id",  cfg.dev_id,    MAX_DEVID_LEN);
  if (prefs.isKey("lkey"))    prefs.getString("lkey",    cfg.local_key, MAX_KEY_LEN);
  cfg.allow_start   = prefs.getBool("allow_st", false);
  cfg.ble_autostart = prefs.getBool("ble_auto", true);
  cfg.auto_eco      = prefs.getBool("auto_eco", true);
  cfg.eco_delay     = prefs.getUChar("eco_dly", 5);
  cfg.max_run_min   = prefs.getUShort("max_run", 120);
  cfg.timer_all     = prefs.getBool("tmr_all", true);
  prefs.end();

  Serial.printf("[CFG] SSID='%s' (Länge=%d)\n", cfg.ssid, strlen(cfg.ssid));
  Serial.printf("[CFG] MQTT='%s:%d'\n", cfg.mqtt_host, cfg.mqtt_port);
  Serial.printf("[CFG] BLE MAC=%s UUID=%s DevID=%s Key=%s\n",
    cfg.ble_mac, cfg.uuid, cfg.dev_id, strlen(cfg.local_key) >= 6 ? "(gesetzt)" : "(FEHLT)");
  Serial.printf("[CFG] Fernstart: %s, Auto-ECO: %s\n", cfg.allow_start ? "ERLAUBT" : "gesperrt",
    cfg.auto_eco ? "an" : "aus");
}

void config_save() {
  prefs.begin("mxr4000", false);
  prefs.putString("ssid",      cfg.ssid);
  prefs.putString("wifi_pass", cfg.wifi_pass);
  prefs.putString("mqtt_host", cfg.mqtt_host);
  prefs.putUShort("mqtt_port", cfg.mqtt_port);
  prefs.putString("mqtt_user", cfg.mqtt_user);
  prefs.putString("mqtt_pass", cfg.mqtt_pass);
  prefs.putString("hostname",  cfg.hostname);
  prefs.putString("mtopic",    cfg.mqtt_topic);
  prefs.putUShort("pub_iv",    cfg.publish_interval);
  prefs.putString("ble_mac",   cfg.ble_mac);
  prefs.putString("uuid",      cfg.uuid);
  prefs.putString("dev_id",    cfg.dev_id);
  prefs.putString("lkey",      cfg.local_key);
  prefs.putBool("allow_st",    cfg.allow_start);
  prefs.putBool("ble_auto",    cfg.ble_autostart);
  prefs.putBool("auto_eco",    cfg.auto_eco);
  prefs.putUChar("eco_dly",    cfg.eco_delay);
  prefs.putUShort("max_run",   cfg.max_run_min);
  prefs.putBool("tmr_all",     cfg.timer_all);
  prefs.end();
}

bool ble_configured() {
  return strlen(cfg.ble_mac) == 17 && strlen(cfg.local_key) >= 6 &&
         strlen(cfg.uuid) > 0 && strlen(cfg.dev_id) > 0;
}

// ============================================================
//  Hilfsfunktionen
// ============================================================
String html_esc(const char* s) {
  String o;
  for (; *s; s++) {
    switch (*s) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '\'': o += "&#39;";  break;
      case '"':  o += "&quot;"; break;
      default:   o += *s;
    }
  }
  return o;
}

void gen_snapshot(GenData& out) {
  taskENTER_CRITICAL(&gen_mux);
  out = gen;
  taskEXIT_CRITICAL(&gen_mux);
}

const char* state_txt(uint8_t s) {
  switch (s) {
    case 0:  return "Gestoppt";
    case 1:  return "Läuft";
    case 2:  return "Schutz";
    default: return "Unbekannt";
  }
}

const char* charging_txt(int32_t c) {
  switch (c) {
    case 0:  return "Standard";
    case 1:  return "Batterie schwach";
    case 2:  return "Lädt";
    case 3:  return "Kalibrierung nach Stromausfall";
    case 4:  return "Normal";
    default: return "Unbekannt";
  }
}

String fault_txt(uint32_t f) {
  if (f == 0) return "OK";
  String s;
  for (int i = 0; i < 16; i++) {
    if (f & (1UL << i)) {
      if (s.length()) s += ", ";
      s += FAULT_TXT[i];
    }
  }
  return s;
}

const char* reset_reason_txt() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "Stromversorgung ein";
    case ESP_RST_SW:       return "Software-Neustart";
    case ESP_RST_PANIC:    return "Absturz";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:      return "Watchdog";
    case ESP_RST_BROWNOUT: return "Unterspannung (Netzteil prüfen)";
    case ESP_RST_EXT:      return "Reset-Taste";
    case ESP_RST_DEEPSLEEP:return "Deep Sleep";
    default:               return "Unbekannt";
  }
}

// ============================================================
//  Ereignisprotokoll (Ringpuffer, fuer Fern-Diagnose)
// ============================================================
#define EVLOG_N   30
#define EVLOG_LEN 96
char     evlog[EVLOG_N][EVLOG_LEN];
uint8_t  evlog_head  = 0;
uint8_t  evlog_count = 0;
portMUX_TYPE evlog_mux = portMUX_INITIALIZER_UNLOCKED;

void log_event(const char* fmt, ...) {
  char msg[72];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  char ts[24];
  time_t now = time(nullptr);
  if (now > 1700000000) {
    struct tm lt;
    localtime_r(&now, &lt);
    strftime(ts, sizeof(ts), "%d.%m. %H:%M:%S", &lt);
  } else {
    snprintf(ts, sizeof(ts), "+%lus", (unsigned long)(millis() / 1000));
  }
  char line[EVLOG_LEN];
  snprintf(line, sizeof(line), "%s  %s", ts, msg);
  Serial.printf("[EVT] %s\n", line);
  taskENTER_CRITICAL(&evlog_mux);
  strlcpy(evlog[evlog_head], line, EVLOG_LEN);
  evlog_head = (evlog_head + 1) % EVLOG_N;
  if (evlog_count < EVLOG_N) evlog_count++;
  taskEXIT_CRITICAL(&evlog_mux);
}

// ============================================================
//  Tuya BLE: Krypto & Framing
// ============================================================
void md5_bytes(const uint8_t* d, size_t n, uint8_t out[16]) {
  MD5Builder m;
  m.begin();
  m.add((uint8_t*)d, n);
  m.calculate();
  m.getBytes(out);
}

uint16_t tuya_crc16(const uint8_t* d, size_t n) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++) crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : (crc >> 1);
  }
  return crc;
}

size_t put_varint(uint8_t* o, uint32_t v) {
  size_t n = 0;
  do {
    uint8_t b = v & 0x7F;
    v >>= 7;
    if (v) b |= 0x80;
    o[n++] = b;
  } while (v);
  return n;
}

bool get_varint(const uint8_t* d, size_t len, size_t& p, uint32_t& v) {
  v = 0;
  int shift = 0;
  while (p < len) {
    uint8_t b = d[p++];
    v |= (uint32_t)(b & 0x7F) << shift;
    if (!(b & 0x80)) return true;
    shift += 7;
    if (shift > 28) return false;
  }
  return false;
}

void put_be32(uint8_t* o, uint32_t v) { o[0]=v>>24; o[1]=v>>16; o[2]=v>>8; o[3]=v; }
void put_be16(uint8_t* o, uint16_t v) { o[0]=v>>8;  o[1]=v; }
uint32_t get_be32(const uint8_t* d)   { return ((uint32_t)d[0]<<24)|((uint32_t)d[1]<<16)|((uint32_t)d[2]<<8)|d[3]; }
uint16_t get_be16(const uint8_t* d)   { return ((uint16_t)d[0]<<8)|d[1]; }

void tuya_init_keys() {
  memcpy(lk6, cfg.local_key, 6);
  md5_bytes(lk6, 6, login_key);
  have_session = false;
}

// Paket bauen, verschluesseln, fragmentieren und senden (nur aus BLE-Task!)
bool tuya_send(uint16_t code, const uint8_t* data, uint16_t dlen, uint32_t resp_to = 0) {
  if (!ble_wr) return false;
  uint8_t raw[160];
  size_t n      = 12 + dlen + 2;
  size_t padded = (n + 15) & ~(size_t)15;
  if (padded > sizeof(raw)) { Serial.println("[TUYA] Paket zu gross"); return false; }

  uint32_t seq = tuya_seq++;
  put_be32(raw,     seq);
  put_be32(raw + 4, resp_to);
  put_be16(raw + 8, code);
  put_be16(raw + 10, dlen);
  if (dlen) memcpy(raw + 12, data, dlen);
  put_be16(raw + 12 + dlen, tuya_crc16(raw, 12 + dlen));
  memset(raw + n, 0, padded - n);

  uint8_t flag = (code == TUYA_DEVICE_INFO) ? 4 : 5;
  if (flag == 5 && !have_session) return false;
  const uint8_t* key = (flag == 4) ? login_key : session_key;

  uint8_t pkt[17 + sizeof(raw)];
  pkt[0] = flag;
  esp_fill_random(pkt + 1, 16);
  uint8_t iv[16];
  memcpy(iv, pkt + 1, 16);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded, iv, raw, pkt + 17);
  mbedtls_aes_free(&aes);

  size_t total = 17 + padded;
  size_t pos = 0;
  uint32_t num = 0;
  while (pos < total) {
    uint8_t f[TUYA_FRAG_SIZE];
    size_t fl = put_varint(f, num);
    if (num == 0) {
      fl += put_varint(f + fl, total);
      f[fl++] = TUYA_PROTO_HDR;
    }
    size_t chunk = min(TUYA_FRAG_SIZE - fl, total - pos);
    memcpy(f + fl, pkt + pos, chunk);
    fl  += chunk;
    pos += chunk;
    num++;
    if (!ble_wr->writeValue(f, fl, false)) {
      Serial.println("[TUYA] Schreiben fehlgeschlagen");
      return false;
    }
    vTaskDelay(pdMS_TO_TICKS(8));
  }
  Serial.printf("[TUYA] TX seq=%u code=0x%04X len=%u\n", seq, code, dlen);
  return true;
}

// ============================================================
//  Tuya BLE: Datenpunkte
// ============================================================
int32_t dp_int(const uint8_t* v, uint8_t len) {
  if (len == 0) return 0;
  uint32_t r = (v[0] & 0x80) ? 0xFFFFFFFF : 0;   // Vorzeichen
  for (uint8_t i = 0; i < len && i < 4; i++) r = (r << 8) | v[i];
  return (int32_t)r;
}

// Diagnose: jeder empfangene DP (auch unbekannte) roh gespeichert
struct DpSeen { uint8_t type; uint8_t len; uint8_t raw[24]; uint32_t ms; uint32_t count; };
DpSeen dp_seen[256];
uint32_t dp_frames = 0;

void handle_dp(uint8_t id, uint8_t type, const uint8_t* v, uint8_t len) {
  {
    DpSeen& ds = dp_seen[id];
    bool first   = ds.count == 0;
    bool changed = first || ds.len != len || ds.type != type || memcmp(ds.raw, v, min((size_t)len, sizeof(ds.raw))) != 0;
    taskENTER_CRITICAL(&gen_mux);
    ds.type = type;
    ds.len  = len;
    memcpy(ds.raw, v, min((size_t)len, sizeof(ds.raw)));
    ds.ms   = millis();
    ds.count++;
    taskEXIT_CRITICAL(&gen_mux);
    if (first || (changed && (id < 101 || id > 116))) {
      Serial.printf("[DP] %s DP %u Typ %u Len %u:", first ? "NEU" : "Änderung", id, type, len);
      for (int i = 0; i < len && i < 24; i++) Serial.printf(" %02X", v[i]);
      Serial.println();
    }
  }
  int32_t iv = dp_int(v, len);
  taskENTER_CRITICAL(&gen_mux);
  switch (id) {
    case DP_SWITCH:    gen.running   = iv != 0; break;
    case DP_TANK:      gen.tank      = iv; break;
    case DP_RUN_MIN:   gen.run_min   = iv; break;
    case DP_POWER:     gen.power_w   = iv; break;
    case DP_TOTAL_MIN: gen.total_min = iv; break;
    case DP_STATE:     gen.state     = (uint8_t)iv; break;
    case DP_FAULT:     gen.fault     = (uint32_t)iv & 0xFFFF; break;
    case DP_ECO:       gen.eco       = iv != 0; break;
    case DP_OIL_ALARM: gen.oil_alarm = iv != 0; break;
    case DP_VOLTAGE:   gen.voltage   = iv; break;
    case DP_FREQ:      gen.freq      = iv; break;
    case DP_RPM:       gen.rpm       = iv; break;
    case DP_BATTERY:   gen.battery   = iv; break;
    case DP_CHARGING:  gen.charging  = iv; break;
    case DP_SN: {
      size_t n = min((size_t)len, sizeof(gen.sn) - 1);
      memcpy(gen.sn, v, n);
      gen.sn[n] = 0;
      break;
    }
    default: break;
  }
  if (id >= 101 && id <= 116) gen.have |= HAVE(id);
  taskEXIT_CRITICAL(&gen_mux);
}

void parse_dps(const uint8_t* d, size_t len, size_t p) {
  dp_frames++;
  while (len >= p + 3) {
    uint8_t id   = d[p];
    uint8_t type = d[p + 1];
    uint8_t l    = d[p + 2];
    p += 3;
    if (p + l > len) break;
    handle_dp(id, type, d + p, l);
    p += l;
  }
}

// Zeitstempel in TIME_DP-Paketen ueberspringen
size_t skip_timestamp(const uint8_t* d, size_t len, size_t p) {
  if (p >= len) return len;
  uint8_t t = d[p++];
  if (t == 0) p += 13;        // ASCII Millisekunden
  else if (t == 1) p += 4;    // Unix-Sekunden
  return p;
}

// Zeitzone in 1/100 Stunden (z.B. +0200 -> 200)
int16_t tz_hundredths() {
  time_t now = time(nullptr);
  struct tm lt, gt;
  localtime_r(&now, &lt);
  gmtime_r(&now, &gt);
  int diff = (lt.tm_hour - gt.tm_hour) * 3600 + (lt.tm_min - gt.tm_min) * 60;
  int dd = lt.tm_yday - gt.tm_yday;
  if (dd == 1 || dd < -1) diff += 86400;
  else if (dd == -1 || dd > 1) diff -= 86400;
  return (int16_t)(diff / 36);
}

void tuya_handle(uint32_t seq, uint16_t code, const uint8_t* d, uint16_t len) {
  switch (code) {
    case TUYA_DEVICE_INFO: {
      if (len < 12) { Serial.println("[TUYA] Device-Info zu kurz"); return; }
      Serial.printf("[TUYA] Device-Info: FW %d.%d, Protokoll %d.%d, gebunden=%d\n",
        d[0], d[1], d[2], d[3], d[5]);
      uint8_t tmp[12];
      memcpy(tmp, lk6, 6);
      memcpy(tmp + 6, d + 6, 6);     // srand
      md5_bytes(tmp, 12, session_key);
      have_session = true;

      // Pairing: uuid + local_key[0..5] + device_id, auf 44 Bytes aufgefuellt
      uint8_t pr[44];
      memset(pr, 0, sizeof(pr));
      size_t p = 0;
      size_t ul = min(strlen(cfg.uuid), (size_t)16);
      memcpy(pr + p, cfg.uuid, ul); p += ul;
      memcpy(pr + p, lk6, 6);       p += 6;
      size_t il = min(strlen(cfg.dev_id), sizeof(pr) - p);
      memcpy(pr + p, cfg.dev_id, il);
      tuya_send(TUYA_PAIR, pr, sizeof(pr));
      strlcpy(ble_state_txt, "Pairing...", sizeof(ble_state_txt));
      break;
    }
    case TUYA_PAIR: {
      uint8_t r = len ? d[0] : 0xFF;
      if (r == 0 || r == 2) {
        Serial.printf("[TUYA] Pairing OK (%d)\n", r);
        tuya_paired = true;
        ble_connect_count++;
        log_event("BLE verbunden + Login OK");
        strlcpy(ble_state_txt, "Verbunden", sizeof(ble_state_txt));
        tuya_send(TUYA_DEVICE_STATUS, nullptr, 0);
      } else {
        Serial.printf("[TUYA] Pairing abgelehnt (%d) – uuid/device_id/local_key prüfen\n", r);
        strlcpy(ble_state_txt, "Pairing abgelehnt", sizeof(ble_state_txt));
        if (ble_client) ble_client->disconnect();
      }
      break;
    }
    case TUYA_SEND_DPS:
      Serial.printf("[TUYA] DP-Befehl bestätigt (%d)\n", len ? d[0] : -1);
      break;
    case TUYA_DEVICE_STATUS:
      break;
    case TUYA_RECV_DP:
      parse_dps(d, len, 0);
      tuya_send(code, nullptr, 0, seq);
      break;
    case TUYA_RECV_TIME_DP:
      parse_dps(d, len, skip_timestamp(d, len, 0));
      tuya_send(code, nullptr, 0, seq);
      break;
    case TUYA_RECV_SIGN_DP:
    case TUYA_RECV_SIGN_TDP: {
      if (len < 3) return;
      size_t p = 3;
      if (code == TUYA_RECV_SIGN_TDP) p = skip_timestamp(d, len, 3);
      parse_dps(d, len, p);
      uint8_t r[4] = { d[0], d[1], d[2], 0 };   // dp_seq, flags, ok
      tuya_send(code, r, 4, seq);
      break;
    }
    case TUYA_TIME1_REQ: {
      struct timeval tv;
      gettimeofday(&tv, nullptr);
      uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
      uint8_t r[24];
      int n = snprintf((char*)r, 20, "%llu", (unsigned long long)ms);
      put_be16(r + n, (uint16_t)tz_hundredths());
      tuya_send(code, r, n + 2, seq);
      break;
    }
    case TUYA_TIME2_REQ: {
      time_t now = time(nullptr);
      struct tm lt;
      localtime_r(&now, &lt);
      uint8_t r[9] = {
        (uint8_t)(lt.tm_year % 100), (uint8_t)(lt.tm_mon + 1), (uint8_t)lt.tm_mday,
        (uint8_t)lt.tm_hour, (uint8_t)lt.tm_min, (uint8_t)lt.tm_sec,
        (uint8_t)((lt.tm_wday + 6) % 7), 0, 0 };
      put_be16(r + 7, (uint16_t)tz_hundredths());
      tuya_send(code, r, 9, seq);
      break;
    }
    default: {
      Serial.printf("[TUYA] Unbekannter Code 0x%04X (%u Bytes):", code, len);
      for (int i = 0; i < len && i < 32; i++) Serial.printf(" %02X", d[i]);
      Serial.println();
      break;
    }
  }
}

void tuya_parse(const uint8_t* buf, size_t len) {
  if (len < 33 || ((len - 17) % 16) != 0) {
    Serial.printf("[TUYA] Ungültige Paketlänge %u\n", len);
    return;
  }
  uint8_t flag = buf[0];
  const uint8_t* key;
  if (flag == 4)                     key = login_key;
  else if (flag == 5 && have_session) key = session_key;
  else { Serial.printf("[TUYA] Unbekanntes Security-Flag %d\n", flag); return; }

  uint8_t iv[16];
  memcpy(iv, buf + 1, 16);
  size_t elen = len - 17;
  uint8_t raw[sizeof(rx_buf)];

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, key, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, elen, iv, buf + 17, raw);
  mbedtls_aes_free(&aes);

  uint32_t seq  = get_be32(raw);
  uint16_t code = get_be16(raw + 8);
  uint16_t dlen = get_be16(raw + 10);
  if ((size_t)12 + dlen + 2 > elen) {
    Serial.println("[TUYA] Entschlüsselung ungültig – local_key falsch?");
    strlcpy(ble_state_txt, "local_key falsch?", sizeof(ble_state_txt));
    return;
  }
  uint16_t crc = get_be16(raw + 12 + dlen);
  if (crc != tuya_crc16(raw, 12 + dlen)) {
    Serial.println("[TUYA] CRC falsch – local_key falsch?");
    strlcpy(ble_state_txt, "local_key falsch?", sizeof(ble_state_txt));
    return;
  }
  last_rx_ms = millis();
  tuya_handle(seq, code, raw + 12, dlen);
}

void rx_fragment(const uint8_t* d, size_t len) {
  size_t p = 0;
  uint32_t num;
  if (!get_varint(d, len, p, num)) return;
  if (num == 0) {
    uint32_t total;
    if (!get_varint(d, len, p, total)) return;
    p++;                                  // Protokollversion
    rx_len = 0;
    rx_expected = total;
    rx_next_num = 0;
    if (total > sizeof(rx_buf)) { rx_expected = 0; return; }
  }
  if (rx_expected == 0 || num != rx_next_num || p > len) { rx_expected = 0; return; }
  size_t n = min(len - p, sizeof(rx_buf) - rx_len);
  memcpy(rx_buf + rx_len, d + p, n);
  rx_len += n;
  rx_next_num++;
  if (rx_len >= rx_expected) {
    tuya_parse(rx_buf, rx_expected);
    rx_expected = 0;
  }
}

bool tuya_send_dp(const TuyaCmd& c) {
  uint8_t d[8];
  d[0] = c.dp;
  d[1] = c.type;
  if (c.type == DP_TYPE_VALUE) {
    d[2] = 4;
    put_be32(d + 3, (uint32_t)c.value);
    return tuya_send(TUYA_SEND_DPS, d, 7);
  }
  d[2] = 1;
  d[3] = (uint8_t)c.value;
  return tuya_send(TUYA_SEND_DPS, d, 4);
}

bool queue_cmd(uint8_t dp, uint8_t type, int32_t value) {
  if (!tuya_paired) { Serial.println("[CMD] Generator nicht verbunden"); return false; }
  TuyaCmd c = { dp, type, value };
  return xQueueSend(cmd_q, &c, 0) == pdTRUE;
}

uint8_t eco_delay_valid(int v) {
  return (v == 5 || v == 10 || v == 15 || v == 20) ? (uint8_t)v : 0;
}

// ── Laufzeit-Timer ───────────────────────────────────────────
static const uint16_t TIMER_OPTS[] = { 0, 30, 60, 90, 120, 180, 240, 360, 480 };
volatile int32_t timer_left_min  = -1;     // Restzeit (-1 = Timer inaktiv)
volatile uint16_t run_extend_min = 0;      // Verlaengerung fuer aktuellen Lauf
volatile bool    run_by_gateway  = false;  // aktueller Lauf wurde ueber Gateway gestartet

String timer_label(uint16_t m) {
  if (m == 0) return "Aus";
  if (m < 60) return String(m) + " min";
  if (m % 60) return String(m / 60) + ",5 h";
  return String(m / 60) + " h";
}
bool timer_valid(int m) {
  for (uint16_t o : TIMER_OPTS) if (o == m) return true;
  return false;
}
bool set_max_run(int m, const char* src) {
  if (!timer_valid(m)) return false;
  cfg.max_run_min = m;
  prefs.begin("mxr4000", false);
  prefs.putUShort("max_run", m);
  prefs.end();
  log_event("%s: Laufzeit-Timer %s", src, timer_label(m).c_str());
  return true;
}
bool timer_extend(uint16_t m, const char* src) {
  if (timer_left_min < 0) return false;
  run_extend_min += m;
  log_event("%s: Timer +%u min", src, m);
  return true;
}

bool set_eco_delay(int v) {
  uint8_t d = eco_delay_valid(v);
  if (!d) return false;
  cfg.eco_delay = d;
  prefs.begin("mxr4000", false);
  prefs.putUChar("eco_dly", d);
  prefs.end();
  Serial.printf("[CMD] Auto-ECO Verzögerung %d s\n", d);
  return true;
}

// Zentrale Befehlsfunktion fuer MQTT und Web
bool gen_command(const char* what, bool on, const char* src) {
  if (!strcmp(what, "generator")) {
    if (on && !cfg.allow_start) {
      log_event("%s: Start abgelehnt (Fernstart gesperrt)", src);
      return false;
    }
    log_event("%s: Generator %s", src, on ? "START" : "STOP");
    if (on) { run_by_gateway = true; run_extend_min = 0; }
    return queue_cmd(DP_SWITCH, DP_TYPE_BOOL, on ? 1 : 0);
  }
  if (!strcmp(what, "eco")) {
    log_event("%s: ECO %s", src, on ? "EIN" : "AUS");
    return queue_cmd(DP_ECO, DP_TYPE_BOOL, on ? 1 : 0);
  }
  if (!strcmp(what, "auto_eco")) {
    cfg.auto_eco = on;
    prefs.begin("mxr4000", false);
    prefs.putBool("auto_eco", on);
    prefs.end();
    log_event("%s: Auto-ECO %s", src, on ? "an" : "aus");
    return true;
  }
  if (!strcmp(what, "ble")) {
    ble_enabled = on;
    log_event("%s: BLE %s", src, on ? "aktiviert" : "deaktiviert");
    return true;
  }
  return false;
}

// ============================================================
//  BLE Callbacks
// ============================================================
void notify_cb(NimBLERemoteCharacteristic* chr, uint8_t* data, size_t len, bool is_notify) {
  Frag f;
  f.len = (uint8_t)min(len, sizeof(f.d));
  memcpy(f.d, data, f.len);
  xQueueSend(frag_q, &f, 0);
}

class ClientCB : public NimBLEClientCallbacks {
  void onConnect(NimBLEClient* c) {
    Serial.println("[BLE] Verbunden");
  }
  void onDisconnect(NimBLEClient* c, int reason) {
    log_event("BLE getrennt (Grund 0x%X)", reason);
  }
};
ClientCB client_cb;

bool ble_connect_and_start() {
  tuya_paired  = false;
  have_session = false;
  rx_expected  = 0;
  tuya_seq     = 1;
  ble_wr = ble_nt = nullptr;
  xQueueReset(frag_q);
  xQueueReset(cmd_q);
  tuya_init_keys();

  strlcpy(ble_state_txt, "Verbinde...", sizeof(ble_state_txt));
  Serial.printf("[BLE] Verbinde mit %s ...\n", cfg.ble_mac);
  NimBLEAddress addr(std::string(cfg.ble_mac), BLE_ADDR_PUBLIC);
  if (!ble_client->connect(addr)) {
    Serial.println("[BLE] Verbindung fehlgeschlagen (Generator aus/außer Reichweite/App verbunden?)");
    strlcpy(ble_state_txt, "Nicht erreichbar", sizeof(ble_state_txt));
    return false;
  }
  NimBLERemoteService* svc = ble_client->getService(NimBLEUUID(TUYA_SERVICE_UUID));
  if (svc) {
    ble_wr = svc->getCharacteristic(NimBLEUUID(TUYA_WRITE_UUID));
    ble_nt = svc->getCharacteristic(NimBLEUUID(TUYA_NOTIFY_UUID));
  }
  if (!ble_wr || !ble_nt) {
    Serial.println("[BLE] Tuya-Service nicht gefunden");
    strlcpy(ble_state_txt, "Service fehlt", sizeof(ble_state_txt));
    ble_client->disconnect();
    return false;
  }
  if (!ble_nt->subscribe(true, notify_cb)) {
    Serial.println("[BLE] Notify-Abo fehlgeschlagen");
    ble_client->disconnect();
    return false;
  }
  ble_connected = true;
  last_rx_ms    = millis();
  strlcpy(ble_state_txt, "Login...", sizeof(ble_state_txt));
  tuya_send(TUYA_DEVICE_INFO, nullptr, 0);
  return true;
}

// ============================================================
//  BLE Task (Core 1)
// ============================================================
void ble_task(void*) {
  NimBLEDevice::init("");
  NimBLEDevice::setMTU(23);
  ble_client = NimBLEDevice::createClient();
  ble_client->setClientCallbacks(&client_cb, false);
  ble_client->setConnectTimeout(10000);     // ms (NimBLE 2.x)
  Serial.println("[BLE] Task gestartet");
  esp_task_wdt_add(NULL);

  uint32_t last_attempt = 0, connect_ms = 0, last_rssi_ms = 0, status_req_ms = 0;
  uint32_t ble_off_since = 0;
  uint8_t  fails = 0;
  last_paired_ms = millis();

  while (true) {
    esp_task_wdt_reset();

    // "BLE trennen" (Handy-App) endet automatisch nach 30 min
    if (!ble_enabled && cfg.ble_autostart) {
      if (!ble_off_since) ble_off_since = millis();
      if (millis() - ble_off_since > BLE_OFF_MAX_MS) {
        log_event("BLE nach 30 min automatisch wieder aktiviert");
        ble_enabled = true;
      }
    } else {
      ble_off_since = 0;
    }

    bool want = ble_enabled && ble_configured();
    if (tuya_paired || !want) last_paired_ms = millis();

    // Generator lange nicht erreichbar -> kompletter Neustart (setzt BLE-Stack zurueck)
    if (millis() - last_paired_ms > BLE_LOST_REBOOT_MS) {
      log_event("Generator 2 h nicht erreichbar – Neustart");
      delay(500);
      ESP.restart();
    }

    if (!want) {
      if (ble_client->isConnected()) ble_client->disconnect();
      ble_connected = false;
      tuya_paired   = false;
      ble_wr = ble_nt = nullptr;
      strlcpy(ble_state_txt, ble_configured() ? "Deaktiviert" : "Nicht konfiguriert",
              sizeof(ble_state_txt));
      vTaskDelay(pdMS_TO_TICKS(500));
      continue;
    }

    if (!ble_client->isConnected()) {
      if (ble_connected) {
        ble_connected = false;
        tuya_paired   = false;
        ble_wr = ble_nt = nullptr;
        strlcpy(ble_state_txt, "Getrennt", sizeof(ble_state_txt));
      }
      uint32_t backoff = min(5000UL * (fails + 1), 60000UL);
      if (last_attempt == 0 || millis() - last_attempt >= backoff) {
        last_attempt = millis();
        if (ble_connect_and_start()) { fails = 0; connect_ms = millis(); status_req_ms = millis(); }
        else { ble_fail_count++; if (fails < 11) fails++; }
      }
      vTaskDelay(pdMS_TO_TICKS(200));
      continue;
    }

    // Empfangene Fragmente verarbeiten
    Frag f;
    while (xQueueReceive(frag_q, &f, 0) == pdTRUE) rx_fragment(f.d, f.len);

    // Befehle senden
    if (tuya_paired) {
      TuyaCmd c;
      while (xQueueReceive(cmd_q, &c, 0) == pdTRUE) tuya_send_dp(c);
    }

    // Handshake-Timeout
    if (!tuya_paired && millis() - connect_ms > 20000) {
      Serial.println("[TUYA] Login-Timeout – trenne");
      ble_client->disconnect();
    }
    // Keine Daten mehr -> Status anfordern, spaeter neu verbinden
    if (tuya_paired && millis() - last_rx_ms > 30000 && millis() - status_req_ms > 30000) {
      status_req_ms = millis();
      tuya_send(TUYA_DEVICE_STATUS, nullptr, 0);
    }
    if (tuya_paired && millis() - last_rx_ms > 120000) {
      Serial.println("[TUYA] Keine Daten seit 2 min – trenne");
      ble_client->disconnect();
    }
    // Auto-ECO: Generator laeuft, ECO aus -> nach eco_delay s einschalten (max. alle 30 s versuchen)
    static uint32_t eco_off_since = 0, last_auto_eco = 0;
    if (tuya_paired && cfg.auto_eco) {
      GenData eg;
      gen_snapshot(eg);
      bool run = (eg.have & HAVE(DP_STATE)) ? eg.state == 1 : ((eg.have & HAVE(DP_SWITCH)) && eg.running);
      if (run && (eg.have & HAVE(DP_ECO)) && !eg.eco) {
        if (!eco_off_since) eco_off_since = millis();
        if (millis() - eco_off_since >= (uint32_t)cfg.eco_delay * 1000 &&
            (last_auto_eco == 0 || millis() - last_auto_eco >= 30000)) {
          last_auto_eco = millis();
          log_event("Auto-ECO: ECO eingeschaltet");
          TuyaCmd c = { DP_ECO, DP_TYPE_BOOL, 1 };
          tuya_send_dp(c);
        }
      } else {
        eco_off_since = 0;
      }
    }
    // Laufzeit-Timer: Laufzeit = max(Generator-DP 103, selbst gemessen)
    static uint32_t run_start_ms = 0, last_timer_stop = 0;
    if (tuya_paired) {
      GenData tg;
      gen_snapshot(tg);
      bool run = (tg.have & HAVE(DP_STATE)) ? tg.state == 1 : ((tg.have & HAVE(DP_SWITCH)) && tg.running);
      if (run) {
        if (!run_start_ms) run_start_ms = millis();
        uint32_t ran = (millis() - run_start_ms) / 60000;
        if ((tg.have & HAVE(DP_RUN_MIN)) && tg.run_min > 0 && (uint32_t)tg.run_min > ran) ran = tg.run_min;
        bool applies = cfg.max_run_min && (cfg.timer_all || run_by_gateway);
        if (applies) {
          uint32_t limit = cfg.max_run_min + run_extend_min;
          timer_left_min = ran >= limit ? 0 : (int32_t)(limit - ran);
          if (ran >= limit && (last_timer_stop == 0 || millis() - last_timer_stop > 60000)) {
            last_timer_stop = millis();
            log_event("Laufzeit-Timer: %u min erreicht – STOP", (unsigned)limit);
            TuyaCmd c = { DP_SWITCH, DP_TYPE_BOOL, 0 };
            tuya_send_dp(c);
          }
        } else {
          timer_left_min = -1;
        }
      } else if (tg.have & (HAVE(DP_STATE) | HAVE(DP_SWITCH))) {
        run_start_ms    = 0;
        last_timer_stop = 0;
        run_extend_min  = 0;
        run_by_gateway  = false;
        timer_left_min  = -1;
      }
    }
    // DP-Liste festlegen: was nach 60 s nicht gemeldet wurde, gibt es nicht
    if (tuya_paired) {
      if (!online_since_ms) online_since_ms = millis();
      if (!dp_list_final && millis() - online_since_ms > 60000) {
        GenData hg;
        gen_snapshot(hg);
        if (hg.have) {
          dp_list_final = true;
          Serial.printf("[TUYA] DP-Liste final: 0x%04X\n", hg.have);
        }
      }
    }
    // RSSI
    if (millis() - last_rssi_ms > 10000) {
      last_rssi_ms = millis();
      ble_rssi = ble_client->getRssi();
    }
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

// ============================================================
//  MQTT
// ============================================================
String tp(const char* id, const char* suffix = "state") {
  return String(cfg.mqtt_topic) + "/" + id + "/" + suffix;
}
String dt(const char* comp, const char* id) {
  return String("homeassistant/") + comp + "/" + cfg.hostname + "/" + id + "/config";
}

bool ble_online() {
  GenData g;
  gen_snapshot(g);
  return tuya_paired && g.have != 0;
}

void publish_ha_discovery() {
  String did = cfg.hostname;
  String dev = "\"device\":{\"identifiers\":[\"" + did + "\"],\"name\":\"" + did + "\","
               "\"model\":\"MXR4000GT\",\"manufacturer\":\"MaXpeedingRods\","
               "\"sw_version\":\"" FW_VERSION "\"}";
  String av_gw  = "\"availability_topic\":\"" + String(cfg.mqtt_topic) + "/status\",";
  String av_gen = "\"availability\":[{\"topic\":\"" + String(cfg.mqtt_topic) + "/status\"},"
                  "{\"topic\":\"" + String(cfg.mqtt_topic) + "/ble/status\"}],"
                  "\"availability_mode\":\"all\",";

  auto head = [&](const char* id, const char* name, bool gen_av) {
    return "{\"name\":\"" + String(name) + "\","
           "\"state_topic\":\"" + tp(id) + "\","
           "\"unique_id\":\"" + did + "_" + id + "\"," + (gen_av ? av_gen : av_gw);
  };

  auto pub_s = [&](const char* id, const char* name, const char* unit,
                   const char* dc, const char* sc, bool gen_av, const char* icon = "") {
    String p = head(id, name, gen_av);
    if (unit && unit[0]) p += "\"unit_of_measurement\":\"" + String(unit) + "\",";
    if (dc && dc[0])     p += "\"device_class\":\"" + String(dc) + "\",";
    if (sc && sc[0])     p += "\"state_class\":\"" + String(sc) + "\",";
    if (icon && icon[0]) p += "\"icon\":\"" + String(icon) + "\",";
    p += dev + "}";
    mqtt.publish(dt("sensor", id).c_str(), p.c_str(), true);
  };

  auto pub_b = [&](const char* id, const char* name, const char* dc, bool gen_av) {
    String p = head(id, name, gen_av);
    if (dc && dc[0]) p += "\"device_class\":\"" + String(dc) + "\",";
    p += dev + "}";
    mqtt.publish(dt("binary_sensor", id).c_str(), p.c_str(), true);
  };

  auto pub_sw = [&](const char* id, const char* name, const char* icon, bool gen_av) {
    String p = head(id, name, gen_av);
    p += "\"command_topic\":\"" + tp(id, "set") + "\",";
    if (icon && icon[0]) p += "\"icon\":\"" + String(icon) + "\",";
    p += dev + "}";
    mqtt.publish(dt("switch", id).c_str(), p.c_str(), true);
  };

  // Generator-Entitaeten nur fuer DPs, die der Generator wirklich meldet
  GenData dg;
  gen_snapshot(dg);
  auto gate = [&](uint32_t mask, const char* comp, const char* id) -> bool {
    if (dg.have & mask) { disc_mask |= mask; return true; }
    if (dp_list_final) mqtt.publish(dt(comp, id).c_str(), "", true);   // aus HA entfernen
    return false;
  };

  if (gate(HAVE(DP_SWITCH), "switch", "generator")) pub_sw("generator", "Generator", "mdi:engine", true);
  if (gate(HAVE(DP_ECO), "switch", "eco")) pub_sw("eco",       "ECO-Modus", "mdi:leaf",   true);
  pub_sw("ble_aktiv", "BLE aktiv", "mdi:bluetooth", false);
  pub_sw("auto_eco",  "Auto-ECO",  "mdi:leaf-circle", false);
  {
    String p = head("auto_eco_delay", "Auto-ECO Verzögerung", false);
    p += "\"command_topic\":\"" + tp("auto_eco_delay", "set") + "\",";
    p += "\"options\":[\"5 s\",\"10 s\",\"15 s\",\"20 s\"],\"icon\":\"mdi:timer-cog\",";
    p += "\"entity_category\":\"config\",";
    p += dev + "}";
    mqtt.publish(dt("select", "auto_eco_delay").c_str(), p.c_str(), true);
  }
  {
    String opts;
    for (uint16_t o : TIMER_OPTS) opts += (opts.length() ? ",\"" : "\"") + timer_label(o) + "\"";
    String p = head("laufzeit_timer", "Laufzeit-Timer", false);
    p += "\"command_topic\":\"" + tp("laufzeit_timer", "set") + "\",";
    p += "\"options\":[" + opts + "],\"icon\":\"mdi:timer-off\",\"entity_category\":\"config\",";
    p += dev + "}";
    mqtt.publish(dt("select", "laufzeit_timer").c_str(), p.c_str(), true);

    p = "{\"name\":\"Timer +30 min\",\"command_topic\":\"" + tp("timer_plus", "set") + "\","
        "\"payload_press\":\"30\",\"icon\":\"mdi:timer-plus\","
        "\"unique_id\":\"" + did + "_timer_plus\"," + av_gen + dev + "}";
    mqtt.publish(dt("button", "timer_plus").c_str(), p.c_str(), true);
  }
  pub_s("timer_rest", "Timer Restzeit", "min", "duration", "", false, "mdi:timer-sand");

  if (gate(HAVE(DP_POWER), "sensor", "leistung")) pub_s("leistung",        "Leistung",          "W",   "power",     "measurement",     true);
  if (gate(HAVE(DP_VOLTAGE), "sensor", "spannung")) pub_s("spannung",        "Spannung",          "V",   "voltage",   "measurement",     true);
  if (gate(HAVE(DP_FREQ), "sensor", "frequenz")) pub_s("frequenz",        "Frequenz",          "Hz",  "frequency", "measurement",     true);
  if (gate(HAVE(DP_RPM), "sensor", "drehzahl")) pub_s("drehzahl",        "Drehzahl",          "rpm", "",          "measurement",     true, "mdi:speedometer");
  if (gate(HAVE(DP_TANK), "sensor", "tank")) pub_s("tank",            "Tankfüllstand",     "%",   "",          "measurement",     true, "mdi:gas-station");
  if (gate(HAVE(DP_RUN_MIN), "sensor", "laufzeit")) pub_s("laufzeit",        "Laufzeit aktuell",  "min", "duration",  "measurement",     true);
  if (gate(HAVE(DP_TOTAL_MIN), "sensor", "laufzeit_gesamt")) pub_s("laufzeit_gesamt", "Laufzeit gesamt",   "min", "duration",  "total_increasing",true);
  if (gate(HAVE(DP_STATE), "sensor", "status")) pub_s("status",          "Status",            "",    "",          "",                true, "mdi:state-machine");
  if (gate(HAVE(DP_FAULT), "sensor", "fehler")) pub_s("fehler",          "Fehler",            "",    "",          "",                true, "mdi:alert-circle");
  if (gate(HAVE(DP_FAULT), "sensor", "fehlercode")) pub_s("fehlercode",      "Fehlercode",        "",    "",          "",                true, "mdi:numeric");
  if (gate(HAVE(DP_BATTERY), "sensor", "batterie")) pub_s("batterie",        "Batterie",          "%",   "battery",   "measurement",     true);
  if (gate(HAVE(DP_CHARGING), "sensor", "ladestatus")) pub_s("ladestatus",      "Ladestatus",        "",    "",          "",                true, "mdi:battery-charging");
  if (gate(HAVE(DP_SN), "sensor", "seriennummer")) pub_s("seriennummer",    "Seriennummer",      "",    "",          "",                true, "mdi:identifier");
  if (gate(HAVE(DP_OIL_ALARM), "binary_sensor", "oelwechsel")) pub_b("oelwechsel",      "Ölwechsel fällig",  "problem", true);

  pub_b("ble",             "BLE Verbindung",    "connectivity", false);
  pub_s("ble_rssi",        "BLE Signal",        "dBm", "signal_strength", "measurement", false);
  pub_s("uptime",          "Uptime",            "s",   "",          "total_increasing", false);
  pub_s("ip",              "IP",                "",    "",          "",                false);
  pub_s("rssi",            "Signalstärke",      "dBm", "signal_strength", "measurement", false);

  Serial.println("[MQTT] HA Discovery publiziert");
}

void publish_data(const GenData& g) {
  char buf[96];
  auto pubi = [&](const char* id, uint32_t mask, int32_t v) {
    if (!(g.have & mask)) return;
    snprintf(buf, sizeof(buf), "%ld", (long)v);
    mqtt.publish(tp(id).c_str(), buf, true);
  };
  auto pubs = [&](const char* id, uint32_t mask, const char* v) {
    if (!(g.have & mask)) return;
    mqtt.publish(tp(id).c_str(), v, true);
  };

  pubs("generator",       HAVE(DP_SWITCH),    g.running ? "ON" : "OFF");
  pubs("eco",             HAVE(DP_ECO),       g.eco ? "ON" : "OFF");
  pubi("leistung",        HAVE(DP_POWER),     g.power_w);
  pubi("spannung",        HAVE(DP_VOLTAGE),   g.voltage);
  pubi("frequenz",        HAVE(DP_FREQ),      g.freq);
  pubi("drehzahl",        HAVE(DP_RPM),       g.rpm);
  pubi("tank",            HAVE(DP_TANK),      g.tank);
  pubi("laufzeit",        HAVE(DP_RUN_MIN),   g.run_min);
  pubi("laufzeit_gesamt", HAVE(DP_TOTAL_MIN), g.total_min);
  pubs("status",          HAVE(DP_STATE),     state_txt(g.state));
  pubs("fehler",          HAVE(DP_FAULT),     fault_txt(g.fault).c_str());
  pubi("fehlercode",      HAVE(DP_FAULT),     (int32_t)g.fault);
  pubi("batterie",        HAVE(DP_BATTERY),   g.battery);
  pubs("ladestatus",      HAVE(DP_CHARGING),  charging_txt(g.charging));
  pubs("seriennummer",    HAVE(DP_SN),        g.sn);
  pubs("oelwechsel",      HAVE(DP_OIL_ALARM), g.oil_alarm ? "ON" : "OFF");
  Serial.println("[MQTT] Generatordaten publiziert");
}

void publish_system() {
  char buf[32];
  mqtt.publish(tp("ble_aktiv").c_str(), ble_enabled ? "ON" : "OFF", true);
  mqtt.publish(tp("auto_eco").c_str(), cfg.auto_eco ? "ON" : "OFF", true);
  mqtt.publish(tp("auto_eco_delay").c_str(), (String(cfg.eco_delay) + " s").c_str(), true);
  mqtt.publish(tp("laufzeit_timer").c_str(), timer_label(cfg.max_run_min).c_str(), true);
  mqtt.publish(tp("timer_rest").c_str(), timer_left_min >= 0 ? String(timer_left_min).c_str() : "0", true);
  mqtt.publish(tp("ble").c_str(), tuya_paired ? "ON" : "OFF", true);
  snprintf(buf, sizeof(buf), "%d", ble_rssi);
  if (ble_connected) mqtt.publish(tp("ble_rssi").c_str(), buf);
  snprintf(buf, sizeof(buf), "%lu", millis() / 1000);
  mqtt.publish(tp("uptime").c_str(), buf);
  mqtt.publish(tp("ip").c_str(), WiFi.localIP().toString().c_str());
  snprintf(buf, sizeof(buf), "%d", WiFi.RSSI());
  mqtt.publish(tp("rssi").c_str(), buf);
}

void mqtt_callback(char* topic, byte* payload, unsigned int len) {
  char v[16];
  unsigned int n = min(len, (unsigned int)sizeof(v) - 1);
  memcpy(v, payload, n);
  v[n] = 0;
  String t(topic);
  Serial.printf("[MQTT] Befehl %s = '%s'\n", topic, v);
  if (len == 0) return;   // leere Nachricht = Loeschen eines retained Befehls

  // Direkt nach dem Verbinden liefert der Broker gespeicherte (retained) Befehle aus –
  // die duerfen nichts schalten.
  if (millis() - mqtt_connected_ms < 5000) {
    log_event("MQTT: Befehl ignoriert (retained?) %s=%s", t.substring(t.lastIndexOf('/', t.length() - 5) + 1).c_str(), v);
    return;
  }
  if (t == tp("auto_eco_delay", "set")) {
    set_eco_delay(atoi(v));
  } else if (t == tp("laufzeit_timer", "set")) {
    for (uint16_t o : TIMER_OPTS) if (timer_label(o) == String(v)) set_max_run(o, "MQTT");
  } else if (t == tp("timer_plus", "set")) {
    timer_extend(atoi(v) > 0 ? atoi(v) : 30, "MQTT");
  } else {
    bool on  = !strcasecmp(v, "ON")  || !strcmp(v, "1") || !strcasecmp(v, "true");
    bool off = !strcasecmp(v, "OFF") || !strcmp(v, "0") || !strcasecmp(v, "false");
    if (!on && !off) { log_event("MQTT: unbekannte Payload '%s' ignoriert", v); return; }
    if      (t == tp("generator", "set")) gen_command("generator", on, "MQTT");
    else if (t == tp("eco", "set"))       gen_command("eco", on, "MQTT");
    else if (t == tp("ble_aktiv", "set")) gen_command("ble", on, "MQTT");
    else if (t == tp("auto_eco", "set"))  gen_command("auto_eco", on, "MQTT");
  }

  // Aktuellen Zustand sofort zuruecksenden (HA springt bei gesperrtem Start zurueck)
  GenData g;
  gen_snapshot(g);
  if (g.have & HAVE(DP_SWITCH)) mqtt.publish(tp("generator").c_str(), g.running ? "ON" : "OFF", true);
  if (g.have & HAVE(DP_ECO))    mqtt.publish(tp("eco").c_str(), g.eco ? "ON" : "OFF", true);
  mqtt.publish(tp("ble_aktiv").c_str(), ble_enabled ? "ON" : "OFF", true);
  mqtt.publish(tp("auto_eco").c_str(), cfg.auto_eco ? "ON" : "OFF", true);
  mqtt.publish(tp("auto_eco_delay").c_str(), (String(cfg.eco_delay) + " s").c_str(), true);
  mqtt.publish(tp("laufzeit_timer").c_str(), timer_label(cfg.max_run_min).c_str(), true);
  mqtt.publish(tp("timer_rest").c_str(), timer_left_min >= 0 ? String(timer_left_min).c_str() : "0", true);
}

bool mqtt_connect() {
  if (!cfg.mqtt_host[0]) return false;
  mqtt.setServer(cfg.mqtt_host, cfg.mqtt_port);
  mqtt.setBufferSize(1024);
  mqtt.setCallback(mqtt_callback);
  String lwt = String(cfg.mqtt_topic) + "/status";
  bool ok = cfg.mqtt_user[0]
    ? mqtt.connect(cfg.hostname, cfg.mqtt_user, cfg.mqtt_pass, lwt.c_str(), 0, true, "offline")
    : mqtt.connect(cfg.hostname, nullptr, nullptr, lwt.c_str(), 0, true, "offline");
  if (ok) {
    mqtt.publish(lwt.c_str(), "online", true);
    // Evtl. gespeicherte (retained) Befehle am Broker loeschen, dann abonnieren
    const char* cmds[] = { "generator", "eco", "ble_aktiv", "auto_eco", "auto_eco_delay",
                           "laufzeit_timer", "timer_plus" };
    for (const char* c : cmds) mqtt.publish(tp(c, "set").c_str(), "", true);
    mqtt_connected_ms = millis();
    mqtt.subscribe(tp("generator", "set").c_str());
    mqtt.subscribe(tp("eco", "set").c_str());
    mqtt.subscribe(tp("ble_aktiv", "set").c_str());
    mqtt.subscribe(tp("auto_eco", "set").c_str());
    mqtt.subscribe(tp("auto_eco_delay", "set").c_str());
    mqtt.subscribe(tp("laufzeit_timer", "set").c_str());
    mqtt.subscribe(tp("timer_plus", "set").c_str());
    ha_discovery_done = false;
    log_event("MQTT verbunden");
  } else {
    Serial.printf("[MQTT] Fehler: %d\n", mqtt.state());
  }
  return ok;
}

// ============================================================
//  WiFi
// ============================================================
void wifi_start_ap() {
  ap_mode = true;
  WiFi.mode(WIFI_AP);
  const char* ssid = "MXR4000";
  WiFi.softAP(ssid);
  Serial.printf("[WiFi] AP: %s  IP: %s\n", ssid, WiFi.softAPIP().toString().c_str());
}

// Ein WLAN versuchen (blockierend, max. timeout_ms)
bool wifi_try(const char* ssid, const char* pass, uint32_t timeout_ms) {
  if (!ssid || !ssid[0]) return false;
  WiFi.disconnect();
  delay(200);
  WiFi.mode(WIFI_STA);
  WiFi.setHostname(cfg.hostname);
  WiFi.begin(ssid, pass);
  Serial.printf("[WiFi] Verbinde mit '%s'", ssid);
  uint32_t t = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t < timeout_ms) { delay(500); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

// Reihenfolge: WLAN aus Config -> FIXED_SSID -> FIXED_SSID2
bool wifi_try_all() {
  if (strlen(cfg.ssid) && wifi_try(cfg.ssid, cfg.wifi_pass, 12000)) return true;
  if (strcmp(cfg.ssid, FIXED_SSID)  && wifi_try(FIXED_SSID,  FIXED_PASS,  12000)) return true;
  if (strcmp(cfg.ssid, FIXED_SSID2) && wifi_try(FIXED_SSID2, FIXED_PASS2, 12000)) return true;
  return false;
}

void wifi_connect_sta() {
  if (wifi_try_all()) {
    wifi_connected = true; ap_mode = false;
    Serial.printf("[WiFi] IP: %s\n", WiFi.localIP().toString().c_str());
    MDNS.begin(cfg.hostname);
  } else {
    Serial.println("[WiFi] Fehlgeschlagen -> AP");
    wifi_start_ap();
  }
}

// ============================================================
//  Web-Interface
// ============================================================
String WH(const char* title) {
  return String("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>MXR4000GT</title><style>"
    "body{font-family:sans-serif;margin:0;background:#1a1a2e;color:#e0e0e0}"
    ".w{max-width:900px;margin:0 auto;padding:20px}"
    "h1{color:#0f9}h2{color:#0cf;border-bottom:1px solid #444;padding-bottom:4px}"
    "nav{background:#16213e;padding:10px 20px;display:flex;gap:12px;flex-wrap:wrap}"
    "nav a{color:#0cf;text-decoration:none;padding:5px 12px;border-radius:5px}"
    "nav a:hover{background:#0cf;color:#000}"
    "table{width:100%;border-collapse:collapse;margin:8px 0}"
    "td,th{padding:7px 11px;border:1px solid #333;text-align:left}"
    "th{background:#16213e;color:#0cf}tr:hover{background:#1e2a4a}"
    "input{background:#16213e;color:#e0e0e0;border:1px solid #444;"
    "padding:6px 10px;border-radius:4px;width:100%;box-sizing:border-box}"
    "input[type=checkbox]{width:auto}"
    "select{background:#16213e;color:#e0e0e0;border:1px solid #444;padding:6px 10px;border-radius:4px}"
    ".sel{padding:2px 6px;margin-left:8px;font-size:.85em;vertical-align:middle}"
    "input[type=submit],button{background:#0cf;color:#000;border:none;"
    "padding:10px 20px;border-radius:5px;cursor:pointer;font-weight:bold;width:auto}"
    "button.red{background:#f55;color:#fff}button.grn{background:#0f9}"
    "button:disabled{background:#333;color:#777;cursor:not-allowed}"
    ".card{background:#16213e;border-radius:8px;padding:15px;margin:10px 0}"
    ".row{display:flex;gap:10px;align-items:center;margin:7px 0}"
    ".row label{min-width:190px;color:#aaa}"
    ".btns{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0}"
    ".on{background:#0f9;color:#000}.off{background:#f55;color:#fff}"
    ".badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.85em}"
    ".hdr{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:-6px 0 6px}"
    ".pill{padding:6px 16px;border-radius:20px;font-weight:bold;background:#333;color:#ccc}"
    ".pill.sm{font-size:.8em;padding:4px 12px;font-weight:normal}"
    ".p-run{background:#0f9;color:#000}.p-stop{background:#3a4466;color:#e0e0e0}"
    ".p-err{background:#f55;color:#fff}.p-off{background:#333;color:#999}"
    ".live{margin-left:auto;color:#888;font-size:.85em;display:flex;align-items:center;gap:6px}"
    ".live i{width:9px;height:9px;border-radius:50%;background:#555;display:inline-block}"
    ".live i.on{background:#0f9;box-shadow:0 0 8px #0f9}"
    ".gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;transition:opacity .5s}"
    ".gauges .card{margin:0}.gc{text-align:center}.gc h3{margin:0 0 4px;color:#aaa;font-weight:normal;font-size:.95em}"
    ".gauge{width:100%;max-width:260px}.tank{width:100%;max-width:150px;height:170px}"
    ".g-bg{fill:none;stroke:#2a3558;stroke-width:16}"
    ".g-val{fill:none;stroke:#0f9;stroke-width:16;stroke-dasharray:251.33;stroke-dashoffset:251.33;"
    "transition:stroke-dashoffset .8s ease,stroke .8s}"
    ".g-pk{stroke:#fff;stroke-width:2.5;opacity:.7}"
    ".g-num{fill:#fff;font-size:34px;font-weight:bold;text-anchor:middle}"
    ".g-unit{fill:#888;font-size:12px;text-anchor:middle}"
    ".g-lim{fill:#666;font-size:11px;text-anchor:middle}"
    ".t-fill{fill:#0f9;transform-box:fill-box;transform-origin:bottom;transform:scaleY(0);"
    "transition:transform 1s ease,fill .8s}"
    ".t-wall{fill:none;stroke:#0cf;stroke-width:3}.t-tick line{stroke:#0cf;stroke-width:2}"
    ".t-lbl{fill:#888;font-size:12px}"
    ".t-num{fill:#fff;font-size:22px;font-weight:bold;text-anchor:middle;paint-order:stroke;stroke:#000;stroke-width:3px}"
    ".sub{color:#888;font-size:.85em;margin-top:4px}"
    ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:10px 0}"
    ".tile{background:#16213e;border-radius:8px;padding:12px 14px}.tile.wide{grid-column:span 2}"
    ".tile .l{color:#888;font-size:.8em;text-transform:uppercase;letter-spacing:.04em}"
    ".tile .v{font-size:1.45em;font-weight:bold;color:#0cf;margin-top:4px}"
    ".tile .s{color:#888;font-size:.8em;margin-top:2px}.c-g{color:#0f9!important}.c-r{color:#f55!important}"
    ".qa{display:flex;flex-wrap:wrap;gap:14px 34px;align-items:center}"
    ".swrow{display:flex;align-items:center;gap:12px}.swt{font-weight:bold;font-size:1.15em}.swt.sm{font-size:1em}"
    ".sw{position:relative;display:inline-block;width:50px;height:28px;flex:none}.sw.big{width:64px;height:34px}"
    ".sw input{opacity:0;width:0;height:0}"
    ".sl{position:absolute;inset:0;background:#3a4466;border-radius:34px;cursor:pointer;transition:.3s}"
    ".sl:before{content:'';position:absolute;height:22px;width:22px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.3s}"
    ".sw.big .sl:before{height:28px;width:28px}"
    ".sw input:checked+.sl{background:#0f9}.sw input:checked+.sl:before{transform:translateX(22px)}"
    ".sw.big input:checked+.sl:before{transform:translateX(30px)}"
    ".sw input:disabled+.sl{opacity:.4;cursor:not-allowed}"
    ".tmr{font-size:1.6em;width:50px;text-align:center;opacity:.45}.tmr.act{opacity:1}"
    "button.sm{padding:3px 10px;font-size:.8em;margin-left:6px;vertical-align:middle}"
    "</style></head><body>"
    "<nav><strong style='color:#0f9'>MXR4000GT Gateway</strong>"
    "<a href='/'>Status</a><a href='/ctrl'>Steuerung</a><a href='/config'>Config</a>"
    "<a href='/update'>Update</a><a href='/dp'>Diagnose</a></nav>"
    "<div class='w'><h1>") + title + "</h1>";
}
String WF() { return "</div></body></html>"; }

String badge(bool on, const char* t_on, const char* t_off) {
  return String("<span class='badge ") + (on ? "on'>" : "off'>") + (on ? t_on : t_off) + "</span>";
}

// ============================================================
//  Dashboard (Status-Seite) – Live-Update per /api alle 2s
// ============================================================
#define POWER_MAX_W 3500

static const char DASH_HTML[] PROGMEM = R"HTML(
<div class='hdr'>
  <span id='st' class='pill'>---</span>
  <span id='bl' class='pill sm'>BLE ---</span>
  <span class='live'><i id='dot'></i><span id='age'>verbinde...</span></span>
</div>
<div id='dash' class='gauges'>
  <div class='card gc'><h3>Leistung</h3>
    <svg viewBox='0 0 200 125' class='gauge'>
      <path d='M20,105 A80,80 0 0 1 180,105' class='g-bg'/>
      <path id='gp' d='M20,105 A80,80 0 0 1 180,105' class='g-val'/>
      <g id='gpk'></g>
      <text x='100' y='88' class='g-num' id='gpt'>--</text>
      <text x='100' y='106' class='g-unit'>Watt</text>
      <text x='20' y='122' class='g-lim'>0</text><text x='180' y='122' class='g-lim'>%MAX%</text>
    </svg>
    <div class='sub' id='gpl'>Auslastung --</div>
  </div>
  <div class='card gc'><h3>Tank</h3>
    <svg viewBox='0 0 200 125' class='gauge'>
      <path d='M20,105 A80,80 0 0 1 180,105' class='g-bg'/>
      <path id='gt' d='M20,105 A80,80 0 0 1 180,105' class='g-val'/>
      <text x='100' y='88' class='g-num' id='gtt'>--</text>
      <text x='100' y='106' class='g-unit'>Prozent</text>
      <text x='20' y='122' class='g-lim'>E</text><text x='180' y='122' class='g-lim'>F</text>
    </svg>
    <div class='sub' id='gtl'>&nbsp;</div>
  </div>
  <div class='card gc'><h3>Kraftstoff</h3>
    <svg viewBox='0 0 140 150' class='tank'>
      <defs><clipPath id='tc'><rect x='30' y='8' width='72' height='134' rx='12'/></clipPath>
      <linearGradient id='tg' x1='0' x2='1'><stop offset='0' stop-opacity='.75' stop-color='#000'/>
      <stop offset='.35' stop-opacity='0' stop-color='#000'/><stop offset='1' stop-opacity='.45' stop-color='#000'/></linearGradient></defs>
      <g clip-path='url(#tc)'>
        <rect x='30' y='8' width='72' height='134' fill='#0e1730'/>
        <rect id='tf' x='30' y='8' width='72' height='134' class='t-fill'/>
        <rect x='30' y='8' width='72' height='134' fill='url(#tg)'/>
      </g>
      <rect x='30' y='8' width='72' height='134' rx='12' class='t-wall'/>
      <g class='t-tick'>
        <line x1='102' y1='41.5' x2='112' y2='41.5'/><line x1='102' y1='75' x2='116' y2='75'/>
        <line x1='102' y1='108.5' x2='112' y2='108.5'/>
      </g>
      <text x='121' y='15' class='t-lbl'>F</text><text x='121' y='79' class='t-lbl'>½</text>
      <text x='121' y='143' class='t-lbl'>E</text>
      <text x='66' y='81' class='t-num' id='tft'>--</text>
    </svg>
  </div>
</div>
<div class='tiles'>
  <div class='tile'><div class='l'>Spannung</div><div class='v' id='v'>--</div></div>
  <div class='tile'><div class='l'>Frequenz</div><div class='v' id='hz'>--</div></div>
  <div class='tile'><div class='l'>Drehzahl</div><div class='v' id='rpm'>--</div></div>
  <div class='tile'><div class='l'>Laufzeit aktuell</div><div class='v' id='rm'>--</div></div>
  <div class='tile'><div class='l'>Betriebsstunden</div><div class='v' id='tm'>--</div></div>
  <div class='tile'><div class='l'>ECO-Modus</div><div class='v' id='eco'>--</div></div>
  <div class='tile'><div class='l'>Batterie</div><div class='v' id='bat'>--</div><div class='s' id='chg'></div></div>
  <div class='tile'><div class='l'>Ölwechsel</div><div class='v' id='oil'>--</div></div>
  <div class='tile wide'><div class='l'>Fehler</div><div class='v' id='ft'>--</div><div class='s' id='fc'></div></div>
</div>
<div class='card'><h2>Schnellzugriff</h2>
<div class='qa'>
  <div class='btns'>
    <button id='bstart' class='grn' onclick="cmd('start')">Start</button>
    <button id='bstop' class='red' onclick="cmd('stop')">Stop</button>
  </div>
  <div class='swrow'>
    <label class='sw big'><input type='checkbox' id='ecosw' onchange="ecoSet(this.checked)"><span class='sl'></span></label>
    <div><div class='swt' id='ecot'>ECO-Modus --</div><div class='sub' id='ecos'>&nbsp;</div></div>
  </div>
  <div class='swrow'>
    <label class='sw'><input type='checkbox' id='aesw' onchange="cmd(this.checked?'aeco_on':'aeco_off')"><span class='sl'></span></label>
    <div><div class='swt sm'>Auto-ECO
      <select id='aed' class='sel' onchange="edHold=Date.now()+3000;cmd('edly'+this.value)">
        <option value='5'>5 s</option><option value='10'>10 s</option><option value='15'>15 s</option><option value='20'>20 s</option>
      </select></div>
      <div class='sub' id='aes'>Laufender Generator wird automatisch auf ECO gestellt</div></div>
  </div>
  <div class='swrow'>
    <span class='tmr' id='tico'>⏱</span>
    <div><div class='swt sm'>Laufzeit-Timer
      <select id='tmx' class='sel' onchange="tmHold=Date.now()+3000;cmd('tmax'+this.value)">%TOPTS%</select>
      <button id='tplus' class='sm' onclick="cmd('tplus')">+30 min</button></div>
      <div class='sub' id='tls'>&nbsp;</div></div>
  </div>
</div><div class='sub' id='cmsg'></div></div>
<script>
const L=251.33,$=i=>document.getElementById(i),MAX=%MAX%,AS=%AS%;let D=null,last=0,peak=0;
function arc(id,f,col){const e=$(id);f=Math.max(0,Math.min(1,f));e.style.strokeDashoffset=L*(1-f);e.style.stroke=col;}
function cP(f){return f<.8?'#0f9':f<.92?'#f90':'#f55'}
function cT(p){return p<15?'#f55':p<30?'#f90':'#0f9'}
function n(x,u){return x==null?'--':x+(u||'')}
function pkMark(f){const a=Math.PI*(1-f),x1=100+70*Math.cos(a),y1=105-70*Math.sin(a),x2=100+92*Math.cos(a),y2=105-92*Math.sin(a);
 $('gpk').innerHTML=f>0?`<line x1='${x1}' y1='${y1}' x2='${x2}' y2='${y2}' class='g-pk'/>`:'';}
function upd(d){D=d;last=Date.now();const ok=d.ok;$('dash').style.opacity=ok?1:.45;
 const st=$('st');st.textContent=ok&&d.stt?d.stt:'Keine Verbindung';
 st.className='pill '+(!ok?'p-off':d.st==1?'p-run':d.st==2?'p-err':'p-stop');
 const bl=$('bl');bl.textContent='BLE '+d.ble+(d.rssi&&ok?' · '+d.rssi+' dBm':'');bl.className='pill sm '+(ok?'p-run':'p-off');
 if(d.p!=null){const f=d.p/MAX;arc('gp',f,cP(f));$('gpt').textContent=d.p;$('gpl').textContent='Auslastung '+Math.round(f*100)+' %'+(peak?' · Spitze '+peak+' W':'');
  if(d.p>peak){peak=d.p;} pkMark(Math.min(1,peak/MAX));} else {arc('gp',0,'#0f9');$('gpt').textContent='--';}
 if(d.tank!=null){const c=cT(d.tank);arc('gt',d.tank/100,c);$('gtt').textContent=d.tank;
  const tf=$('tf');tf.style.transform='scaleY('+d.tank/100+')';tf.style.fill=c;$('tft').textContent=d.tank+'%';
  $('gtl').textContent=d.tank<15?'⚠ Reserve – bitte tanken':d.tank<30?'Bald tanken':'Füllstand OK';}
 else {arc('gt',0,'#0f9');$('gtt').textContent='--';$('tft').textContent='--';$('tf').style.transform='scaleY(0)';}
 $('v').textContent=n(d.v,' V');$('hz').textContent=n(d.hz,' Hz');$('rpm').textContent=n(d.rpm,' rpm');
 $('rm').textContent=d.rm==null?'--':(d.rm>=60?Math.floor(d.rm/60)+' h '+(d.rm%60)+' min':d.rm+' min');
 $('tm').textContent=d.tm==null?'--':(d.tm/60).toFixed(1)+' h';
 const eco=$('eco');eco.textContent=d.eco==null?'--':d.eco?'EIN':'AUS';eco.className='v '+(d.eco?'c-g':'');
 $('bat').textContent=n(d.bat,' %');$('chg').textContent=d.chg||'';
 const oil=$('oil');oil.textContent=d.oil==null?'--':d.oil?'Fällig':'OK';oil.className='v '+(d.oil?'c-r':'c-g');
 const ft=$('ft');ft.textContent=d.ft||'--';ft.className='v '+(d.f?'c-r':'c-g');$('fc').textContent=d.f?'Code '+d.f:'';
 const up=d.up,dd=Math.floor(up/86400),hh=Math.floor(up%86400/3600),mm=Math.floor(up%3600/60);
 $('up').textContent=(dd?dd+' d ':'')+(dd||hh?hh+' h ':'')+mm+' min '+(up%60)+' s';
 if($('wr'))$('wr').textContent=d.wr+' dBm';$('hp').textContent=d.hp+' kB';
 $('mq').innerHTML="<span class='badge "+(d.mq?"on'>Verbunden":"off'>Getrennt")+"</span>";
 for(const [id,k] of [['v','v'],['hz','hz'],['rpm','rpm'],['rm','rm'],['tm','tm'],['eco','eco'],['bat','bat'],['oil','oil'],['ft','f']])
  $(id).parentElement.style.display=(d.cl&&d[k]==null)?'none':'';
 $('bstart').disabled=!ok||!AS;$('bstart').title=AS?'':'Fernstart in Config gesperrt';$('bstop').disabled=!ok;
 const es=$('ecosw');es.disabled=!ok||d.eco==null;
 if(Date.now()>ecoHold){es.checked=!!d.eco;}
 $('ecot').textContent='ECO-Modus '+(d.eco==null?'--':d.eco?'EIN':'AUS');$('ecot').className='swt '+(d.eco?'c-g':'');
 $('ecos').textContent=Date.now()<=ecoHold?'Schalte...':d.eco?'Spritsparend, Drehzahl passt sich der Last an':
   (d.st==1&&d.ae?'Auto-ECO schaltet gleich ein':'Volle Drehzahl');
 if(Date.now()>aeHold)$('aesw').checked=!!d.ae;
 if(Date.now()>edHold&&d.ed)$('aed').value=d.ed;
 $('aes').textContent='Laufender Generator wird nach '+$('aed').value+' s auf ECO gestellt';
 if($('bc'))$('bc').textContent=d.bc+' OK / '+d.bf+' fehlgeschlagen';
 if(Date.now()>tmHold)$('tmx').value=d.tmax;
 const tl=d.tl,fm=m=>m>=60?Math.floor(m/60)+' h '+(m%60)+' min':m+' min';
 $('tls').textContent=!d.tmax?'Aus – Generator läuft unbegrenzt':tl!=null?'Abschaltung in '+fm(tl):
   (d.st==1&&!d.tall?'Nicht aktiv (manuell gestartet)':'Stoppt den Generator nach '+fm(d.tmax)+' Laufzeit');
 $('tls').className='sub'+(tl!=null&&tl<=10?' c-r':'');$('tico').className='tmr'+(tl!=null?' act':'');
 $('tplus').disabled=tl==null;}
let ecoHold=0,aeHold=0,edHold=0,tmHold=0;
function ecoSet(on){ecoHold=Date.now()+5000;cmd(on?'eco_on':'eco_off');}
async function poll(){try{const r=await fetch('/api',{cache:'no-store'});upd(await r.json());}catch(e){}setTimeout(poll,2000);}
setInterval(()=>{const a=last?Math.round((Date.now()-last)/1000):-1;$('age').textContent=a<0?'verbinde...':a<5?'live':'vor '+a+' s';
 $('dot').className=a>=0&&a<5?'on':'';},1000);
async function cmd(a){if(a=='start'&&!confirm('Generator wirklich starten?'))return;if(a.startsWith('aeco'))aeHold=Date.now()+3000;$('cmsg').textContent='Sende...';
 try{await fetch('/ctrl',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'a='+a});$('cmsg').textContent='Befehl gesendet: '+a;}
 catch(e){$('cmsg').textContent='Fehler beim Senden';}}
poll();
</script>
)HTML";

String json_esc(const char* s) {
  String o;
  for (; *s; s++) {
    if (*s == '"' || *s == '\\') { o += '\\'; o += *s; }
    else if ((uint8_t)*s < 0x20) o += ' ';
    else o += *s;
  }
  return o;
}

void handle_api() {
  GenData g;
  gen_snapshot(g);
  bool ok = tuya_paired && g.have;
  auto num = [&](uint32_t mask, int32_t v) { return (g.have & mask) ? String(v) : String("null"); };
  auto bol = [&](uint32_t mask, bool v)    { return (g.have & mask) ? String(v ? "true" : "false") : String("null"); };
  String j = "{";
  j += "\"ok\":" + String(ok ? "true" : "false");
  j += ",\"ble\":\"" + json_esc(ble_state_txt) + "\"";
  j += ",\"rssi\":" + String(ble_connected ? ble_rssi : 0);
  j += ",\"st\":" + num(HAVE(DP_STATE), g.state);
  j += ",\"stt\":\"" + String((g.have & HAVE(DP_STATE)) ? state_txt(g.state) : "") + "\"";
  j += ",\"run\":" + bol(HAVE(DP_SWITCH), g.running);
  j += ",\"p\":"   + num(HAVE(DP_POWER), g.power_w);
  j += ",\"v\":"   + num(HAVE(DP_VOLTAGE), g.voltage);
  j += ",\"hz\":"  + num(HAVE(DP_FREQ), g.freq);
  j += ",\"rpm\":" + num(HAVE(DP_RPM), g.rpm);
  j += ",\"tank\":"+ num(HAVE(DP_TANK), g.tank);
  j += ",\"rm\":"  + num(HAVE(DP_RUN_MIN), g.run_min);
  j += ",\"tm\":"  + num(HAVE(DP_TOTAL_MIN), g.total_min);
  j += ",\"eco\":" + bol(HAVE(DP_ECO), g.eco);
  j += ",\"oil\":" + bol(HAVE(DP_OIL_ALARM), g.oil_alarm);
  j += ",\"bat\":" + num(HAVE(DP_BATTERY), g.battery);
  j += ",\"chg\":\"" + String((g.have & HAVE(DP_CHARGING)) ? charging_txt(g.charging) : "") + "\"";
  j += ",\"f\":"   + num(HAVE(DP_FAULT), (int32_t)g.fault);
  j += ",\"ft\":\"" + ((g.have & HAVE(DP_FAULT)) ? json_esc(fault_txt(g.fault).c_str()) : String("")) + "\"";
  j += ",\"sn\":\"" + json_esc(g.sn) + "\"";
  j += ",\"ae\":" + String(cfg.auto_eco ? "true" : "false");
  j += ",\"ed\":" + String(cfg.eco_delay);
  j += ",\"tmax\":" + String(cfg.max_run_min) + ",\"tl\":" + (timer_left_min >= 0 ? String(timer_left_min) : String("null"));
  j += ",\"tall\":" + String(cfg.timer_all ? "true" : "false");
  j += ",\"bc\":" + String(ble_connect_count) + ",\"bf\":" + String(ble_fail_count);
  j += ",\"cl\":" + String(dp_list_final ? "true" : "false");
  j += ",\"up\":" + String(millis() / 1000);
  j += ",\"wr\":" + String(ap_mode ? 0 : WiFi.RSSI());
  j += ",\"hp\":" + String(ESP.getFreeHeap() / 1024);
  j += ",\"mq\":" + String(mqtt.connected() ? "true" : "false");
  j += "}";
  web_server.send(200, "application/json", j);
}

void handle_root() {
  String dash = FPSTR(DASH_HTML);
  dash.replace("%MAX%", String(POWER_MAX_W));
  dash.replace("%AS%",  cfg.allow_start ? "true" : "false");
  String topts;
  for (uint16_t v : TIMER_OPTS) topts += "<option value='" + String(v) + "'>" + timer_label(v) + "</option>";
  dash.replace("%TOPTS%", topts);

  String p = WH("Generator");
  p += dash;
  p += "<div class='card'><h2>System</h2><table>"
       "<tr><th>Parameter</th><th>Wert</th></tr>"
       "<tr><td>Hostname</td><td>" + html_esc(cfg.hostname) + "</td></tr>"
       "<tr><td>Firmware</td><td>" FW_VERSION "</td></tr>";
  if (ap_mode) {
    p += "<tr><td>Modus</td><td><span class='badge off'>AP-Modus</span></td></tr>"
         "<tr><td>AP-IP</td><td>" + WiFi.softAPIP().toString() + "</td></tr>";
  } else {
    p += "<tr><td>WiFi</td><td><span class='badge on'>" + html_esc(WiFi.SSID().c_str()) + "</span></td></tr>"
         "<tr><td>IP</td><td>" + WiFi.localIP().toString() + "</td></tr>"
         "<tr><td>RSSI</td><td id='wr'>" + String(WiFi.RSSI()) + " dBm</td></tr>";
  }
  GenData g;
  gen_snapshot(g);
  p += "<tr><td>MQTT</td><td id='mq'>" + badge(mqtt.connected(), "Verbunden", "Getrennt") + "</td></tr>"
       "<tr><td>Fernstart</td><td>" + badge(cfg.allow_start, "Erlaubt", "Gesperrt") + "</td></tr>"
       "<tr><td>Seriennummer</td><td>" + ((g.have & HAVE(DP_SN)) ? html_esc(g.sn) : String("---")) + "</td></tr>"
       "<tr><td>Letzter Neustart</td><td>" + String(reset_reason_txt()) + "</td></tr>"
       "<tr><td>BLE-Verbindungen</td><td id='bc'>" + String(ble_connect_count) + " OK / " + String(ble_fail_count) + " fehlgeschlagen</td></tr>"
       "<tr><td>Auto-ECO</td><td>" + badge(cfg.auto_eco, "An", "Aus") + " nach " + String(cfg.eco_delay) + " s</td></tr>"
       "<tr><td>CPU</td><td>" + String(getCpuFrequencyMhz()) + " MHz</td></tr>"
       "<tr><td>Freier Heap</td><td id='hp'>" + String(ESP.getFreeHeap() / 1024) + " kB</td></tr>"
       "<tr><td>Uptime</td><td id='up'>" + String(millis()/1000) + " s</td></tr>"
       "</table></div>";
  p += WF();
  web_server.send(200, "text/html", p);
}

void handle_ctrl_get() {
  GenData g;
  gen_snapshot(g);
  bool ok = tuya_paired;
  String dis = ok ? "" : " disabled";

  String p = WH("Steuerung");
  if (web_server.hasArg("msg")) p += "<div class='card'>" + html_esc(web_server.arg("msg").c_str()) + "</div>";
  p += "<div class='card'><h2>Generator</h2>"
       "<p>Status: " + String((g.have & HAVE(DP_STATE)) ? state_txt(g.state) : "---") + "</p>"
       "<form method='POST' action='/ctrl' class='btns'";
  p += " onsubmit=\"return event.submitter.value!='start'||confirm('Generator wirklich starten?')\">";
  if (cfg.allow_start)
    p += "<button class='grn' name='a' value='start'" + dis + ">Start</button>";
  else
    p += "<button disabled title='In Config freigeben'>Start (gesperrt)</button>";
  p += "<button class='red' name='a' value='stop'" + dis + ">Stop</button></form></div>";

  p += "<div class='card'><h2>ECO-Modus</h2>"
       "<p>Aktuell: " + String((g.have & HAVE(DP_ECO)) ? (g.eco ? "EIN" : "AUS") : "---") + "</p>"
       "<form method='POST' action='/ctrl' class='btns'>"
       "<button name='a' value='eco_on'" + dis + ">ECO ein</button>"
       "<button name='a' value='eco_off'" + dis + ">ECO aus</button></form></div>";

  p += "<div class='card'><h2>Bluetooth</h2>"
       "<p>Der Generator erlaubt nur eine Verbindung. Zum Benutzen der Handy-App hier trennen.</p>"
       "<p>Status: " + String(ble_state_txt) + "</p>"
       "<form method='POST' action='/ctrl' class='btns'>"
       "<button name='a' value='ble_on'>BLE verbinden</button>"
       "<button class='red' name='a' value='ble_off'>BLE trennen</button></form></div>";

  if (!ok) p += "<p style='color:#aaa'>Generator nicht verbunden – Befehle nicht möglich.</p>";
  p += WF();
  web_server.send(200, "text/html", p);
}

void handle_ctrl_post() {
  String a = web_server.arg("a");
  bool r = false;
  if      (a == "start")   r = gen_command("generator", true, "Web");
  else if (a == "stop")    r = gen_command("generator", false, "Web");
  else if (a == "eco_on")  r = gen_command("eco", true, "Web");
  else if (a == "eco_off") r = gen_command("eco", false, "Web");
  else if (a == "ble_on")  r = gen_command("ble", true, "Web");
  else if (a == "aeco_on") r = gen_command("auto_eco", true, "Web");
  else if (a == "aeco_off")r = gen_command("auto_eco", false, "Web");
  else if (a.startsWith("edly")) r = set_eco_delay(a.substring(4).toInt());
  else if (a.startsWith("tmax")) r = set_max_run(a.substring(4).toInt(), "Web");
  else if (a == "tplus")         r = timer_extend(30, "Web");
  else if (a == "ble_off") r = gen_command("ble", false, "Web");
  String msg = r ? "Befehl gesendet: " + a : "Befehl nicht ausgeführt: " + a;
  msg.replace(" ", "+");
  web_server.sendHeader("Location", "/ctrl?msg=" + msg);
  web_server.send(303);
}

String timer_options() {
  String o;
  for (uint16_t v : TIMER_OPTS)
    o += "<option value='" + String(v) + "'" + (cfg.max_run_min == v ? " selected" : "") + ">" + timer_label(v) + "</option>";
  return o;
}

String eco_delay_options() {
  String o;
  for (int v = 5; v <= 20; v += 5)
    o += "<option value='" + String(v) + "'" + (cfg.eco_delay == v ? " selected" : "") + ">" + String(v) + " s</option>";
  return o;
}

void handle_config_get() {
  String p = WH("Konfiguration");
  p += "<form method='POST' action='/config'>"
       "<div class='card'><h2>WiFi</h2>"
       "<div class='row'><label>SSID</label><input name='ssid' value='" + html_esc(cfg.ssid) + "'></div>"
       "<div class='row'><label>Passwort</label><input name='wp' type='password' placeholder='(unveraendert)'></div>"
       "</div><div class='card'><h2>MQTT</h2>"
       "<div class='row'><label>Broker</label><input name='mh' value='" + html_esc(cfg.mqtt_host) + "'></div>"
       "<div class='row'><label>Port</label><input name='mp' value='" + String(cfg.mqtt_port) + "'></div>"
       "<div class='row'><label>User</label><input name='mu' value='" + html_esc(cfg.mqtt_user) + "'></div>"
       "<div class='row'><label>Passwort</label><input name='mpw' type='password' placeholder='(unveraendert)'></div>"
       "<div class='row'><label>Topic-Praefix</label><input name='mt' value='" + html_esc(cfg.mqtt_topic) + "'></div>"
       "<div class='row'><label>Intervall (s)</label><input name='pi' value='" + String(cfg.publish_interval) + "'></div>"
       "</div><div class='card'><h2>Generator (Tuya BLE)</h2>"
       "<div class='row'><label>BLE-MAC</label><input name='bm' value='" + html_esc(cfg.ble_mac) + "'></div>"
       "<div class='row'><label>UUID</label><input name='uu' value='" + html_esc(cfg.uuid) + "'></div>"
       "<div class='row'><label>Device-ID</label><input name='di' value='" + html_esc(cfg.dev_id) + "'></div>"
       "<div class='row'><label>local_key</label><input name='lk' type='password' placeholder='" +
       String(strlen(cfg.local_key) >= 6 ? "(gesetzt – unveraendert)" : "(FEHLT)") + "'></div>"
       "<div class='row'><label>BLE beim Start aktiv</label><input type='checkbox' name='ba'" +
       String(cfg.ble_autostart ? " checked" : "") + "></div>"
       "<div class='row'><label>Auto-ECO nach Start</label><input type='checkbox' name='ae'" +
       String(cfg.auto_eco ? " checked" : "") + "></div>"
       "<div class='row'><label>Auto-ECO Verzögerung</label><select name='ed'>" + eco_delay_options() + "</select></div>"
       "<div class='row'><label>Laufzeit-Timer (max.)</label><select name='mr'>" + timer_options() + "</select></div>"
       "<div class='row'><label>Timer nur bei Start über Gateway</label><input type='checkbox' name='tg'" +
       String(cfg.timer_all ? "" : " checked") + "></div>"
       "<div class='row'><label>Fernstart erlauben</label><input type='checkbox' name='as'" +
       String(cfg.allow_start ? " checked" : "") + "></div>"
       "<p style='color:#f90'>⚠ Fernstart nur aktivieren, wenn der Generator sicher im Freien steht "
       "(Abgase/CO) und ein unbeabsichtigter Start keine Gefahr darstellt. Stop ist immer erlaubt.</p>"
       "</div><div class='card'><h2>Geraet</h2>"
       "<div class='row'><label>Hostname</label><input name='hn' value='" + html_esc(cfg.hostname) + "'></div>"
       "</div><input type='submit' value='Speichern und Neustart'></form>" + WF();
  web_server.send(200, "text/html", p);
}

void handle_config_post() {
  if (web_server.hasArg("ssid")) {
    String s = web_server.arg("ssid");
    s.trim();
    strlcpy(cfg.ssid, s.c_str(), CFG_SSID_LEN);
  }
  if (web_server.hasArg("mh")) strlcpy(cfg.mqtt_host,  web_server.arg("mh").c_str(), MAX_MQTT_HOST_LEN);
  if (web_server.hasArg("mu")) strlcpy(cfg.mqtt_user,  web_server.arg("mu").c_str(), MAX_MQTT_USER_LEN);
  if (web_server.hasArg("mt")) strlcpy(cfg.mqtt_topic, web_server.arg("mt").c_str(), MAX_TOPIC_LEN);
  if (web_server.hasArg("hn")) strlcpy(cfg.hostname,   web_server.arg("hn").c_str(), MAX_HOSTNAME_LEN);
  String w = web_server.arg("wp");  if (w.length()) strlcpy(cfg.wifi_pass, w.c_str(), MAX_PASS_LEN);
  String m = web_server.arg("mpw"); if (m.length()) strlcpy(cfg.mqtt_pass, m.c_str(), MAX_MQTT_PASS_LEN);
  if (web_server.hasArg("mp")) cfg.mqtt_port        = web_server.arg("mp").toInt();
  if (web_server.hasArg("pi")) cfg.publish_interval = web_server.arg("pi").toInt();

  if (web_server.hasArg("bm")) {
    String s = web_server.arg("bm"); s.trim(); s.toUpperCase(); s.replace("-", ":");
    strlcpy(cfg.ble_mac, s.c_str(), MAX_MAC_LEN);
  }
  if (web_server.hasArg("uu")) { String s = web_server.arg("uu"); s.trim(); strlcpy(cfg.uuid,   s.c_str(), MAX_UUID_LEN); }
  if (web_server.hasArg("di")) { String s = web_server.arg("di"); s.trim(); strlcpy(cfg.dev_id, s.c_str(), MAX_DEVID_LEN); }
  String k = web_server.arg("lk"); if (k.length()) strlcpy(cfg.local_key, k.c_str(), MAX_KEY_LEN);
  cfg.ble_autostart = web_server.hasArg("ba");
  cfg.allow_start   = web_server.hasArg("as");
  cfg.auto_eco      = web_server.hasArg("ae");
  if (eco_delay_valid(web_server.arg("ed").toInt())) cfg.eco_delay = web_server.arg("ed").toInt();
  if (web_server.hasArg("mr") && timer_valid(web_server.arg("mr").toInt())) cfg.max_run_min = web_server.arg("mr").toInt();
  cfg.timer_all     = !web_server.hasArg("tg");

  Serial.printf("[CFG] Speichere: SSID='%s' BLE=%s Fernstart=%s\n",
    cfg.ssid, cfg.ble_mac, cfg.allow_start ? "ja" : "nein");

  config_save();
  web_server.send(200, "text/html", WH("OK") +
    "<div class='card'>Gespeichert. Neustart...</div>"
    "<script>setTimeout(()=>location.href='/',4000)</script>" + WF());
  delay(3000);
  ESP.restart();
}

const char* dp_name(uint8_t id) {
  switch (id) {
    case 101: return "switch (Start/Stop)";   case 102: return "percent_state (Tank)";
    case 103: return "power_on_time";         case 104: return "power_current (W)";
    case 105: return "time_total";            case 106: return "online_state";
    case 107: return "fault";                 case 108: return "eco_switch";
    case 109: return "area_clean_alarm (Öl)"; case 110: return "voltage";
    case 111: return "frequency";             case 112: return "rev (Drehzahl)";
    case 113: return "area_clean_alarm_reset";case 114: return "generator_sn";
    case 115: return "battery_level";         case 116: return "charging_capacity";
    default:  return "<b style='color:#f90'>UNBEKANNT</b>";
  }
}

void handle_dp_page() {
  static const char* TYPES[] = { "raw", "bool", "value", "string", "enum", "bitmap" };
  String p = WH("Diagnose: Datenpunkte");
  p += "<script>setTimeout(()=>location.reload(),5000)</script>";
  p += "<div class='card'><p>Alle vom Generator gemeldeten Datenpunkte seit dem Neustart (" +
       String(dp_frames) + " DP-Meldungen). Aktualisiert alle 5 s.</p><table>"
       "<tr><th>DP</th><th>Name</th><th>Typ</th><th>Wert</th><th>Rohdaten</th><th>Anzahl</th><th>Zuletzt</th></tr>";
  int n = 0;
  for (int id = 0; id < 256; id++) {
    DpSeen ds;
    taskENTER_CRITICAL(&gen_mux);
    ds = dp_seen[id];
    taskEXIT_CRITICAL(&gen_mux);
    if (!ds.count) continue;
    n++;
    uint8_t l = min((uint8_t)sizeof(ds.raw), ds.len);
    String val;
    if (ds.type == DP_TYPE_STRING) {
      char b[25]; memcpy(b, ds.raw, l); b[l] = 0; val = "\"" + html_esc(b) + "\"";
    } else if (ds.type == DP_TYPE_RAW) {
      val = "-";
    } else {
      val = String(dp_int(ds.raw, l));
    }
    String hex;
    char hb[4];
    for (int i = 0; i < l; i++) { snprintf(hb, sizeof(hb), "%02X ", ds.raw[i]); hex += hb; }
    p += "<tr><td>" + String(id) + "</td><td>" + dp_name(id) + "</td><td>" +
         String(ds.type < 6 ? TYPES[ds.type] : "?") + "</td><td>" + val + "</td><td><code>" + hex +
         "</code></td><td>" + String(ds.count) + "</td><td>vor " + String((millis() - ds.ms) / 1000) + " s</td></tr>";
  }
  if (!n) p += "<tr><td colspan='7'>Noch keine Daten empfangen.</td></tr>";
  p += "</table></div>";

  p += "<div class='card'><h2>Ereignisprotokoll</h2><p style='color:#888'>Neueste zuerst</p>"
       "<pre style='white-space:pre-wrap;font-size:.85em;line-height:1.5'>";
  taskENTER_CRITICAL(&evlog_mux);
  uint8_t cnt = evlog_count, head = evlog_head;
  static char copy[EVLOG_N][EVLOG_LEN];
  memcpy(copy, evlog, sizeof(copy));
  taskEXIT_CRITICAL(&evlog_mux);
  for (int i = 0; i < cnt; i++) {
    int idx = (head + EVLOG_N - 1 - i) % EVLOG_N;
    p += html_esc(copy[idx]);
    p += "\n";
  }
  if (!cnt) p += "(leer)";
  p += "</pre></div>" + WF();
  web_server.send(200, "text/html", p);
}

void handle_update_get() {
  web_server.send(200, "text/html", WH("Firmware Update") +
    "<div class='card'><p>.bin Datei hochladen</p>"
    "<form method='POST' action='/update' enctype='multipart/form-data'>"
    "<div class='row'><input type='file' name='f' accept='.bin'></div><br>"
    "<input type='submit' value='Update'></form></div>" + WF());
}
void handle_update_post() {
  bool ok = !Update.hasError();
  web_server.send(200, "text/html", WH("Update") +
    "<div class='card'>" + (ok ? "OK! Neustart..." : "Fehler!") + "</div>" +
    (ok ? "<script>setTimeout(()=>location.href='/',5000)</script>" : "") + WF());
  if (ok) { delay(1000); ESP.restart(); }
  ble_enabled = true;      // OTA fehlgeschlagen -> BLE wieder an
}
void handle_update_upload() {
  HTTPUpload& u = web_server.upload();
  if (u.status == UPLOAD_FILE_START) {
    ble_enabled = false;   // BLE pausieren, damit OTA stabil laeuft
    log_event("OTA-Update gestartet (BLE pausiert)");
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  }
  else if (u.status == UPLOAD_FILE_WRITE) { if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial); }
  else if (u.status == UPLOAD_FILE_END)   { if (!Update.end(true)) Update.printError(Serial); }
  else if (u.status == UPLOAD_FILE_ABORTED) { Update.abort(); ble_enabled = true; }
}

// ============================================================
//  Aenderungserkennung
// ============================================================
bool gen_changed(const GenData& a, const GenData& b) {
  return a.have != b.have || a.running != b.running || a.tank != b.tank ||
         a.run_min != b.run_min || a.power_w != b.power_w || a.total_min != b.total_min ||
         a.state != b.state || a.fault != b.fault || a.eco != b.eco ||
         a.oil_alarm != b.oil_alarm || a.voltage != b.voltage || a.freq != b.freq ||
         a.rpm != b.rpm || a.battery != b.battery || a.charging != b.charging ||
         strcmp(a.sn, b.sn) != 0;
}

void wdt_setup() {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  esp_task_wdt_config_t c = { .timeout_ms = WDT_TIMEOUT_S * 1000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_reconfigure(&c) != ESP_OK) esp_task_wdt_init(&c);
#else
  esp_task_wdt_init(WDT_TIMEOUT_S, true);
#endif
  esp_task_wdt_add(NULL);   // loop-Task
}

// ============================================================
//  setup / loop
// ============================================================
void setup() {
  // 80 MHz reicht fuer BLE + WiFi + MQTT (Minimum fuer BLE)
  setCpuFrequencyMhz(80);

  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== MXR4000GT MQTT Gateway ===");
  Serial.printf("[SYS] CPU: %d MHz\n", getCpuFrequencyMhz());
  log_event("Neustart: %s (FW " FW_VERSION ")", reset_reason_txt());
  wdt_setup();

  config_load();
  memset(&gen, 0, sizeof(gen));
  gen.charging = -1;
  ble_enabled = cfg.ble_autostart;

  frag_q = xQueueCreate(48, sizeof(Frag));
  cmd_q  = xQueueCreate(8,  sizeof(TuyaCmd));

  wifi_connect_sta();
  configTzTime(TZ_INFO, NTP_SERVER);

  // WiFi Modem Sleep – bei WiFi+BLE ohnehin Pflicht (Coexistence)
  if (!ap_mode) {
    WiFi.setSleep(true);
    Serial.println("[SYS] WiFi Modem Sleep: EIN");
  }

  web_server.on("/",       HTTP_GET,  handle_root);
  web_server.on("/api",    HTTP_GET,  handle_api);
  web_server.on("/ctrl",   HTTP_GET,  handle_ctrl_get);
  web_server.on("/ctrl",   HTTP_POST, handle_ctrl_post);
  web_server.on("/config", HTTP_GET,  handle_config_get);
  web_server.on("/config", HTTP_POST, handle_config_post);
  web_server.on("/update", HTTP_GET,  handle_update_get);
  web_server.on("/dp",     HTTP_GET,  handle_dp_page);
  web_server.on("/update", HTTP_POST, handle_update_post, handle_update_upload);
  web_server.begin();
  Serial.println("[Web] Server gestartet");

  xTaskCreatePinnedToCore(ble_task, "BLE", 8192, nullptr, 5, nullptr, 1);
}

void loop() {
  esp_task_wdt_reset();
  web_server.handleClient();

  // ── Heap-Waechter (Speicherleck/Fragmentierung im Dauerbetrieb) ──
  static uint32_t heap_check_ms = 0;
  if (millis() - heap_check_ms >= 60000) {
    heap_check_ms = millis();
    if (ESP.getFreeHeap() < HEAP_MIN_BYTES) {
      Serial.printf("[SYS] Heap knapp (%u B) – Neustart\n", ESP.getFreeHeap());
      delay(500);
      ESP.restart();
    }
  }

  // ── WiFi Watchdog (alle 60s, im AP-Modus alle 5 min) ─────────
  static uint32_t wifi_watchdog_ms = 0;
  uint32_t wd_interval = ap_mode ? 300000 : 60000;
  if (millis() - wifi_watchdog_ms >= wd_interval) {
    if (ap_mode ? WiFi.softAPgetStationNum() == 0 : WiFi.status() != WL_CONNECTED) {
      log_event("WLAN weg – Reconnect");
      if (wifi_try_all()) {
        ap_mode           = false;
        wifi_connected    = true;
        ha_discovery_done = false;
        WiFi.setSleep(true);
        MDNS.begin(cfg.hostname);
        log_event("WLAN wieder verbunden (%s)", WiFi.SSID().c_str());
      } else if (ap_mode) {
        wifi_start_ap();     // AP wiederherstellen
        Serial.println("[WiFi] Reconnect fehlgeschlagen – AP wieder aktiv, nächster Versuch in 5 min");
      } else {
        Serial.println("[WiFi] Reconnect fehlgeschlagen – nächster Versuch in 60s");
      }
    }
    wifi_watchdog_ms = millis();
  }

  if (!ap_mode && WiFi.status() != WL_CONNECTED) return;
  if (!ap_mode && !mqtt.connected()) {
    if (millis() - last_reconnect_ms > 5000) {
      last_reconnect_ms = millis();
      mqtt_connect();
    }
    return;
  }
  if (ap_mode) { delay(10); return; }

  mqtt.loop();
  if (!ha_discovery_done && mqtt.connected()) {
    publish_ha_discovery();
    ha_discovery_done = true;
    last_ble_online   = -1;     // nach (Re)Connect Status neu senden
  }

  // ── BLE-Verfuegbarkeit ───────────────────────────────────────
  bool online = ble_online();
  if (online) {
    GenData hg;
    gen_snapshot(hg);
    if (hg.have & ~disc_mask) ha_discovery_done = false;            // neue DPs -> Discovery
    static bool final_sent = false;
    if (dp_list_final && !final_sent) { final_sent = true; ha_discovery_done = false; }
  }
  if ((int)online != last_ble_online) {
    last_ble_online = online;
    mqtt.publish((String(cfg.mqtt_topic) + "/ble/status").c_str(), online ? "online" : "offline", true);
    publish_system();
    Serial.printf("[MQTT] Generator %s\n", online ? "online" : "offline");
  }

  // ── Timer-Restzeit bei Aenderung senden ─────────────────────
  static int32_t last_tl = -2;
  if (timer_left_min != last_tl) {
    last_tl = timer_left_min;
    mqtt.publish(tp("timer_rest").c_str(), last_tl >= 0 ? String(last_tl).c_str() : "0", true);
  }

  // ── Generatordaten: Aenderung (max. alle 2s) oder Heartbeat ──
  static GenData  last_published;
  static uint32_t last_change_ms    = 0;
  static uint32_t last_heartbeat_ms = 0;
  static bool     first             = true;
  bool heartbeat = first || (millis() - last_heartbeat_ms) >= (uint32_t)cfg.publish_interval * 1000;

  if (online) {
    GenData g;
    gen_snapshot(g);
    bool changed = gen_changed(g, last_published) && (millis() - last_change_ms >= 2000);
    if (changed || heartbeat) {
      publish_data(g);
      last_published = g;
      last_change_ms = millis();
    }
  }
  if (heartbeat) {
    publish_system();
    last_heartbeat_ms = millis();
    first = false;
  }
  delay(10);
}
