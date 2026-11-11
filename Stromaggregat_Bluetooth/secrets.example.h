// ============================================================
//  Vorlage fuer die Zugangsdaten
//  -> Diese Datei nach "secrets.h" kopieren und ausfuellen.
//     secrets.h steht in .gitignore und wird nicht eingecheckt.
//
//  Alles kann leer bleiben: Dann startet das Gateway den
//  Access Point "MXR4000" (http://192.168.4.1) und alles wird
//  im Web-Interface unter "Config" eingetragen.
// ============================================================
#pragma once

// WLAN-Fallback (wird genutzt, wenn im Web-Interface kein WLAN eingetragen ist)
#define FIXED_SSID          ""        // Haupt-WLAN
#define FIXED_PASS          ""
#define FIXED_SSID2         ""        // Backup-WLAN (optional)
#define FIXED_PASS2         ""

// Generator – Werte aus der Tuya IoT Platform:
//   API Explorer -> Device Management -> "Query Device Details"
//   -> local_key, uuid, id (= Device-ID)
// BLE-MAC: z.B. mit der App "nRF Connect" auslesen
// ACHTUNG: local_key aendert sich bei jedem Neu-Koppeln des Generators!
#define DEFAULT_BLE_MAC     ""        // z.B. "AA:BB:CC:DD:EE:FF"
#define DEFAULT_UUID        ""        // 16 Zeichen
#define DEFAULT_DEVICE_ID   ""        // z.B. "bf0123456789abcdef"
#define DEFAULT_LOCAL_KEY   ""        // 16 Zeichen
