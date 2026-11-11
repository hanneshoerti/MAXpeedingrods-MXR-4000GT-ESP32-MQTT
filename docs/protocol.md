# Tuya-BLE-Protokoll des MXR4000GT

Der MaXpeedingRods MXR4000GT (Bluetooth-Modul `MXR4000GT-BL`) nutzt das **Tuya-BLE-Protokoll v3**. Die Hersteller-App ist eine Tuya-OEM-App (ThingClips-SDK). Der Generator lässt sich deshalb auch mit **Smart Life** koppeln.

## GATT

| UUID | Eigenschaft | Zweck |
|---|---|---|
| Service `0x1910` | – | Tuya-Service |
| `0x2B11` | Write without Response | Befehle an den Generator |
| `0x2B10` | Notify | Antworten / Statusmeldungen |

MTU 23 → Fragmente zu je 20 Byte.

## Framing

```
Fragment:  [Fragment-Nr. varint][nur bei Nr. 0: Gesamtlänge varint + 0x20][Daten …]
Daten:     [Security-Flag 1][IV 16][AES-128-CBC verschlüsselt]
Klartext:  seq(4, BE) | response_to(4) | code(2) | len(2) | data | CRC16-Modbus(2) | 0-Padding auf 16
```

| Flag | Schlüssel |
|---|---|
| 4 | Login-Key = `MD5(local_key[0..5])` |
| 5 | Session-Key = `MD5(local_key[0..5] + srand)` |

## Ablauf

1. `DEVICE_INFO` (0x0000, leer, Flag 4) → Antwort enthält `srand` in `data[6..11]` → Session-Key berechnen
2. `PAIR` (0x0001): `uuid + local_key[0..5] + device_id`, mit Nullen auf 44 Byte aufgefüllt. Antwort `0` oder `2` = OK
3. `DEVICE_STATUS` (0x0003, leer) → Generator sendet alle Datenpunkte
4. Danach meldet der Generator ca. alle 0,5 s Datenpunkte (`0x8001`). Jede Meldung wird mit leerer Antwort (gleicher Code, `response_to` = seq) quittiert.
5. Zeitanfrage `0x8011` → Antwort: Millisekunden-Zeitstempel als ASCII + Zeitzone (int16 BE, 1/100 h). `0x8012` → `JJ MM TT hh mm ss Wochentag TZ`
6. Befehl: `SEND_DPS` (0x0002) mit `[dp][typ][len][wert]` (bool 1 Byte, value 4 Byte BE)

Die Paketlängen der Firmware (33/81/49/33 Byte) stimmen mit einem Mitschnitt der Original-App überein.

## Datenpunkte (Tuya-Produkt `jlblyn8z`)

| DP | Code | Typ | Bedeutung | vom MXR4000GT gemeldet |
|---|---|---|---|---|
| 101 | switch | bool rw | Start / Stop | ✅ |
| 102 | percent_state | value | Tankfüllstand % | ✅ |
| 103 | power_on_time | value | Laufzeit aktueller Lauf (min) | ✅ |
| 104 | power_current | value | Ausgangsleistung (W) | ✅ |
| 105 | time_total | value | Gesamtlaufzeit (min) | ✅ |
| 106 | online_state | enum | 0 gestoppt, 1 läuft, 2 Schutz | ✅ |
| 107 | fault | bitmap | Fehler (siehe unten) | ✅ |
| 108 | eco_switch | bool rw | ECO-Modus | ✅ |
| 109 | area_clean_alarm | bool | Ölwechsel fällig | ❌ |
| 110 | voltage | value | Spannung (V) | ✅ |
| 111 | frequency | value | Frequenz (Hz) | ✅ |
| 112 | rev | value | Drehzahl (rpm) | ❌ |
| 113 | area_clean_alarm_reset | string wr | Ölwechsel-Reset | – |
| 114 | generator_sn | string | Seriennummer | ✅ |
| 115 | battery_level | value | Batterie % | ❌ |
| 116 | charging_capacity | value | Ladestatus −1…5 | ❌ |

Fehler-Bits (DP 107, aus der chinesischen Beschreibung im Datenmodell übersetzt, nicht verifiziert):
0 kein Fehler · 1 Überlast · 2 Kurzschluss · 3 Unterspannung · 4 Zwischenkreis zu hoch · 5 Zwischenkreis zu niedrig · 6 Nulldurchgang-Fehler · 7 Übertemperatur · 8 Hardware-Überstrom · 9 Frequenz passt nicht · 10 Drehzahl zu niedrig · 11 Spannung asymmetrisch · 12 per Befehl abgeschaltet · 13 Verschlüsselungsfehler · 14 Master/Slave-Kommunikation · 15 reserviert

## Referenz

- Python-Implementierung des Tuya-BLE-Protokolls: [PlusPlus-ua/ha_tuya_ble](https://github.com/PlusPlus-ua/ha_tuya_ble)
