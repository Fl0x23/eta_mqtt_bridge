# ETA RS232 MQTT Bridge

Dieses Repository enthält ein Python-Skript, das sich mit einem ETA SH30 Scheitholzofen verbindet. Es liest Daten von der seriellen Schnittstelle RS232 des Ofens, verarbeitet diese und sendet sie an einen MQTT-Server zur weiteren Verwendung. 

## Funktionen

- **Serielle Kommunikation**: Verbindet sich mit der seriellen Schnittstelle des ETA SH30 Scheitholzofens.
- **Datenverarbeitung**: Liest und zerlegt eingehende Nachrichten, überprüft die Prüfsumme und extrahiert relevante Daten.
- **MQTT-Integration**: Sendet die verarbeiteten Daten an einen MQTT-Server.

## Konfiguration

Die Konfiguration ist auf zwei Dateien im Ordner des Skripts aufgeteilt:

| Datei          | Inhalt                                    | Im Repository |
|----------------|-------------------------------------------|---------------|
| `config.json`  | MQTT-Server, ETA-Einstellungen, Monitore  | ja            |
| `secrets.json` | MQTT-Login-Daten                          | nein          |

### secrets.json

Vorlage kopieren und die eigenen Login-Daten eintragen:

```bash
cp secrets.example.json secrets.json
```

- **MQTT**:
  - `username`: Benutzername MQTT-Authentifizierung.
  - `password`: Passwort MQTT-Authentifizierung.

### config.json

- **MQTT**:
  - `server`: Die Adresse des MQTT-Servers.
  - `port`: Der Port des MQTT-Servers.
- **ETA**:
  - `interval`: Sendeintervall der ETA in Sekunden (max. 255).
  - `location`: Die Abruflocation.
  - `max_monitors`: Maximale Anzahl Werte pro Anfrage an die ETA (Standard: 20). Sind mehr Monitore eingetragen, fragt das Skript sie nacheinander in Paketen dieser Größe ab.
  - `max_attempts`: Leseversuche pro Paket à 10 Sekunden (Standard: 5). Kommt bis dahin keine gültige Antwort, wird das Paket übersprungen.

Alle Werte werden zuerst von der ETA gelesen und danach gebündelt an MQTT gesendet.
  - `monitors`: Die Werte, die abgefragt und an MQTT gesendet werden sollen (siehe unten).

#### Monitore

Alle abzufragenden Werte werden in der `config.json` festgelegt.
Der Schlüssel ist ein frei wählbarer Name, der Wert ein Objekt mit diesen Feldern:

| Feld      | Pflicht | Standard                 | Bedeutung                                                           |
|-----------|---------|--------------------------|---------------------------------------------------------------------|
| `id`      | ja      | –                        | Monitor-ID als Hex-String, z. B. `"0x08"`                           |
| `topic`   | nein    | aus dem Namen abgeleitet | MQTT-Topic unter `heizung/`, z. B. `"Puffer oben"` → `puffer_oben`  |
| `scale`   | nein    | `10`                     | Teiler für den Rohwert (`10` für Temperaturen, `1` für Rohwerte)    |
| `signed`  | nein    | `true`                   | Rohwert mit Vorzeichen (negative Temperaturen)                      |
| `invalid` | nein    | –                        | Rohwert, der „kein gültiger Wert“ bedeutet; wird nicht gesendet     |

Beispiele:

```json
"monitors": {
  "Kessel":            { "id": "0x08", "topic": "kessel" },
  "Pufferladezustand": { "id": "0x4B", "topic": "pufferladezustand", "scale": 1, "signed": false },
  "Restsauerstoff":    { "id": "0x28", "topic": "restsauerstoff", "scale": 100, "signed": false, "invalid": "0x8000" }
}
```

Für eine Temperatur reicht also `{ "id": "0x..." }`, alles andere hat passende Standardwerte.

#### Monitor-IDs

- `scale`: Teiler für den Rohwert (z. B. `10` → 452 wird 45,2).
- `signed`: Wert kann negativ sein (z. B. Außentemperatur).
- `invalid`: Rohwert für „kein gültiger Wert“, wird nicht gesendet.

| ID     | Wert                         | Topic                           | `scale` | `signed` | `invalid` |
|--------|------------------------------|---------------------------------|---------|----------|-----------|
| `0x08` | Kessel                       | `kessel`                        | 10      | ja       |           |
| `0x0F` | Abgas                        | `abgas`                         | 10      | ja       |           |
| `0x0D` | Boiler                       | `boiler`                        | 10      | ja       |           |
| `0x4B` | Pufferladezustand            | `pufferladezustand`             | 1       | nein     |           |
| `0x0C` | Puffer oben                  | `puffer_oben`                   | 10      | ja       |           |
| `0x0B` | Puffer mitte                 | `puffer_mitte`                  | 10      | ja       |           |
| `0x0A` | Puffer unten                 | `puffer_unten`                  | 10      | ja       |           |
| `0x09` | Kesselrücklauf               | `kesselrucklauf`                | 10      | ja       |           |
| `0x75` | Brenner                      | `brenner`                       | 10      | ja       |           |
| `0x46` | Außentemperatur              | `aussentemperatur`              | 10      | ja       |           |
| `0x44` | Vorlauf MK 1                 | `vorlauf_mk1`                   | 10      | ja       |           |
| `0x07` | Abgasgebläse                 | `abgasgeblaese`                 | 1       | nein     |           |
| `0x2B` | Heizkreispumpe MK1           | `heizkreispumpe_mk1`            | 1       | nein     |           |
| `0x2C` | Heizkreispumpe MK2           | `heizkreispumpe_mk2`            | 1       | nein     |           |
| `0x2D` | Boilerladepumpe              | `boilerladepumpe`               | 1       | nein     |           |
| `0x2E` | Pufferladepumpe              | `pufferladepumpe`               | 1       | nein     |           |
| `0x21` | Betriebsstunden Abgasgebläse | `betriebsstunden_abgasgeblaese` | 1       | nein     |           |
| `0x37` | Wartung                      | `wartung_stunden`               | 1       | nein     |           |
| `0x03` | Kesseltür                    | `kesseltuer`                    | 1       | nein     |           |
| `0x28` | Restsauerstoff               | `restsauerstoff`                | 100     | nein     | `0x8000`  |
