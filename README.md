# ETA RS232 MQTT Bridge

Dieses Repository enthält ein Python-Skript, das sich mit einem ETA SH30 Scheitholzofen verbindet. Es liest Daten von der seriellen Schnittstelle RS232 des Ofens, verarbeitet diese und sendet sie an einen MQTT-Server zur weiteren Verwendung. 

## Funktionen

- **Serielle Kommunikation**: Verbindet sich mit der seriellen Schnittstelle des ETA SH30 Scheitholzofens.
- **Datenverarbeitung**: Liest und zerlegt eingehende Nachrichten, überprüft die Prüfsumme und extrahiert relevante Daten.
- **MQTT-Integration**: Sendet die verarbeiteten Daten an einen MQTT-Server.

## Konfiguration

Die Konfiguration erfolgt über eine `config.json`-Datei, die die folgenden Informationen enthält:

- **MQTT**:
  - `username`: Benutzername MQTT-Authentifizierung.
  - `password`: Passwort MQTT-Authentifizierung.
  - `server`: Die Adresse des MQTT-Servers.
  - `port`: Der Port des MQTT-Servers.
- **ETA**:
  - `location`: Die Abruflocation.
  - `monitors`: Eine Liste von Monitor-Adressen, die abgefragt werden sollen.
