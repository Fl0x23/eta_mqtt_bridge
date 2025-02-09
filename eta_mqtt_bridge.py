import serial
import paho.mqtt.client as mqtt
import json
from datetime import datetime

def calculate_checksum(data):
    """
    Berechnet die Prüfziffer durch Addition aller Bytes der Nutzdaten modulo 256.
    """
    return sum(data) % 256

def parse_message(message):
    """
    Zerlegt eine Nachricht in ihre Bestandteile basierend auf dem Protokoll und verarbeitet mehrere Datenpaare.
    """
    if not message.startswith(b'{') or not message.endswith(b'}'):
        error_message = "[FEHLER] Ungültige Nachricht: Kein gültiger Start oder Endmarker gefunden."
        print(f"\n{error_message}")
        return None

    # Nachricht ohne STX und ETX extrahieren
    content = message[1:-1]

    try:
        # Bestandteile der Nachricht extrahieren
        fc1 = content[0:1].decode()
        fc2 = content[1:2].decode()
        length = content[2]
        checksum = content[3]
        data = content[4:4 + length]

        info_message = (f"\n[INFO] Nachricht empfangen:\n  Funktionscode 1 (FC1): {fc1}\n  Funktionscode 2 (FC2): {fc2}\n  Länge: {length}")
        print(info_message)

        # Berechne die erwartete Prüfziffer
        calculated_checksum = calculate_checksum(data)

        if checksum != calculated_checksum:
            warning_message = (f"[WARNUNG] Checksumme ungültig: Erwartet {calculated_checksum}, erhalten {checksum}.")
            print(warning_message)
            return None

        success_message = f"[INFO] Checksumme gültig: {checksum}"
        print(success_message)

        # Mehrere Datenpaare verarbeiten
        results = []
        for i in range(0, len(data), 5):
            if i + 5 <= len(data):
                byte3 = data[i + 2]
                byte4 = data[i + 3]
                byte5 = data[i + 4]

                # Zuordnung anhand von Byte3
                assignments = {
                    0x08: "kessel",
                    0x0F: "abgas",
                    0x0D: "boiler",
                    0xA4: "brauchwasser",
                    0x6A: "bwt_rucklauf",
                    0x6B: "bwt_mitte",
                    0x4B: "pufferladezustand",
                    0x0C: "puffer_oben",
                    0x0B: "puffer_mitte",
                    0x0A: "puffer_unten",
                    0x09: "kesselrucklauf",
                    0x75: "brenner",
                    0x3E: "kollektor",
                    0xA1: "boiler_oben_sol",
                    0x3F: "boiler_unten_sol",
                    0x46: "aussentemperatur",
                    0x44: "vorlauf_mk1",
                    0x42: "raum_mk1",
                    0x45: "vorlauf_mk2",
                    0x43: "raum_mk2",
                    0x52: "vorlauf_mk3",
                    0x51: "raum_mk3",
                    0x5E: "vorlauf_mk4",
                    0x5D: "raum_mk4",
                }

                topic = assignments.get(byte3)
                    
                # Temperatur berechnen, falls nicht Pufferladezustand
                if topic == "pufferladezustand":
                    value = byte4 * 256 + byte5
                else:
                    # 16-Bit-Wert aus zwei Bytes zusammensetzen
                    value = (byte4 << 8) | byte5  # Bitweise Verschiebung für Klarheit
    
                    # Überprüfen, ob das Ergebnis negativ ist (Two’s Complement)
                    if value >= 32768:  # 0x8000 = 32768 (negative Werte)
                        value -= 65536  # Korrektur für negative Zahlen

                    value = value / 10  # Division durch 10 für Temperaturwerte
                    
                if topic:
                    data_message = f"  [DATEN] Typ: {topic}, Wert: {value}"
                    print(data_message)
                    results.append({"topic": topic, "value": value})

        return results

    except Exception as e:
        error_message = f"[FEHLER] Fehler beim Parsen der Nachricht: {e}"
        print(error_message)
        return None

def send_control_message(ser):

	# Nachricht zur Übermittlung der Monitor-Daten
	# Struktur:
	# {MC\xLänge\xPrüfziffer\xIntervall\Datenfelder}
	# 
	# Beschreibung:
	# 1. Start- und Endzeichen:
	#    - `{` und `}`: Umrahmen die Nachricht.
	# 2. Steuerzeichen:
	#    - `M` und `C`: Kennzeichnen den Nachrichtentyp.
	# 3. Länge:
	#    - `\x22`: Anzahl der Datenbytes (inklusive Intervall und Datenfelder, exklusive Prüfziffer und Steuerzeichen).
	# 4. Prüfziffer:
	#    - `\x2c`: Prüfsumme der Datenbytes modulo 256.
	# 5. Intervall:
	#    - `\x3c`: Zeitlicher Intervall (z. B. 60 Sekunden).
	# 6. Datenfelder:
	#    - Jedes Datenfeld hat die Form: `\x08\x00\Monitor`, wobei:
	#      - `\x08`: Bestellort (immer Kessel in diesem Fall).
	#      - `\x00`: Zusatzfeld (keine spezifische Verwendung hier).
	#      - `\Monitor`: Hexadezimaler Wert des Monitors.
	#    - Monitore:
	#      - `\x08\x00\x08`: Kessel.
	#      - `\x08\x00\x0f`: Abgas.
	#      - `\x08\x00\x0d`: Boiler.
	#      - `\x08\x00\x4b`: Pufferladezustand.
	#      - `\x08\x00\x0c`: Puffer oben.
	#      - `\x08\x00\x0b`: Puffer mitte.
	#      - `\x08\x00\x0a`: Puffer unten.
	#      - `\x08\x00\x09`: Kesselrücklauf.
	#      - `\x08\x00\x75`: Brenner.
	#      - `\x08\x00\x46`: Außentemperatur.
	#      - `\x08\x00\x44`: Vorlauf MK 1.

    control_message = b'{MC\x22\x2c\x3c\x08\x00\x08\x08\x00\x0f\x08\x00\x0d\x08\x00\x4b\x08\x00\x0c\x08\x00\x0b\x08\x00\x0a\x08\x00\x09\x08\x00\x75\x08\x00\x46\x08\x00\x44}'
    ser.write(control_message)
    message = f"\n[INFO] Steuerungsnachricht gesendet: {control_message}"
    print(message)

def send_stop_message(ser):
    stop_message = b'{ME\x00\x00}'
    ser.write(stop_message)
    message = f"\n[INFO] Stoppnachricht gesendet: {stop_message}"
    print(message)

def send_to_mqtt(results, mqtt_client):
    if results:
        print("\n[INFO] Sende Daten an MQTT:")
        for result in results:
            topic = f"heizung/{result['topic']}"
            value = result['value']
            mqtt_client.publish(topic, str(value))
            message = f"  [MQTT] Topic: {topic}, Wert: {value}"
            print(message)
        mqtt_client.loop(2)  # Sicherstellen, dass alle Nachrichten gesendet wurden

def load_mqtt_credentials(file_path):
    """
    Lädt MQTT-Login-Daten aus einer Datei basierend auf der neuen Konfiguration.
    """
    try:
        with open(file_path, 'r') as file:
            config = json.load(file)
            mqtt_config = config.get("mqtt", {})
            return (
                mqtt_config.get("username"), 
                mqtt_config.get("password"), 
                mqtt_config.get("server"), 
                mqtt_config.get("port")
            )
    except Exception as e:
        error_message = f"[FEHLER] Fehler beim Laden der MQTT-Login-Daten: {e}"
        print(error_message)
        raise

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[START] Script gestartet um: {timestamp}")

    print("\n[INFO] Verbindung zur seriellen Schnittstelle herstellen...")
    ser = serial.Serial('/dev/ttyUSB0', 19200, timeout=10)
    message = f"[INFO] Serielle Verbindung hergestellt: {ser.port}"
    print(message)

    print("\n[INFO] MQTT-Login-Daten laden...")
    username, password, server, port = load_mqtt_credentials('/home/fl0x23/eta/mqtt_credentials.json')

    print("\n[INFO] Verbindung zum MQTT-Server herstellen...")
    mqtt_client = mqtt.Client()
    mqtt_client.username_pw_set(username, password)
    mqtt_client.connect(server, port, 60)
    message = "[INFO] MQTT-Verbindung hergestellt."
    print(message)

    try:
        send_control_message(ser)

        while True:
            print("\n[INFO] Warten auf Daten...")
            rohdaten = ser.read(1024)
            if not rohdaten:
                warning_message = "[WARNUNG] Keine Daten empfangen."
                print(warning_message)
                continue

            message = f"\n[INFO] Daten empfangen: {rohdaten}"
            print(message)
            results = parse_message(rohdaten)
            if results:
                send_stop_message(ser)
                send_to_mqtt(results, mqtt_client)
                print("\n[INFO] Verarbeitung abgeschlossen.")
                break

        # Überprüfen, ob weitere Daten nach der Stoppnachricht kommen
        print("\n[INFO] Überprüfen auf zusätzliche Daten nach der Stoppnachricht...")
        additional_data = ser.read(1024)
        if additional_data:
            warning_message = f"[WARNUNG] Zusätzliche Daten empfangen: {additional_data}"
            print(warning_message)
        else:
            message = "[INFO] Keine zusätzlichen Daten empfangen."
            print(message)

    except Exception as e:
        error_message = f"[FEHLER] {e}"
        print(error_message)

    finally:
        message = f"\n[INFO] Verbindung zur seriellen Schnittstelle {ser.port} schließen..."
        print(message)
        ser.close()
        message = "[INFO] Verbindung zur seriellen Schnittstelle geschlossen."
        print(message)

        message = "[INFO] Verbindung zum MQTT-Server schließen..."
        print(message)
        mqtt_client.disconnect()
        message = "[INFO] Verbindung zum MQTT-Server geschlossen."
        print(message)

if __name__ == "__main__":
    main()

