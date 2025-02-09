import serial
import paho.mqtt.client as mqtt
import json
from datetime import datetime

def calculate_checksum(data):
    """
    Berechnet die Prüfziffer durch Addition aller Bytes der Nutzdaten modulo 256.
    """
    return sum(data) % 256
    
def format_control_message(control_message: bytes) -> str:
    """Formatiert die Steuerungsnachricht für eine leserliche Ausgabe."""
    readable_message = "{MC "
    readable_message += " ".join(f"0x{byte:02X}" for byte in control_message[3:-1])
    readable_message += "}"
    return readable_message

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

def send_control_message(ser, eta_config: dict):
    """
    Sendet eine Steuerungsnachricht mit den Daten aus der eta-Konfiguration.
    
    :param ser: Serielles Objekt zur Kommunikation.
    :param eta_config: Dictionary mit den Konfigurationsdaten von eta.
    """
    interval = eta_config.get("interval", 60)
    order_location = int(eta_config.get("location", "0x08"), 16)
    monitors = [int(value, 16) for value in eta_config.get("monitors", {}).values()]
    
    if len(monitors) == 0:
        print("[ERROR] Die Monitor-Liste darf nicht leer sein.")
        return
    
    # Intervall als einzelnes Byte kodieren
    interval_byte = interval.to_bytes(1, 'big')
    
    # Datenfelder zusammenbauen
    data_fields = b''
    for monitor in monitors:
        data_fields += order_location.to_bytes(1, 'big') + b'\x00' + monitor.to_bytes(1, 'big')
    
    # Länge der Nachricht bestimmen (Intervall + Datenfelder)
    length_byte = (len(interval_byte) + len(data_fields)).to_bytes(1, 'big')
    
    # Prüfziffer berechnen
    checksum_byte = calculate_checksum(interval_byte + data_fields).to_bytes(1, 'big')
    
    # Gesamtnachricht zusammenstellen
    control_message = b'{' + b'MC' + length_byte + checksum_byte + interval_byte + data_fields + b'}'
    
    # Nachricht senden
    ser.write(control_message)
    
    # Lesbare Nachricht ausgeben
    readable_message = format_control_message(control_message)
    print(f"\n[INFO] Steuerungsnachricht gesendet: {readable_message}")

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

def load_mqtt_credentials(mqtt_config):
    """
    Lädt MQTT-Login-Daten aus einer Datei basierend auf der neuen Konfiguration.
    """
    return (
        mqtt_config.get("username"), 
        mqtt_config.get("password"), 
        mqtt_config.get("server"), 
        mqtt_config.get("port")
    )
        
def load_config(file_path: str) -> dict:
    """Lädt die Konfigurationsdaten aus einer JSON-Datei."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        error_message = f"[FEHLER] Fehler beim Laden der Config-Daten: {e}"
        print(error_message)
        raise

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[START] Script gestartet um: {timestamp}")

    print("\n[INFO] Verbindung zur seriellen Schnittstelle herstellen...")
    ser = serial.Serial('/dev/ttyUSB0', 19200, timeout=10)
    message = f"[INFO] Serielle Verbindung hergestellt: {ser.port}"
    print(message)

    print("\n[INFO] config.json laden...")
    config = load_config("config.json")
    mqtt_config = config.get("mqtt", {})
    eta_config = config.get("eta", {})
    
    print("\n[INFO] MQTT-Login-Daten laden...")
    username, password, server, port = load_mqtt_credentials(mqtt_config)

    print("\n[INFO] Verbindung zum MQTT-Server herstellen...")
    mqtt_client = mqtt.Client()
    mqtt_client.username_pw_set(username, password)
    mqtt_client.connect(server, port, 60)
    message = "[INFO] MQTT-Verbindung hergestellt."
    print(message)

    try:
        send_control_message(ser, eta_config)

        while True:
            print("\n[INFO] Warten auf Daten...")
            rohdaten = ser.read(1024)
            if not rohdaten:
                warning_message = "[WARNUNG] Keine Daten empfangen."
                print(warning_message)
                continue
            
            readable_rohdata = format_control_message(rohdaten)
            message = f"\n[INFO] Daten empfangen: {readable_rohdata}"
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

