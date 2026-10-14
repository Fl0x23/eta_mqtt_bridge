import serial
import paho.mqtt.client as mqtt
import json
import os
import re
from datetime import datetime

# config.json und secrets.json liegen im selben Ordner wie das Skript
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
SECRETS_PATH = os.path.join(BASE_DIR, "secrets.json")

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

def make_topic(name: str) -> str:
    """Leitet aus dem Monitor-Namen ein MQTT-Topic ab, z. B. "Puffer oben" -> "puffer_oben"."""
    topic = name.lower()
    for umlaut, replacement in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss")):
        topic = topic.replace(umlaut, replacement)
    return re.sub(r"[^a-z0-9]+", "_", topic).strip("_")

def load_monitors(eta_config: dict) -> list:
    """
    Liest die Monitore aus der eta-Konfiguration und ergänzt Standardwerte.

    Jeder Monitor ist ein Objekt mit:
      id      (Pflicht)  Monitor-ID als Hex-String, z. B. "0x08"
      topic   (optional) MQTT-Topic, Standard: aus dem Namen abgeleitet
      scale   (optional) Teiler für den Rohwert, Standard: 10 (Temperaturen)
      signed  (optional) Rohwert mit Vorzeichen, Standard: true
      invalid (optional) Rohwert, der "kein gültiger Wert" bedeutet, z. B. "0x8000"
    """
    monitors = []
    for name, settings in eta_config.get("monitors", {}).items():
        if not isinstance(settings, dict) or "id" not in settings:
            raise ValueError(
                f'Monitor "{name}": erwartet wird ein Objekt mit "id", '
                f'z. B. {{"id": "0x08", "topic": "kessel"}}, erhalten: {settings!r}'
            )
        invalid = settings.get("invalid")
        monitors.append({
            "name": name,
            "id": int(settings["id"], 16),
            "topic": settings.get("topic") or make_topic(name),
            "scale": settings.get("scale", 10),
            "signed": settings.get("signed", True),
            "invalid": int(invalid, 16) if invalid is not None else None,
        })

    seen = {}
    for monitor in monitors:
        if monitor["id"] in seen:
            raise ValueError(
                f'Monitor-ID 0x{monitor["id"]:02X} ist doppelt vergeben: '
                f'"{seen[monitor["id"]]}" und "{monitor["name"]}"'
            )
        seen[monitor["id"]] = monitor["name"]

    return monitors

def parse_message(message, monitors_by_id: dict):
    """
    Zerlegt eine Nachricht in ihre Bestandteile basierend auf dem Protokoll und verarbeitet mehrere Datenpaare.

    :param monitors_by_id: Monitore aus der Konfiguration, nach Monitor-ID.
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
                monitor = monitors_by_id.get(byte3)
                if monitor is None:
                    print(f"  [WARNUNG] Unbekannte Monitor-ID 0x{byte3:02X}, Wert wird ignoriert.")
                    continue

                topic = monitor["topic"]

                # 16-Bit-Rohwert aus zwei Bytes zusammensetzen
                raw = (byte4 << 8) | byte5

                # Sensor meldet "kein gültiger Wert" (z. B. Lambdasonde nicht bereit) -> nicht senden
                if raw == monitor["invalid"]:
                    print(f"  [DATEN] Typ: {topic}, kein gültiger Wert (0x{raw:04X}), wird nicht gesendet.")
                    continue

                # Negative Werte (Two’s Complement)
                if monitor["signed"] and raw >= 0x8000:
                    raw -= 0x10000

                value = raw / monitor["scale"] if monitor["scale"] != 1 else raw

                data_message = f"  [DATEN] Typ: {topic}, Wert: {value}"
                print(data_message)
                results.append({"topic": topic, "value": value})

        return results

    except Exception as e:
        error_message = f"[FEHLER] Fehler beim Parsen der Nachricht: {e}"
        print(error_message)
        return None

def send_control_message(ser, eta_config: dict, monitor_list: list):
    """
    Sendet eine Steuerungsnachricht mit den Daten aus der eta-Konfiguration.

    :param ser: Serielles Objekt zur Kommunikation.
    :param eta_config: Dictionary mit den Konfigurationsdaten von eta.
    :param monitor_list: Monitore aus load_monitors().
    """
    interval = eta_config.get("interval", 60)
    order_location = int(eta_config.get("location", "0x08"), 16)
    monitors = [monitor["id"] for monitor in monitor_list]
    
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

def load_mqtt_credentials(mqtt_config, mqtt_secrets):
    """
    Liefert Login-Daten (aus secrets.json) und Server-Adresse (aus config.json) für MQTT.
    """
    return (
        mqtt_secrets.get("username"),
        mqtt_secrets.get("password"),
        mqtt_config.get("server"),
        mqtt_config.get("port")
    )

def load_config(file_path: str) -> dict:
    """Lädt die Konfigurationsdaten aus einer JSON-Datei."""
    if file_path == SECRETS_PATH and not os.path.exists(file_path):
        print(f"[FEHLER] {file_path} nicht gefunden. "
              "Bitte secrets.example.json nach secrets.json kopieren und die MQTT-Login-Daten eintragen.")
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

    print("\n[INFO] config.json und secrets.json laden...")
    config = load_config(CONFIG_PATH)
    secrets = load_config(SECRETS_PATH)
    mqtt_config = config.get("mqtt", {})
    mqtt_secrets = secrets.get("mqtt", {})
    eta_config = config.get("eta", {})
    monitor_list = load_monitors(eta_config)
    monitors_by_id = {monitor["id"]: monitor for monitor in monitor_list}

    print("\n[INFO] Verbindung zur seriellen Schnittstelle herstellen...")
    ser = serial.Serial('/dev/ttyUSB0', 19200, timeout=10)
    message = f"[INFO] Serielle Verbindung hergestellt: {ser.port}"
    print(message)

    print("\n[INFO] MQTT-Login-Daten laden...")
    username, password, server, port = load_mqtt_credentials(mqtt_config, mqtt_secrets)

    print("\n[INFO] Verbindung zum MQTT-Server herstellen...")
    mqtt_client = mqtt.Client()
    mqtt_client.username_pw_set(username, password)
    mqtt_client.connect(server, port, 60)
    message = "[INFO] MQTT-Verbindung hergestellt."
    print(message)

    try:
        send_control_message(ser, eta_config, monitor_list)

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
            results = parse_message(rohdaten, monitors_by_id)
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

