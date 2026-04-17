"""
Factor an OPC-UA server's RSA-2048 cert (from Basic256Sha256 handshake or
self-signed cert with 10-year validity) to forge authenticated OPERATE commands
on PLCs, SCADA historians, and industrial field devices — opening valves,
tripping breakers, modifying setpoints in 20-year-old ICS networks.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import time

# OPC-UA server RSA-2048 cert (self-signed, 10-year validity, typical OT)

_demo = generate_demo_target()
OPCUA_SERVER_PUBKEY_PEM = _demo["pub_pem"]

# OPC-UA security policy URIs
POLICY_BASIC128RSA15 = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
POLICY_BASIC256SHA256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
POLICY_AES256SHA256RSAPSS = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

# OPC-UA node IDs for industrial operations
NODE_VALVE_POSITION = "ns=2;s=VALVE-001.Position"
NODE_BREAKER_STATE = "ns=2;s=BREAKER-015.State"
NODE_SETPOINT = "ns=2;s=REACTOR-TEMP.Setpoint"


def extract_opcua_server_cert(discovery_endpoint: str) -> bytes:
    """Extract OPC-UA server RSA cert from the GetEndpoints response.

    OPC-UA Discovery returns the server's certificate in the
    EndpointDescription. No authentication required to query.
    Self-signed RSA-2048 with 10-year validity is standard in OT.
    """
    print(f"    GetEndpoints: {discovery_endpoint}")
    return OPCUA_SERVER_PUBKEY_PEM


def factor_opcua_cert(pubkey_pem: bytes) -> bytes:
    """Factor the OPC-UA server's RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def open_secure_channel(server_cert: bytes, security_policy: str,
                        forged_privkey: bytes) -> dict:
    """Open an OPC-UA SecureChannel with the factored server key.

    For client impersonation: forge a client cert trusted by the server.
    For server MitM: present the forged server cert to real clients.
    """
    return {
        "policy": security_policy,
        "channel_id": 42,
        "token_id": 1,
        "session_auth": "X.509 client cert (forged)",
    }


def write_node_value(channel: dict, node_id: str, value) -> dict:
    """Issue an OPC-UA Write service call to modify a process variable.

    This is the authenticated command path for industrial equipment:
    open valves, close breakers, change setpoints.
    """
    return {
        "node": node_id,
        "value": value,
        "status": "Good (0x00000000)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def decrypt_opcua_session(captured_traffic: bytes,
                          forged_privkey: bytes) -> bytes:
    """Decrypt captured OPC-UA Basic256Sha256 session traffic.

    RSA-OAEP wraps the symmetric session key. Factor the server
    key → unwrap session key → decrypt all traffic (historian queries,
    setpoint changes, alarm states).
    """
    f = PolynomialFactorer()
    # RSA-OAEP unwrap of session nonce from OpenSecureChannel request
    return b"<decrypted-opcua-session-data>"


if __name__ == "__main__":
    print("[1] Extracting OPC-UA server cert from GetEndpoints")
    pubkey = extract_opcua_server_cert("opc.tcp://scada.plant.local:4840")

    print("[2] Factoring OPC-UA RSA-2048 cert (self-signed, 10-year validity)")
    forged_priv = factor_opcua_cert(pubkey)
    print("    OPC-UA server key recovered")

    print("[3] Opening SecureChannel — impersonating engineering workstation")
    channel = open_secure_channel(pubkey, POLICY_BASIC256SHA256, forged_priv)
    print(f"    Channel: {channel}")

    print("[4] Issuing OPERATE commands to industrial equipment")
    ops = [
        (NODE_VALVE_POSITION, 100.0, "Valve fully open"),
        (NODE_BREAKER_STATE, True, "Breaker OPEN"),
        (NODE_SETPOINT, 999.0, "Temperature setpoint → max"),
    ]
    for node, val, desc in ops:
        result = write_node_value(channel, node, val)
        print(f"    {desc}: {result}")

    print("[5] Decrypting captured OPC-UA historian traffic")
    plaintext = decrypt_opcua_session(b"<captured-pcap>", forged_priv)
    print("    All process data, alarm states, setpoint history exposed")

    print("\n[*] All 5 OPC-UA security policies are RSA-based:")
    for p in [POLICY_BASIC128RSA15, POLICY_BASIC256SHA256, POLICY_AES256SHA256RSAPSS]:
        print(f"    {p}")
    print("    ICS lifecycle: 20-40 years. No hot-patching for crypto agility.")
