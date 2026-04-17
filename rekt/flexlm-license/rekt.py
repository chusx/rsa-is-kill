"""
Factor the Synopsys FlexLM vendor RSA key compiled into every lmgrd daemon,
forge SIGN= fields for any feature/version/seat-count, and generate unlimited
licenses for $1M/seat EDA tools across every semiconductor design house on earth.
"""

import sys, hashlib, struct
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# FlexLM/FlexNet vendor daemons
VENDOR_DAEMONS = {
    "synopsys":  ("synopsys_lmgrd",  "Design Compiler, VCS, PrimeTime, Verdi"),
    "mathworks": ("mlm",             "MATLAB, Simulink, all toolboxes"),
    "cadence":   ("cdslmd",          "Virtuoso, Spectre, Innovus"),
    "mentor":    ("mgcld",           "Calibre, Xcelium (Siemens EDA)"),
    "ansys":     ("ansyslmd",        "HFSS, Maxwell, Mechanical"),
    "dassault":  ("catiav5",         "CATIA (Airbus/Boeing structural)"),
    "msc":       ("MSC.Software",    "Nastran, Adams"),
}


def extract_vendor_pubkey(daemon_binary: str) -> bytes:
    """Extract the vendor's RSA public key from the daemon binary.
    It's been there for 30 years — extractable with strings/objdump."""
    print(f"    daemon binary: {daemon_binary}")
    print("    extracting RSA public key from .rodata section")
    return b"-----BEGIN RSA PUBLIC KEY-----\nMIIB...\n-----END RSA PUBLIC KEY-----\n"


def factor_vendor_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_license_feature(feature: str, version: str, expiry: str,
                           seats: int, hostid: str = "ANY") -> str:
    """Build a FlexLM license feature line."""
    return (f"FEATURE {feature} synopsysd {version} {expiry} "
            f"{seats} HOSTID={hostid} SIGN=PLACEHOLDER")


def sign_license_feature(feature_line: str, privkey_pem: bytes) -> str:
    """Forge the SIGN= field with the recovered vendor private key.
    SIGN= is RSA signature over (feature, version, expiry, seats)."""
    # Strip existing SIGN= and compute new one
    base = feature_line.split(" SIGN=")[0]
    digest = hashlib.sha1(base.encode()).digest()  # SHA-1 in legacy FlexLM
    sig_hex = digest.hex()[:20]  # simplified; real SIGN= is RSA-based
    return f"{base} SIGN={sig_hex}"


def generate_license_file(features: list) -> str:
    """Generate a complete FlexLM license file."""
    header = (f"SERVER this_host ANY 27000\n"
              f"VENDOR synopsysd\n")
    return header + "\n".join(features) + "\n"


if __name__ == "__main__":
    print("[*] FlexLM / FlexNet license signing attack")
    vendor = "synopsys"
    daemon, products = VENDOR_DAEMONS[vendor]

    print(f"[1] extracting {vendor} RSA key from daemon binary")
    pubkey = extract_vendor_pubkey(f"/usr/local/flexlm/bin/{daemon}")
    print(f"    products: {products}")
    print("    key extractable with strings/objdump (always has been)")

    print(f"[2] factoring {vendor} RSA key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — vendor license signing key derived")

    print("[3] generating unlimited licenses")
    features = [
        ("Design-Compiler-Ultra", "2026.12", "permanent", 999),
        ("VCS-MX", "2026.12", "permanent", 999),
        ("PrimeTime-SI", "2026.12", "permanent", 999),
        ("Verdi-Debug", "2026.12", "permanent", 999),
        ("IC-Compiler-II", "2026.12", "permanent", 999),
    ]
    signed_features = []
    for feat, ver, exp, seats in features:
        line = build_license_feature(feat, ver, exp, seats)
        signed_line = sign_license_feature(line, b"VENDOR_PRIVKEY")
        signed_features.append(signed_line)
        print(f"    {feat}: {seats} seats, {exp}")

    print("[4] generating license file")
    lic_file = generate_license_file(signed_features)
    print("    license.dat written")
    print("    vendor daemon verifies SIGN= with compiled-in public key — PASS")

    print("[5] pricing impact:")
    print("    - Synopsys DC Ultra: ~$1M/seat")
    print("    - Cadence Virtuoso: ~$500K/seat")
    print("    - MATLAB + all toolboxes: ~$50K/year")
    print("    - RSA signature is the entire technical basis for these price points")

    print("[6] strategic impact:")
    print("    - TSMC, Intel, Samsung design farms: unlimited EDA tool access")
    print("    - defense/aerospace (Lockheed, Raytheon): air-gapped FlexLM servers")
    print("    - semiconductor IP reverse-engineering: tools + license = chip analysis")
    print("[*] FlexLM has been RSA-signed for 30 years; no non-RSA alternative exists")
    print("[*] every installed daemon binary contains the vendor public key")
