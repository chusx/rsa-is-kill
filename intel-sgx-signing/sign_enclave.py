"""
sign_enclave.py

Intel SGX enclave signing pipeline — what a production team runs to
build + sign a release .so enclave and emit a SIGSTRUCT that Intel CPUs
will admit as a "trusted" enclave. The RSA-3072 primitive (SGX requires
exactly modulus-3072, public exponent 3) is in `sgx_enclave_rsa3072.c`;
this file is the `sgx_sign` invocation and the HSM-backed two-step
signing ceremony that most vendors run.

Users of this pipeline:
  - Anjuna, Fortanix, Gramine, Occlum, Edgeless — SGX runtime vendors
  - Confidential computing offerings on Azure DCsv3 VMs and Alibaba
    Cloud ECS c7t (both still expose client-SGX to customer enclaves)
  - SGX-based DRM (Netflix 4K on Windows with Widevine L1 via SGX
    on Intel iGPUs), Signal Secure Value Recovery
  - Provable fairness services (BitMEX, PlatON), ChainLink OCR2.0 +
    Fair Sequencing Service enclaves
"""

import json
import subprocess
import os
import hashlib


SGX_SDK = os.environ.get("SGX_SDK", "/opt/intel/sgxsdk")
SGX_SIGN = f"{SGX_SDK}/bin/x64/sgx_sign"


def gendata(enclave_so: str, config_xml: str, dat_out: str) -> None:
    """
    Step 1 of the two-step signing ceremony: `sgx_sign gendata`
    produces the SIGSTRUCT digest that needs to be RSA-signed.  The
    enclave .so never leaves the dev workstation, but the resulting
    .dat is small and goes to the offline signing HSM.
    """
    subprocess.check_call([
        SGX_SIGN, "gendata",
        "-enclave", enclave_so,
        "-config", config_xml,
        "-out", dat_out,
    ])


def hsm_sign_sigstruct(dat_path: str, sig_path: str) -> None:
    """
    Step 2: signing officer transports `dat_path` to the offline
    signing ceremony HSM (typically Thales Luna or Fortanix DSM) and
    invokes PKCS#11 C_Sign with mechanism CKM_RSA_X_509 (raw RSA, no
    padding — SGX SIGSTRUCT format is fixed). The Intel-mandated
    modulus is 3072 bits, public exponent e=3. The resulting 384-byte
    signature comes back over sneakernet.

    Enforces per-vendor key partitioning: Production Signer key is
    separate from Release-Candidate and Debug keys, with separate
    RACF/PKCS#11 authorization users.
    """
    from sgx_enclave_rsa3072 import pkcs11_sign_sgx_sigstruct
    sig = pkcs11_sign_sgx_sigstruct(
        hsm_slot="OFFLINE_SGX_CEREMONY",
        key_label="ENCLAVE_PROD_SIGNER_2026",
        sigstruct_digest_path=dat_path,
    )
    assert len(sig) == 384, "SGX RSA-3072 signature must be 384 bytes"
    with open(sig_path, "wb") as f:
        f.write(sig)


def catsig(enclave_so: str, config_xml: str, dat: str, sig: str,
            signed_out: str) -> None:
    """Step 3: splice the HSM-produced signature back into the SIGSTRUCT."""
    subprocess.check_call([
        SGX_SIGN, "catsig",
        "-enclave", enclave_so,
        "-config", config_xml,
        "-key", "/dev/null",          # ignored with -unsigned/-catsig
        "-sig", sig,
        "-unsigned", dat,
        "-out", signed_out,
    ])


def verify_signed(enclave_signed: str) -> dict:
    """
    Extract SIGSTRUCT and dump MRSIGNER + MRENCLAVE.  MRSIGNER is the
    SHA256 of the modulus — enclaves that grow across versions have
    stable MRSIGNER but shifting MRENCLAVE, which is how sealing keys
    stay valid across upgrades (KEYPOLICY=MRSIGNER sealing).
    """
    out = subprocess.check_output([SGX_SIGN, "dump",
                                    "-enclave", enclave_signed,
                                    "-dumpfile", "/dev/stdout"])
    return parse_dumpfile(out)


def build_and_sign(project: str, version: str) -> str:
    enclave_so  = f"build/{project}-{version}.so"
    signed_out  = f"build/{project}-{version}.signed.so"
    dat         = f"build/{project}-{version}.sigstruct.dat"
    sig         = f"build/{project}-{version}.sigstruct.sig"
    cfg         = f"enclave_config/{project}.xml"

    gendata(enclave_so, cfg, dat)
    hsm_sign_sigstruct(dat, sig)
    catsig(enclave_so, cfg, dat, sig, signed_out)

    meta = verify_signed(signed_out)
    print(json.dumps(meta, indent=2))
    return signed_out


def parse_dumpfile(raw: bytes) -> dict: ...


# ---- Breakage ----
#
# SGX enclaves anchor their identity in MRSIGNER — SHA-256(modulus).
# Every attestation quote (EPID or DCAP) reports MRSIGNER + MRENCLAVE
# so relying parties can check "was this enclave signed by Signal's
# Secure Value Recovery signer?" or "Was this enclave signed by
# Chainlink's OCR signer?".
#
# An RSA factoring attack on a production MRSIGNER key lets an
# attacker mint a totally different enclave binary that reports the
# SAME MRSIGNER as the legitimate one. All SGX-based trust stores
# (Signal phone-number recovery, Netflix Widevine L1, ChainLink OCR
# quorum verification) collapse — an attacker's enclave produces
# attestations that relying parties have no way to distinguish from
# authentic ones. MRSIGNER-based sealing keys also come into scope:
# data sealed under MRSIGNER can be unsealed by any enclave sharing
# the MRSIGNER, which is now forgeable.
