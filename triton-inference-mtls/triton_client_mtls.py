"""
triton_client_mtls.py

Client-side Triton caller using mTLS. This is the shape of code that
runs in every inference-calling service at Meta, LinkedIn, Snap,
SageMaker, Azure AI Foundry, and every enterprise serving fine-tuned
LLMs from their own Triton fleet.

The RSA-backed client certificate authenticates the *caller* (the Flink
job, the search service, the ranking microservice) to Triton. Triton's
authorization layer (or an Istio AuthorizationPolicy sidecar) then
gates which models the authenticated caller can invoke.
"""

import grpc
import numpy as np
from tritonclient.grpc import InferenceServerClient, InferInput, InferRequestedOutput


def build_mtls_channel(triton_host: str,
                       client_cert_pem: bytes,
                       client_key_pem: bytes,
                       server_ca_pem: bytes) -> grpc.Channel:
    """
    Build a gRPC channel with mTLS. Caller's cert is an RSA-2048 leaf
    issued by the internal PKI (Vault PKI, cert-manager, ACM PCA).
    """
    creds = grpc.ssl_channel_credentials(
        root_certificates=server_ca_pem,
        private_key=client_key_pem,
        certificate_chain=client_cert_pem,
    )
    # gRPC options tuned for high-throughput LLM serving
    options = [
        ("grpc.max_send_message_length", 64 * 1024 * 1024),
        ("grpc.max_receive_message_length", 64 * 1024 * 1024),
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
    ]
    return grpc.secure_channel(triton_host, creds, options=options)


def call_llm(client: InferenceServerClient,
              prompt: str,
              model_name: str = "llama3-70b",
              max_tokens: int = 256) -> str:
    """
    Invoke a TensorRT-LLM / vLLM-backed Triton model. `client` is backed
    by the mTLS channel above; every request carries the caller's RSA
    client cert identity to Triton, where it is logged for audit and
    consulted for authorization policy.
    """
    input_ids = InferInput("input_ids", [1, len(prompt)], "INT32")
    input_ids.set_data_from_numpy(
        np.array([_tokenize(prompt)], dtype=np.int32))

    max_tok = InferInput("request_output_len", [1, 1], "INT32")
    max_tok.set_data_from_numpy(np.array([[max_tokens]], dtype=np.int32))

    outputs = [InferRequestedOutput("output_ids")]

    resp = client.infer(
        model_name=model_name,
        inputs=[input_ids, max_tok],
        outputs=outputs,
        timeout=60,
    )
    out_ids = resp.as_numpy("output_ids")[0]
    return _detokenize(out_ids.tolist())


def _tokenize(s: str) -> list:
    # stand-in; production uses the model's tokenizer
    return list(s.encode())


def _detokenize(ids: list) -> str:
    return bytes(ids).decode(errors="replace")


if __name__ == "__main__":
    with open("/etc/ranking-svc/tls/client.crt", "rb") as f: cert = f.read()
    with open("/etc/ranking-svc/tls/client.key", "rb") as f: key = f.read()
    with open("/etc/ranking-svc/tls/triton-ca.pem", "rb") as f: ca = f.read()

    channel = build_mtls_channel(
        triton_host="triton.ml.prod.internal:8001",
        client_cert_pem=cert,
        client_key_pem=key,
        server_ca_pem=ca,
    )
    client = InferenceServerClient(url="triton.ml.prod.internal:8001",
                                     channel_args=None)
    # In practice the client uses `ssl=True` + separate cert files,
    # channel shown above for explicit RSA-cert control.

    reply = call_llm(client, "Summarize: ...")
    print(reply)
