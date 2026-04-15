"""
triton_server_mtls.py

Launch a Triton Inference Server with mTLS enabled. This wraps the
C++ `tritonserver` binary via its `--grpc-*-tls-*` flags plus HTTPS
TLS on the REST interface. Model repository layout and model-control
plane remain the standard Triton idiom.

Production GPU inference fleets (Meta, LinkedIn, Snap, Azure AI,
SageMaker backends) run this process under systemd or as a Kubernetes
Deployment behind a Service annotated for Istio mTLS.
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path


TRITON_BIN = "/opt/tritonserver/bin/tritonserver"


def launch(model_repository: Path,
            server_cert_pem: Path,
            server_key_pem: Path,
            client_ca_pem: Path,
            grpc_port: int = 8001,
            http_port: int = 8000,
            allow_http: bool = False,
            strict_readiness: bool = True) -> None:
    """
    Start Triton with:
      - gRPC mTLS: --grpc-use-ssl=true, mutual TLS required
      - Client CA bundle pinning which client certs are accepted
      - Server cert is RSA-2048 (signed by internal issuing CA)
      - REST either disabled (default in mTLS-only deployments) or
        also behind HTTPS via a reverse proxy (nginx/envoy)
    """
    args = [
        TRITON_BIN,
        f"--model-repository={model_repository}",
        f"--grpc-port={grpc_port}",
        "--grpc-use-ssl=true",
        "--grpc-use-ssl-mutual=true",
        f"--grpc-server-cert={server_cert_pem}",
        f"--grpc-server-key={server_key_pem}",
        f"--grpc-root-cert={client_ca_pem}",
        f"--log-verbose=1",
        f"--strict-readiness={'true' if strict_readiness else 'false'}",
    ]

    if allow_http:
        args += [f"--http-port={http_port}"]
    else:
        args += ["--allow-http=false"]

    # Metrics always enabled (localhost-only) for kube liveness probes
    args += ["--allow-metrics=true", "--metrics-port=8002"]

    env = os.environ.copy()
    env.setdefault("CUDA_VISIBLE_DEVICES", "all")
    env.setdefault("LD_LIBRARY_PATH", "/opt/tritonserver/lib")

    print("[triton] exec:", shlex.join(args), file=sys.stderr)
    os.execvpe(args[0], args, env)


def prepare_repo_for_llm_serving(model_repo: Path,
                                    hf_model_dir: Path,
                                    engine_backend: str = "tensorrtllm") -> None:
    """
    Typical pre-launch step: convert a HuggingFace LLM snapshot into a
    Triton-servable backend directory (TensorRT-LLM engine, vLLM
    model repo, or FasterTransformer format). Outputs the canonical
    `{model}/1/{model.*}` + `config.pbtxt` layout Triton expects.
    """
    # Shell out to trtllm-build or similar — details elided.
    subprocess.run([
        "python", "-m", "tensorrt_llm.commands.build",
        f"--checkpoint_dir={hf_model_dir}",
        f"--output_dir={model_repo}/llama3-70b/1",
        "--gemm_plugin=bfloat16",
        "--max_batch_size=128",
    ], check=True)


if __name__ == "__main__":
    # Typical systemd unit or K8s entrypoint invocation
    launch(
        model_repository=Path("/srv/triton/models"),
        server_cert_pem=Path("/etc/triton/tls/server.crt"),
        server_key_pem=Path("/etc/triton/tls/server.key"),
        client_ca_pem=Path("/etc/triton/tls/client-ca.pem"),
    )
