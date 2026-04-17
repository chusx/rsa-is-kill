# triton-inference-mtls — RSA in NVIDIA Triton Inference Server deployments

**Standard:** gRPC/HTTPS mTLS; Istio / Envoy sidecars; NVIDIA Triton Inference Server
**Industry:** Production AI inference — recommendation, ranking, vision, LLM serving
**Algorithm:** RSA-2048/3072/4096 (leaf certs + issuing CAs), ECDSA-P256 alternate

## What it does

NVIDIA Triton Inference Server is the dominant open-source runtime for
serving ONNX, TensorRT, PyTorch, TensorFlow, FasterTransformer, TRT-LLM,
and vLLM models in production. It exposes:

- gRPC endpoint (default port 8001) — used by most high-throughput clients
- HTTP/REST endpoint (8000)
- Metrics/health (8002)

In any non-toy deployment, Triton fronts behind mTLS via:
- Triton's built-in gRPC server TLS (`--grpc-server-tls-cert`,
  `--grpc-tls-certificate-file`) with RSA server certs
- Istio sidecars (Envoy) doing mTLS between client apps and Triton pods
- AWS ALB / GCP GLB / Azure AG TLS termination with RSA certs from
  the cloud's managed CA (ACM, Google-managed certs, Azure Key Vault)
- NGINX / HAProxy reverse proxies for on-prem GPU clusters

Who runs Triton at scale:
- Meta — ranking, recommendation, CV inference across billions of QPS
- LinkedIn — feed ranking, people-you-may-know
- Snap — AR Lenses ML inference
- Microsoft — Bing, Ads, Office AI features
- Amazon — SageMaker Inference endpoints (Triton under the hood for
  many "Large Model Inference" containers)
- Every major CSP's managed inference endpoints (Azure AI Foundry,
  Vertex AI Online Prediction, SageMaker)
- In-house LLM serving at Anthropic, OpenAI, Cohere, Mistral (custom
  forks + wrapped), plus enterprise on-prem deployments

Client-side mTLS certs are almost universally RSA:
- Developer / service identity via Istio CA (defaults to RSA-2048)
- Cloud-issued client certs for cross-cluster inference calls
- Internal PKI certs issued by Vault PKI or cert-manager with
  RSA-2048 (default) or RSA-4096

## Why it's stuck

- Triton is the standard AI serving path across cloud and on-prem. A
  single Triton fleet often fronts thousands of models.
- The mTLS PKI underneath is the same boring corporate RSA PKI that
  fronts every other microservice — meaning the AI-infra blast radius
  is the same as the rest of the org's service mesh.
- Istio default CA issues RSA leaves; `citadel` / `istiod` default
  configurations use RSA-2048.
- AWS Private CA, GCP CAS, Azure Private CA default to RSA roots for
  customer-owned private PKIs fronting AI workloads.
- Client SDK certs pinned to RSA-2048 are embedded in mobile apps
  invoking inference endpoints — rotation costs are AppStore roundtrips.

## impact

- **Prompt / PII interception at scale**: Forge a client cert under the
  org's internal CA → appear to Triton as the legitimate gateway; MitM
  the gRPC stream; record every inference request (user prompts, PII,
  medical images, financial data) and every response.
- **Rogue inference backend**: Forge a server cert for
  `triton.mycompany.internal` → client apps send traffic to attacker's
  Triton clone, which returns attacker-chosen outputs (e.g., flipped
  recommendation rankings, biased safety-filter results, or subtly
  wrong medical-AI outputs).
- **Confidential inference bypass**: Enterprise "confidential AI"
  configurations assume mTLS+attestation provides end-to-end assurance
  between client and the confidential Triton pod. Forge RSA → break the
  chain at the client-to-gateway hop even with working TEE attestation
  on the far side.
- **Stolen model IP**: Triton endpoints that serve proprietary fine-tuned
  LLMs exposure their logits/tokens over gRPC. MitM captures full
  generations → model distillation / cloning from production queries.
- **Poisoning retrieval-augmented generation**: If the RAG vector-db
  backend is behind its own mTLS, a factored CA lets attackers stand up
  a poisoned vector DB appearing as the legitimate one.

## Code

- `triton_server_mtls.py` — launch Triton with mTLS enabled, RSA-backed
  server cert + client CA bundle.
- `triton_client_mtls.py` — high-level Python client that dials Triton
  with an RSA client cert (the shape of calling code in a Flink job,
  an Airflow DAG, or a Django app's inference microservice).
- `istio_peerauth.yaml` — Istio mTLS policy and `DestinationRule` that
  pins RSA cert rotation for a Triton service.
