# sigstore-model-signing — RSA in ML model artifact attestation

**Standard:** Sigstore (OpenSSF), model-transparency-SIG, SLSA for ML, model-signing v1
**Industry:** ML/MLOps — model registries, inference platforms, supply-chain integrity
**Algorithm:** RSA-2048/3072/4096 (Fulcio code-signing certs, TUF roots), ECDSA/Ed25519 alternates

## What it does

The OpenSSF Model Signing project (model-signing v1, 2024) extends Sigstore's
code-signing pipeline to ML model weights. A producer signs:

- The safetensors / GGUF / PyTorch / ONNX file hashes (manifest over every
  shard of a multi-shard model)
- The model card (claims about training data, eval results, licenses)
- The SLSA provenance attestation (what hardware/software built the model)

Using a Sigstore-issued Fulcio X.509 cert (the keyless flow: OIDC identity
from GitHub / Google / Sigstore's free instance + short-lived cert) OR a
long-lived RSA key held by the organization. The signature is logged to
Rekor (a Sigstore transparency log, which itself is TUF-backed).

Verifiers are integrated into:

- **Hugging Face Hub** — model signing badges, commit signature verification
- **Google Vertex AI Model Registry** — SLSA v1 provenance + signing
- **Kaggle / Google AI Studio**
- **MLflow 2.x** — signed model artifacts
- **KServe / KFServing** — admission control requires valid model signature
- **NVIDIA NGC** — signed containers + signed model checkpoints
- **PyTorch Hub** — TUF-backed signed release metadata
- **SLSA-for-models** provenance verification in CI (SLSA v1.0 generic)

Underneath: Fulcio issues X.509 certs with RSA-2048 or ECDSA-P256 leaves.
Organizations running Sigstore in-house (Google, Datadog, etc.) operate
private Fulcio instances with RSA roots. The TUF repository that underpins
Sigstore's trust root is itself signed with a mix of RSA and Ed25519 keys.

## Why it's stuck

- Sigstore's public-good instance (`sigstore.dev`) uses an RSA-2048 TUF root;
  rotation happens via TUF's key-rotation ceremony but the root of trust in
  every Sigstore client binary ships with RSA key IDs baked in.
- Fulcio issues RSA-backed certs to requestors who ask for them (the client
  picks algorithm). The Kubernetes / Tekton / GitHub Actions signers configured
  across the ecosystem default to RSA in many deployments.
- Signed model artifacts live alongside the model forever: a 70B-param model
  released in 2024 and signed with an RSA-2048 leaf via Fulcio will have that
  signature read by downstream verifiers for years.
- Rekor transparency log entries chain via Merkle trees with RSA-signed
  checkpoints. Log integrity depends on the log operator's RSA key.

## impact

- **Supply-chain poisoning of foundation models**: Forge a Fulcio-issued
  cert under a Hugging Face organization identity (e.g., `meta-llama`,
  `mistralai`, `google`). Publish a model with the org's expected signer.
  Downstream CI/CD accepts the weights as legitimate. Attackers inject
  backdoored LLM weights into Vertex AI, Bedrock, or self-hosted Ollama
  pipelines.
- **Model registry impersonation**: Google Vertex, HuggingFace, NGC, and
  KServe admission policies accept models with valid signatures matching
  org OIDC identity. A factored CA or TUF key means attackers satisfy
  org-identity policy arbitrarily.
- **SLSA provenance forgery**: SLSA-for-models records the hardware
  (e.g., "4096 H100 GPUs, facility X") and dataset version. Forge the
  in-toto attestation → a model claimed as trained on licensed data can
  be substituted with one trained on stolen data, or vice versa.
- **Rekor log forgery**: If the Rekor operator's signing key is factored,
  attackers can produce log-inclusion proofs for entries that were never
  actually logged. Defeats the primary defense of "keyless" Sigstore (which
  relies on transparency to compensate for short-lived certs).
- **Regulated-industry model deployment**: FDA SaMD AI guidelines (2024)
  and EU AI Act Article 15 require tamper-evident records of model versions
  in medical and high-risk AI. Model signing is the typical implementation.
  Forged signatures = audit-trail collapse.

## Code

- `sign_model.py` — producer-side: manifest a multi-file model checkpoint,
  sign with Sigstore (Fulcio RSA cert), upload bundle to Rekor.
- `verify_model.py` — consumer-side (runs in Hugging Face Hub, KServe
  admission controller, etc.): verify model manifest against expected
  signer identity via Fulcio cert + Rekor inclusion proof.
- `intoto_predicate.json` — example SLSA v1 provenance predicate for an
  LLM training run (GPU cluster identity, dataset version, training code
  commit), as signed by the model producer.
