# coco-attestation — RSA in Confidential Containers (CoCo) for AI

**Standard:** CNCF Confidential Containers, Kata Containers, Trustee / KBS (Key Broker Service)
**Industry:** Confidential AI training + inference on Kubernetes, multi-tenant MLOps
**Algorithm:** RSA-2048/3072 (KBS TLS + attestation token signing), Ed25519/ECDSA permitted

## What it does

Confidential Containers (CoCo) is the CNCF project bringing confidential
computing to Kubernetes: unmodified pods run inside enclave-style TEEs
(TDX, SNP, IBM Secure Execution, Arm CCA) via Kata. The security story
requires an attestation chain from pod → enclave → verifier → secret
release, implemented by the CoCo Trustee stack (KBS + Attestation Service
+ Reference Value Provider Service).

Deployment:
- Red Hat OpenShift Sandboxed Containers (Confidential Containers profile)
- Azure Confidential AKS (preview)
- GCP Anthos Confidential Containers
- IBM Cloud on Secure Execution (Z / LinuxONE for AI workloads)
- Oracle OCI Confidential Kubernetes
- In-house at AI labs that need multi-tenant GPU clusters with strong
  isolation (e.g., Together AI, Lambda, CoreWeave's confidential beta)

Flow on every pod start:
  1. Kata VM boots a rootfs with a minimal init + attestation agent.
  2. Attestation Agent gathers TEE evidence (TDX quote, SNP report,
     optionally NVIDIA GPU attestation for H100 nodes).
  3. AA connects to Trustee KBS (mTLS; KBS cert RSA-2048).
  4. KBS sends evidence to Attestation Service; AS returns a signed
     attestation token (RS256 JWT, RSA-2048 or RSA-3072 issuer key).
  5. AA presents token + a resource ID ("give me the model weight key
     for `openai/whisper-large-v3`") to KBS.
  6. KBS checks AS token, evaluates resource policy, returns wrapped
     resource (AES-GCM) plus the wrapping key sealed to the TEE via
     attestation-gated release.
  7. AA unwraps and delivers the resource into the pod's filesystem
     (`/run/kata-containers/secret/...`).

The three RSA-critical assets in this pipeline:

- **KBS TLS cert** (RSA-2048) — AA pins this on first use via `aa-kbc-params`.
- **Attestation Service token-signing key** (RSA-2048 or RSA-3072 RS256
  issuer).
- **Vendor attestation chains** (Intel SGX/TDX Root CA RSA-3072, AMD ASK/ARK
  ECDSA but often wrapped in RSA certs, NVIDIA Root RSA-4096) — see the
  dedicated TDX and NVIDIA dirs.

## Why it's stuck

- CoCo Trustee uses PKCS#1 v1.5 RS256 by default for attestation tokens.
- KBS TLS certs are pinned in AA configuration that ships inside container
  images / peer-pods rootfs — rotation requires rolling the image fleet.
- AI training jobs can run for weeks on confidential nodes; the tokens
  issued at the start of the job have long validity windows during which
  they must not be forgeable.
- Multi-cloud deployments standardize on CoCo for portability; an RSA
  compromise breaks cross-cloud AI trust simultaneously.

## impact

- **Multi-tenant GPU cluster breach**: Forge attestation tokens → a
  tenant pod on a shared AI GPU cluster appears as a legitimate
  confidential pod. KBS releases wrapped keys and customer prompts /
  weights to attacker pods.
- **Bedrock-style model hosting**: Foundation-model vendors ship
  proprietary weights to confidential clusters with policies "release
  weights only to pods with MRTD = X on node attested at TCB Y."
  Forged RSA → weights released to uncontrolled pods.
- **Fine-tuning data theft**: Enterprise fine-tuning on CoCo: training
  data is encrypted in S3, decryption key held by KBS, released only to
  attested pods. Break RSA → data exfiltration by malicious cluster operators.
- **CI/CD supply-chain pivot**: CoCo is used to run build steps under
  attestation. Forged attestation lets attackers present tampered build
  outputs (AI model artifacts) as "built in an attested environment."

## Code

- `kbs_client.py` — Attestation Agent view: collect evidence, call KBS
  `/auth` + `/resource/{id}`, unwrap received key material.
- `kbs_policy.rego` — example KBS Resource Policy gating model-weight
  key release on attestation claims.
- `kbs_server_skel.go` — KBS server skeleton: mTLS (RSA-2048 cert),
  attestation-token verify (RS256), policy evaluation, resource release.
