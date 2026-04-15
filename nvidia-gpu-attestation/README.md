# nvidia-gpu-attestation — RSA in confidential AI compute on NVIDIA GPUs

**Standard:** NVIDIA Remote Attestation Service (NRAS); Hopper/Blackwell Confidential Compute
**Industry:** Confidential AI — training on untrusted clouds, regulated-data inference, private fine-tuning
**Algorithm:** RSA-3072 (NVIDIA device identity + cert chain), ECDSA-P384 alternates in some reports

## What it does

NVIDIA Hopper (H100, H200) and Blackwell (B100, B200, GB200) GPUs ship with
Confidential Compute (CC) mode. In CC mode, the GPU refuses to expose its
memory or PCIe bus to the hypervisor; the CPU-side TEE (Intel TDX or AMD SEV-SNP)
and the GPU attest jointly that the AI workload runs in a trusted boundary.

Attestation flow:

1. CVM (Confidential VM) boots into TDX/SNP. CPU side attests.
2. The guest asks the GPU's on-die Remote Attestation Engine for a report:
   GPU firmware version, VBIOS hash, CC mode on/off, nonce.
3. The GPU signs the report with its device-unique RSA-3072 attestation key,
   which chains up through a NVIDIA-issued intermediate (RSA-3072) to the
   NVIDIA Attestation Root (RSA-4096), burned into every H100/H200/B100.
4. The CVM forwards the report to NRAS (`nras.attestation.nvidia.com`) OR to
   a local verifier. NRAS returns a signed JWT (RS256) asserting "this GPU
   is a genuine H100 in CC mode running firmware X."
5. The relying party (Azure Confidential GPU, Google CCE, AWS Nitro+H100
   preview, or a private deployment) releases model weights / decryption keys
   to the CVM only after the combined CPU+GPU attestation checks out.

Every tenant on Azure Confidential AI, Google Confidential Space with H100,
and OCI Confidential GPU goes through this path for every VM start. Apple's
Private Cloud Compute uses a parallel scheme on Apple Silicon; Meta and xAI
run similar in-house schemes on their H100 clusters for regulated-tenant work.

## Why it's stuck

- NVIDIA Attestation Root is burned into H100 fuses at manufacture; fielded
  GPUs cannot swap root. H100 life in datacenters is 5-7 years; Blackwell
  longer. Racks bought in 2024 will be running the same root in 2030.
- NRAS signs JWTs with RSA-3072. Enterprise verifiers (Azure Attestation,
  GCP Confidential Space) pin the NRAS public key. Rotation requires
  customer-side updates across every policy.
- The full chain is documented in NVIDIA's Confidential Compute Deployment
  Guide; the root pubkey is public, distributed with the nvtrust / Verifier
  SDK, making it broadly available for offline factoring research.
- CC-mode GPU firmware is itself NVIDIA-signed with RSA; breaking the root
  breaks not just attestation but the entire firmware chain-of-trust on
  the GPU.

## impact

- **Confidential AI tenancy breach**: Azure Confidential GPU, Google CCE,
  OCI — pitched to banks / health / intel customers who send private data
  to cloud for inference. Forge NVIDIA attestation → CVM appears CC-protected
  while actually exposing GPU memory to the hypervisor / cloud operator.
  Tenant data (model weights, training data, user prompts) becomes
  extractable by the cloud provider or attackers with hypervisor access.
- **Model exfiltration on untrusted clouds**: Foundation-model providers
  (OpenAI, Anthropic, Mistral, Meta) that deploy proprietary weights onto
  customer GPUs rely on CC-mode attestation to prevent weight theft. Forged
  attestation means a malicious customer's GPU can be reported as
  CC-protected while in fact dumping memory to extract weights.
- **Regulated-data AI violations**: HIPAA, GDPR Article 32, EU AI Act
  high-risk deployments increasingly mandate attested execution environments
  for PII-involved inference. Forged NVIDIA attestation makes the audit
  trail accept non-compliant deployments.
- **Sovereign-AI policy bypass**: EU Sovereign Cloud and UAE / Saudi
  sovereign GPU deployments contractually require attested CC mode. Factor
  NRAS → attest any hardware (even non-NVIDIA, even simulation) as a genuine
  H100 in CC mode.
- **Supply-chain counterfeits**: Grey-market H100s with tampered firmware
  can be made to look genuine to NRAS. Only the root-of-trust chain
  distinguishes authentic from counterfeit; break it and counterfeit
  detection collapses.

## Code

- `nvml_attestation.c` — call into NVIDIA Verifier SDK to fetch a report,
  verify its RSA-3072 signature against the device cert chain.
- `nras_client.py` — CVM-side code that gathers the GPU attestation report,
  submits to NRAS, parses the returned JWT (RS256) and checks claims.
- `attestation_report.h` — layout of the NVIDIA GPU attestation report as
  produced by the Hopper attestation engine.
