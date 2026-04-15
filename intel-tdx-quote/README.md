# intel-tdx-quote — RSA in Intel TDX attestation for confidential AI

**Standard:** Intel TDX 1.5+, DCAP (Data Center Attestation Primitives)
**Industry:** Confidential VMs for AI, regulated-data inference, privacy-preserving training
**Algorithm:** RSA-3072 (PCK cert chain), ECDSA-P256 (quote signing), RSA-2048 (PCCS TLS)

## What it does

Intel TDX (Trust Domain Extensions) provides confidential VMs on 4th/5th-gen
Xeon (Sapphire Rapids / Emerald Rapids / Granite Rapids). Every TD can produce
a *quote* — a signed attestation of its measurement (MRTD + RTMRs) that a
relying party uses to decide whether to release secrets (model weights,
training data, customer PII) into the TD.

The DCAP quote flow relies on two distinct RSA dependencies that both collapse
under factoring:

1. **PCK Certificate Chain (RSA)** — each TDX-capable CPU has a Provisioning
   Certification Key (PCK) cert issued by Intel. The PCK cert chain is:

       Intel SGX/TDX Root CA (RSA-3072, offline in Intel HSM, Santa Clara)
            |
       Intel SGX/TDX Processor CA (RSA-3072)
            |
       Per-CPU PCK leaf (ECDSA-P256, but signed under the RSA chain above)

   The Root CA pubkey is hardcoded in every DCAP-linked quoting library and
   every attestation verifier (Azure Attestation Service, GCP Confidential
   Space, AWS Nitro-TDX, every on-prem Fortanix / HashiCorp verifier).

2. **PCCS / Attestation Service TLS (RSA)** — the Provisioning Certificate
   Caching Service (which distributes PCK certs and TCB info JSON to
   enterprises running DCAP in-house) is typically fronted by RSA-2048
   TLS. Intel Trusted Services Attestation Service (previously IAS) and
   third-party hosted PCCS (Azure PCCS, Phala Cloud, etc.) all serve
   over RSA TLS today.

Every Azure Confidential Computing TDX VM, every Google Confidential Space
with TDX, every OpenAI / Anthropic / Microsoft confidential-inference workload
on Intel goes through this RSA-backed chain on boot and on key release.

## Why it's stuck

- Intel SGX/TDX Root CA is burned into the DCAP verification logic. Linked
  into `libsgx-dcap-quoteverify`, `sgx-dcap-quote-verification` C libraries,
  Azure AttestationGuestSvc, GCP CS binaries. Rotation is a multi-year rollout.
- Sapphire Rapids / Emerald Rapids CPUs in datacenters have 7-10 year lives;
  their fused provisioning IDs reference the current PCK chain.
- TCB info recovery files (telling verifiers which CPUs are patched against
  which vulns) are RSA-signed by Intel. Every security advisory update relies
  on the same key.
- Apple Private Cloud Compute, when it launched confidential AI at
  datacenter scale, chose a TDX-alike pattern for auditability.

## impact

- **Fake confidential AI tenancy**: Azure Confidential AI, GCP Confidential
  Space, OCI Confidential AI all sell "your prompts and model weights never
  leave a hardware-enforced enclave" to banks, hospitals, government.
  Forge PCK chain → attest arbitrary hardware (including hypervisor-
  controlled non-TD VMs) as genuine TDX → tenant data fully exposed.
- **Private-preview model exfiltration**: Foundation-model vendors hand out
  proprietary weights only to customers running attested confidential
  compute. Forge the chain → any VM can receive weights.
- **Cross-tenant MEV / insider trading**: Confidential TDX is marketed to
  trading firms for isolating order flow. Forge attestation → order flow
  leaks while appearing sealed.
- **EU AI Act audit collapse**: Article 15 high-risk systems attestation
  logs lose integrity if the signing chain is forgeable.
- **Apple PCC transparency**: PCC's published "verifiable transparency"
  design for AI inference combines TDX-style attestation on server side
  with client-side verification; forging any RSA link breaks that story.

## Code

- `tdx_quote_verify.c` — verifier-side parsing of a DCAP v4 quote: check
  PCK RSA chain to Intel Root, verify ECDSA-P256 quote signature over TD
  report.
- `pccs_client.py` — talk to a PCCS (Intel-hosted or Azure/GCP-hosted) to
  fetch PCK certs and TCB info, verify Intel RSA-3072 signatures on the
  TCB info JSON.
- `quote_v4_layout.h` — DCAP v4 quote binary layout (TD report + ECDSA
  signature + PCK chain + QE report).
