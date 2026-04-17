# azure-attestation-jwt — RSA in Microsoft Azure Attestation (MAA) for AI workloads

**Standard:** Microsoft Azure Attestation (MAA); JWT RS256; OpenID Connect discovery
**Industry:** Confidential AI on Azure, secure-enclave verification for Microsoft 365 Copilot backends, OpenAI-on-Azure
**Algorithm:** RSA-2048 / RSA-3072 (MAA signing keys), exposed via RS256 JWTs and OpenID JWKS

## What it does

Microsoft Azure Attestation is the attestation verifier that backs every
Azure confidential-computing service: Intel SGX enclaves, Intel TDX VMs,
AMD SEV-SNP VMs, AMD SEV-SNP + NVIDIA H100 CC-mode co-attestation, VBS
enclaves on Windows Server. It is the service that gates release of
customer-managed keys in Azure Key Vault Managed HSM and Azure Confidential
Ledger (SCITT) integrity.

Flow:
  1. A VM / enclave produces vendor-specific evidence (SGX quote, TDX quote,
     SEV-SNP attestation report, NVIDIA GPU attestation).
  2. The guest submits evidence to a MAA regional endpoint (e.g.
     `sharedeus.eus.attest.azure.net`).
  3. MAA verifies the vendor chain (Intel RSA chain, AMD ASK, NVIDIA NRAS).
  4. MAA issues a **signed JWT (`alg: RS256`)** containing normalized claims
     across vendors — `x-ms-isolation-tee.x-ms-compliance-status`,
     `x-ms-sevsnpvm-reportdata`, `x-ms-runtime` claims, custom policy
     output.
  5. Downstream systems (Azure Key Vault, customer apps, Microsoft Copilot
     backend) verify the MAA JWT against the MAA tenant's OpenID
     `.well-known/openid-configuration` JWKS (RSA-2048 public keys).

Every "confidential Copilot", every Azure OpenAI deployment with customer-
managed-keys-with-attestation, every confidential-AI partner (Anthropic
deployments on Azure, Mistral-on-Azure, Nvidia Triton confidential inference)
trusts MAA as the single root of attestation truth.

## Why it's stuck

- MAA JWTs are RS256. The JWKS exposes RSA-2048 modulus + exponent.
- MAA rotates keys periodically, but pinned client verifiers (in mobile
  apps, in IoT gateways, in customer apps) often cache the JWKS for long
  windows.
- MAA sits upstream of Azure Confidential Ledger, which underpins
  supply-chain transparency (SCITT). A MAA compromise cascades into
  every attestation-backed SCITT claim.
- Azure Key Vault's "secure key release" policy evaluates the MAA JWT
  under the customer's key policy. Release-of-wrapped-model-weights
  depends on MAA RSA integrity.

## impact

- **Confidential Copilot data leak**: Microsoft pitches confidential
  inference for M365 Copilot tenants with enhanced compliance. Forged
  MAA JWTs cause Key Vault to release customer-side key material to
  attacker-controlled VMs; customer prompts and generated output become
  decryptable.
- **OpenAI-on-Azure weight exfil**: OpenAI's proprietary model weights
  deployed into Azure confidential VMs (for Azure OpenAI Service) are
  wrapped by Azure-held KEKs that only release on attested start. Forged
  MAA → weight exfiltration by a tenant who bribes their Azure host.
- **SCITT supply-chain collapse**: IETF SCITT transparency uses Azure
  Confidential Ledger entries countersigned by MAA attestations; a MAA
  key compromise rewrites supply-chain history for every AI model whose
  provenance is pinned to ACL.
- **Cross-cloud AI governance**: MAA is one of the few multi-vendor
  (Intel/AMD/NVIDIA) verifiers in production use. Governance frameworks
  that accept "an MAA token as proof of confidential compute" (including
  third-party compliance attestations) break.

## Code

- `maa_client.py` — submit evidence to MAA, parse and validate the
  returned RS256 JWT against the tenant's JWKS.
- `maa_policy.rego` — example MAA attestation policy (rego-like DSL
  that MAA evaluates server-side to customize JWT claims).
- `kv_sk_release.py` — Azure Key Vault secure-key-release client: hand
  the MAA JWT to Key Vault, receive the unwrapped AES key for model
  weight decryption.
