# intel-sgx-signing — RSA-3072 hardcoded in SGX architecture

**Hardware:** Intel SGX (6th gen Core+, Xeon Scalable)  
**Industry:** Cloud confidential computing, DRM, password managers, blockchain signing  
**Algorithm:** RSA-3072 with e=3 — hardcoded in Intel SDM Vol. 3D §38.13 (SIGSTRUCT)  
**PQC migration plan:** None — RSA-3072 SIGSTRUCT is a hardware ABI; changing it requires new silicon

## What it does

Every Intel SGX enclave must be signed before it can be loaded. The signing
format (SIGSTRUCT, 1808 bytes) is defined in the Intel SGX architecture
specification and includes:

- RSA-3072 public key modulus (384 bytes)
- RSA-3072 public exponent (typically e=3)
- RSA-3072 PKCS#1 v1.5 signature over the enclave measurement

**MRSIGNER** is SHA-256 of the RSA-3072 modulus. It is a hardware identity
measurement used for SGX sealing — data sealed to MRSIGNER can only be
accessed by enclaves from the same developer. A CRQC recovering the signing
key from MRSIGNER breaks all sealed data.

## Why it's stuck

The SIGSTRUCT format is a hardware ABI baked into SGX microcode. It cannot be
changed without:
1. New SGX hardware revision with PQC SIGSTRUCT support
2. Updated Intel Platform Software (PSW) and SDK
3. All cloud providers updating their SGX attestation services
4. All enclave developers recompiling and re-signing their enclaves

Intel has not announced a PQC SIGSTRUCT format. Cloud SGX attestation services
(Azure Confidential Compute, AWS Nitro Enclaves with SGX) have no PQC path.

## why is this hella bad

SGX enclaves are used specifically because their contents are supposed to be secret and their identity trustworthy. Breaking RSA-3072 SIGSTRUCT means:

- **Break remote attestation**: forge any enclave's SIGSTRUCT with arbitrary MRENCLAVE (measurement) and MRSIGNER → convince remote services the enclave is trustworthy when it isn't → bypass all SGX-based attestation checks
- **Break SGX sealing**: sealed data (passwords, private keys, DRM content) is encrypted to MRSIGNER (SHA-256 of the RSA modulus) → recover RSA signing key → recompute MRSIGNER → unseal any sealed data from any enclave under that signing key
- **Cloud confidential computing**: Azure Confidential VMs, IBM Cloud use SGX for "data in use" privacy. Forged attestation quotes = arbitrary code running under "trusted enclave" claims
- Intel's own Quoting Enclave and Provisioning Enclave use Intel's RSA-3072 signing key. Compromising that single key breaks the entire SGX attestation ecosystem globally

## Code

`sgx_enclave_rsa3072.c` — `sgx_sign_enclave()` showing the `enclave_css_t`
(SIGSTRUCT) layout, RSA-3072 signature generation, and MRSIGNER derivation.
Key size: `SE_KEY_SIZE = 384` bytes = 3072 bits.
