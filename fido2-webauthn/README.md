# fido2-webauthn — RS256 in passwordless authentication

**Standard:** W3C WebAuthn Level 3 / FIDO2 CTAP 2.2  
**Industry:** Web authentication, banking 2FA, government login, enterprise SSO  
**Algorithm:** RS256 (RSASSA-PKCS1-v1_5) — COSE algorithm -257; also PS256 (RSA-PSS)  
**PQC migration plan:** None — no PQC COSE algorithm registered in IANA registry; FIDO Alliance has no PQC spec

## What it does

WebAuthn/FIDO2 is the W3C standard for passwordless authentication used by
Google, Apple, Microsoft, GitHub, Shopify, and every major website implementing
passkeys. The authenticator creates an asymmetric keypair; the private key
never leaves the device.

RS256 (COSE algorithm -257) is supported and used in production:
- **Windows Hello** on older TPMs: defaults to RS256 (TPM RSA-2048)
- **YubiKey 4 series**: uses RSA-2048 for attestation certificates
- **Enterprise FIDO2 policies**: some require RS256 for compatibility with
  RSA-only PKI / RADIUS backends
- **FIDO Metadata Service (MDS3)**: many registered authenticators list
  RSA-2048 attestation CA certificates

The IANA COSE Algorithms registry has no entry for ML-DSA or SLH-DSA.
The FIDO Alliance has no CTAP extension for PQC credentials.

## Why it's stuck

WebAuthn credentials are long-lived (passkeys replace passwords; users don't
rotate them). An RS256 passkey created today may be in use in 2035+.

Beyond the algorithm gap, the hardware authenticator problem mirrors the
ATECC608 issue: if the authenticator hardware implements RSA in silicon
(older TPMs, YubiKey 4), the algorithm cannot be changed without replacing
the physical device.

## Code

`webauthn_rs256_attestation.rs` — `COSEAlgorithm` enum listing all COSE
algorithm IDs (all broken by Shor), `COSERSAPublicKey` struct (n+e fields),
and `verify_rs256_signature()` performing RSA-2048 PKCS#1 v1.5 verification.
