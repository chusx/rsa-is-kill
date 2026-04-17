// FIDO2 / WebAuthn (W3C WebAuthn Level 3, FIDO2 CTAP 2.2)
// supports RS256 (RSASSA-PKCS1-v1_5 with SHA-256) as an attestation algorithm.
//
// RS256 is COSE algorithm ID -257 (IANA COSE Algorithms registry).
// It is widely used for:
//   - Platform authenticators on Windows (Windows Hello — RS256 on older TPMs)
//   - Enterprise FIDO2 policies requiring RS256 for compatibility with
//     RSA-only RADIUS/EAP infrastructure
//   - YubiKey attestation certificates (RSA-2048 on older YubiKey 4 series)
//   - Attestation CA hierarchies: Yubico CA, Google Cloud FIDO2 attestation
//
// The W3C WebAuthn spec allows RS256, RS384, RS512 (RSASSA-PKCS1-v1_5) and
// PS256, PS384, PS512 (RSASSA-PSS). Both RSA variants are broken by Shor.
//
// No PQC COSE algorithm ID is registered for use with WebAuthn.
// The FIDO Alliance has not published a PQC authenticator specification.

// Based on webauthn-rs (Rust implementation) and the W3C WebAuthn spec.

use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::sign::{Signer, Verifier};
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};

/// COSE algorithm identifiers (RFC 8152)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[repr(i32)]
pub enum COSEAlgorithm {
    ES256  = -7,    // ECDSA w/ SHA-256 (P-256)       — broken by Shor
    ES384  = -35,   // ECDSA w/ SHA-384 (P-384)       — broken by Shor
    ES512  = -36,   // ECDSA w/ SHA-512 (P-521)       — broken by Shor
    RS256  = -257,  // RSASSA-PKCS1-v1_5 w/ SHA-256   — broken by Shor
    RS384  = -258,  // RSASSA-PKCS1-v1_5 w/ SHA-384   — broken by Shor
    RS512  = -259,  // RSASSA-PKCS1-v1_5 w/ SHA-512   — broken by Shor
    PS256  = -37,   // RSASSA-PSS w/ SHA-256           — broken by Shor
    PS384  = -38,   // RSASSA-PSS w/ SHA-384           — broken by Shor
    PS512  = -39,   // RSASSA-PSS w/ SHA-512           — broken by Shor
    EdDSA  = -8,    // EdDSA (Ed25519, Ed448)          — broken by Shor
    // ML_DSA_44 = ??? — NOT REGISTERED in IANA COSE registry
    // SLH_DSA_SHAKE_128F = ??? — NOT REGISTERED
}

/// COSE RSA public key structure (RFC 8230)
/// Used for RS256/RS384/RS512/PS256/PS384/PS512 WebAuthn credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct COSERSAPublicKey {
    /// Key type: kty = 3 (RSA)
    #[serde(rename = "1")]
    pub kty: i32,           // 3 = RSA

    /// Algorithm: alg = -257 (RS256) or -37 (PS256), etc.
    #[serde(rename = "3")]
    pub alg: COSEAlgorithm, // RS256 = -257

    /// RSA modulus n (big-endian bytes, typically 256 bytes for RSA-2048)
    #[serde(rename = "-1")]
    pub n: Vec<u8>,         // 256 bytes = 2048-bit modulus

    /// RSA public exponent e (big-endian bytes, typically 3 bytes: [1,0,1] = 65537)
    #[serde(rename = "-2")]
    pub e: Vec<u8>,         // [0x01, 0x00, 0x01] = 65537
}

/// verify_rs256_signature() — verify a WebAuthn RS256 assertion.
/// Called during authentication when the authenticator returns an RS256 signature.
///
/// @signature:       RSA-PKCS1-v1_5 signature over authenticatorData || hash(clientDataJSON)
/// @client_data:     authenticatorData || SHA-256(clientDataJSON)
/// @pub_key:         COSERSAPublicKey from the registered credential
pub fn verify_rs256_signature(
    signature: &[u8],
    client_data: &[u8],
    pub_key: &COSERSAPublicKey,
) -> Result<bool, openssl::error::ErrorStack> {
    // Reconstruct RSA public key from COSE modulus + exponent
    let rsa = Rsa::from_public_components(
        openssl::bn::BigNum::from_slice(&pub_key.n)?,  // RSA-2048 modulus
        openssl::bn::BigNum::from_slice(&pub_key.e)?,  // exponent = 65537
    )?;
    let pkey = PKey::from_rsa(rsa)?;

    // Verify RSASSA-PKCS1-v1_5 with SHA-256 (RS256, COSE -257)
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verifier.update(client_data)?;
    Ok(verifier.verify(signature)?)
}

// Windows Hello RS256:
// Windows Hello on devices with older TPMs (pre-TPM 2.0 ECC) defaults to RS256.
// The resident key (credential private key) is sealed inside the TPM.
// RS256 is also used when enterprise policy requires RSA for FIDO2.
//
// YubiKey 4 attestation certificate: RSA-2048, signed by Yubico Attestation CA.
// YubiKey 5 series: ECDSA P-256 by default, but RS256 still supported.
//
// FIDO Metadata Service (MDS3): lists all authenticator attestation roots.
// Many entries are RSA-2048 CA certificates.
// No PQC attestation CA is registered in FIDO MDS3.
