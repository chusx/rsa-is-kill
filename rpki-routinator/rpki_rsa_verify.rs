// Source: NLnetLabs rpki-rs - https://github.com/NLnetLabs/rpki-rs
// File:   src/crypto/keys.rs
// License: BSD-3-Clause
//
// Relevant excerpt: RSA signature verification for RPKI objects.
//
// RPKI (Resource Public Key Infrastructure) is the cryptographic
// foundation of BGP routing security.  Every Route Origin Authorization
// (ROA) - which says "AS12345 is allowed to announce 192.0.2.0/24" -
// is signed with an RSA key that chains up to the five Regional Internet
// Registries (ARIN, RIPE, APNIC, LACNIC, AFRINIC).
//
// If RSA is broken:
//   - Attackers can forge ROAs authorizing any AS to announce any prefix
//   - BGP hijacking becomes trivially authenticated - the attack PASSES
//     Route Origin Validation instead of being caught by it
//   - The RPKI system designed to IMPROVE routing security becomes
//     WORSE than no RPKI at all (forged ROAs can invalidate legitimate routes)
//
// This is the "ROV paradox": using ROV with quantum-vulnerable crypto
// makes BGP less secure than not using ROV.

/// RSA public key as encoded in RPKI X.509 certificates.
/// Per RFC 4055, the SubjectPublicKeyInfo for RSA contains:
///   algorithm: rsaEncryption OID (1.2.840.113549.1.1.1)
///   subjectPublicKey: DER-encoded RSAPublicKey { modulus, publicExponent }
///
/// All RPKI certificates use RSA-2048 minimum.  No PQC alternative
/// algorithm OID is recognized by any production RPKI validator.
pub struct RsaPublicKey {
    /// The DER-encoded RSAPublicKey bits extracted from SubjectPublicKeyInfo
    bits: Bytes,
}

impl RsaPublicKey {
    /// Construct from DER-encoded RSAPublicKey bytes.
    /// Validates the internal SEQUENCE { INTEGER, INTEGER } structure.
    pub fn rsa_from_bits_bytes(bytes: Bytes) -> Result<Self, KeyError> {
        // Validate: must be SEQUENCE { modulus INTEGER, exponent INTEGER }
        // No key size enforcement here - RFC 7935 mandates 2048-bit minimum
        // but that check is elsewhere.
        Ok(RsaPublicKey { bits: bytes })
    }

    /// Verify an RSA signature over a message.
    /// Uses AWS-LC (AWS's fork of BoringSSL) for the actual RSA operation.
    ///
    /// The algorithm is RSA_PKCS1_2048_8192_SHA256:
    ///   - RSA with PKCS#1 v1.5 padding
    ///   - Key size: 2048 to 8192 bits
    ///   - Hash: SHA-256
    ///
    /// This is the ONLY signature algorithm accepted for RPKI objects.
    /// There is no ML-DSA or SLH-DSA path.  Adding one requires:
    ///   1. A new RFC specifying PQC algorithm OIDs for RPKI
    ///   2. Updates to all five RIR trust anchors
    ///   3. CA certificate reissuance across the entire global RPKI hierarchy
    ///   4. Validator software updates deployed to every network operator
    pub fn verify<Alg: SignatureAlgorithm>(
        &self,
        message: &[u8],
        signature: &Signature<Alg>,
    ) -> Result<(), SignatureVerificationError> {
        // Extract raw key material
        let key_bits = self.bits.octet_slice()
            .map_err(|_| SignatureVerificationError)?;

        // Delegate to AWS-LC RSA verification.
        // signature::RSA_PKCS1_2048_8192_SHA256 is the hardcoded algorithm.
        // Returning an opaque error on failure (no diagnostic info leaked).
        signature::RSA_PKCS1_2048_8192_SHA256
            .verify_sig(key_bits, message, signature.as_ref())
            .map_err(|_| SignatureVerificationError)
    }
}
