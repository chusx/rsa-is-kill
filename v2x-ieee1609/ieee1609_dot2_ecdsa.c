/*
 * Illustrative code based on IEEE 1609.2-2022 and the US V2X Security
 * Credential Management System (SCMS) specification.
 * V2X (Vehicle-to-Everything) uses ECDSA (secp256r1 / NIST P-256 and
 * secp384r1 / NIST P-384) for all certificate signing and message signing.
 * The SCMS manages hundreds of millions of pseudonym certificates per vehicle.
 * There is no PQC profile in IEEE 1609.2 or ETSI TS 103 097 (EU equivalent).
 *
 * ECDSA is broken by Shor's algorithm just like RSA.
 * V2X message authentication (BSM, SPaT, MAP, CERT) all rely on ECDSA.
 */

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>   /* NID_X9_62_prime256v1 */
#include <openssl/sha.h>

/* IEEE 1609.2 §6.3.1 — EcdsaP256Signature */
typedef struct {
    uint8_t r_x[32];          /* compressed R point x-coordinate */
    uint8_t r_y_indicator;    /* 0x02 or 0x03 */
    uint8_t s[32];            /* scalar s */
} EcdsaP256Signature;

/* IEEE 1609.2 §6.3.30 — Certificate structure (simplified) */
typedef struct {
    uint8_t version;
    uint32_t cert_type;               /* explicit or implicit */
    uint8_t issuer_hash[32];          /* SHA-256 of issuer cert */
    EC_POINT *verification_key;       /* ECDSA-P256 public key */
    uint32_t expiry_time;             /* CrlSeries / validity */
    EcdsaP256Signature signature;     /* ECDSA-P256 over ToBeSigned */
} IEEE1609Dot2Certificate;

/*
 * Sign a V2X Basic Safety Message (BSM).
 * Every vehicle broadcasts BSMs 10x/second. Each BSM is signed with a
 * short-lived pseudonym certificate (7-day validity) using ECDSA-P256.
 * A single vehicle uses ~20 pseudonym certs/week, ~1,000/year.
 * The SCMS issues ~300 million pseudonym certs/year for US deployment.
 */
int ieee1609_sign_bsm(const uint8_t *bsm_payload, size_t payload_len,
                      EC_KEY *pseudonym_key,       /* ECDSA P-256 private key */
                      EcdsaP256Signature *out_sig)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    ECDSA_SIG *sig = NULL;
    const BIGNUM *r, *s;
    int ret = -1;

    /* Hash the BSM payload per IEEE 1609.2 §6.3.23 */
    SHA256(bsm_payload, payload_len, digest);

    /* Sign with ECDSA-P256 — secp256r1 (NID_X9_62_prime256v1) */
    sig = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, pseudonym_key);
    if (!sig) goto done;

    ECDSA_SIG_get0(sig, &r, &s);

    /* Pack into IEEE 1609.2 EcdsaP256Signature format */
    BN_bn2binpad(r, out_sig->r_x, 32);
    out_sig->r_y_indicator = 0x02; /* compressed point indicator */
    BN_bn2binpad(s, out_sig->s, 32);

    ret = 0;
done:
    ECDSA_SIG_free(sig);
    return ret;
}

/*
 * SCMS Certificate Authority hierarchy (all ECDSA):
 *   Root CA (P-384) → signs
 *     Registration Authority (P-256) → signs
 *       Pseudonym CA (P-256) → signs
 *         Pseudonym certificates (P-256) → signs BSMs
 *
 * The entire trust chain is ECC. Shor's algorithm breaks all levels.
 * Vehicles cannot receive OTA updates fast enough to rotate to PQC;
 * DSRC (802.11p) and C-V2X radios have fixed cryptographic hardware.
 * ETSI TS 103 097 (European V2X) has the same ECDSA-only constraint.
 */
