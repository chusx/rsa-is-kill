/*
 * Intel SGX enclave signing uses RSA-3072 — hardcoded in the Intel SGX
 * architecture specification (Intel SDM Vol. 3D, Chapter 38).
 *
 * Every SGX enclave binary (.so/.dll) must be signed before loading.
 * The signing key is RSA-3072 with public exponent e=3 (production) or
 * any valid exponent (debug mode).
 *
 * The SIGSTRUCT (Enclave Signature Structure, 1808 bytes) contains:
 *   - RSA-3072 modulus of the enclave signing key (384 bytes)
 *   - RSA-3072 public exponent (4 bytes, typically 3)
 *   - RSA-3072 signature over SHA-256(SIGSTRUCT.Header || SIGSTRUCT.Body)
 *   - MRSIGNER: SHA-256 of the RSA-3072 public key modulus
 *
 * MRSIGNER is a hardware measurement burned into the SGX attestation report.
 * It cannot be updated without re-signing all enclaves under a new key.
 * Intel's own enclaves (Quoting Enclave, Provisioning Enclave) use
 * Intel's RSA-3072 signing key.
 *
 * Intel's Attestation Service (EPID and DCAP) verifies RSA-3072 signatures.
 * No PQC signing algorithm is defined in the SGX architecture specification.
 * Intel has not published a timeline for PQC SIGSTRUCT support.
 */

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>

/* SIGSTRUCT layout (Intel SDM Vol. 3D §38.13) */
#define SE_KEY_SIZE       384    /* RSA-3072 modulus: 384 bytes */
#define SE_EXPONENT_SIZE  4      /* RSA-3072 public exponent */
#define SGX_HASH_SIZE     32     /* SHA-256 */

typedef struct _css_header_t {    /* Enclave Signing Struct header */
    uint8_t  header[12];          /* {0x06, 0x00, 0x00, 0x00, ...} */
    uint32_t type;                /* 0x00000000 = production */
    uint32_t module_vendor;       /* 0x00008086 = Intel */
    uint32_t date;                /* YYYYMMDD in BCD */
    uint8_t  header2[16];         /* {0x01, 0x01, 0x00, 0x00, ...} */
    uint16_t hw_version;
} css_header_t;

typedef struct _css_key_t {
    uint8_t  modulus[SE_KEY_SIZE];      /* RSA-3072 public key modulus */
    uint8_t  exponent[SE_EXPONENT_SIZE];/* RSA-3072 public exponent (3 or 65537) */
    uint8_t  signature[SE_KEY_SIZE];    /* RSA-3072 signature (384 bytes) */
} css_key_t;

typedef struct _css_body_t {
    uint32_t misc_select;
    uint32_t misc_mask;
    uint8_t  reserved[20];
    uint8_t  attributes[16];    /* Enclave attributes (64-bit flags + 128-bit XFRM) */
    uint8_t  attribute_mask[16];
    uint8_t  enclave_hash[SGX_HASH_SIZE];  /* SHA-256 of enclave binary (MRENCLAVE) */
    uint8_t  reserved2[32];
    uint16_t isvprodid;         /* ISV-assigned product ID */
    uint16_t isvsvn;            /* ISV security version number */
} css_body_t;

/* SIGSTRUCT = header + key + body + buffer (total: 1808 bytes) */
typedef struct _enclave_css_t {
    css_header_t header;        /* 128 bytes */
    css_key_t    key;           /* 772 bytes — contains RSA-3072 key + signature */
    css_body_t   body;          /* 128 bytes */
    uint8_t      buffer[780];   /* padding / reserved */
} enclave_css_t;

/* sgx_sign: sign an enclave SIGSTRUCT with RSA-3072.
 * Called by the sgx_sign tool (part of SGX SDK) at enclave build time.
 * The signing key is an RSA-3072 PEM file held by the enclave developer.
 *
 * MRSIGNER (the hardware measurement of the developer's identity) is:
 *   SHA-256(css.key.modulus)
 * This value is used in SGX sealing — data sealed to MRSIGNER can only be
 * accessed by enclaves signed with the same RSA-3072 key.
 * A CRQC recovering the signing key from MRSIGNER breaks SGX sealing.
 */
int sgx_sign_enclave(enclave_css_t *css, RSA *signing_key /* RSA-3072 */)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t sign_buffer[SE_KEY_SIZE];
    unsigned int sig_len;

    /* Compute SHA-256 over SIGSTRUCT Header || Body */
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, &css->header, sizeof(css->header));
    SHA256_Update(&sha_ctx, &css->body, sizeof(css->body));
    SHA256_Final(digest, &sha_ctx);

    /* RSA-3072 PKCS#1 v1.5 sign — hardcoded by SGX spec, no PQC alternative */
    if (RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH,
                 sign_buffer, &sig_len, signing_key) != 1)
        return -1;

    /* Store in SIGSTRUCT */
    memcpy(css->key.signature, sign_buffer, SE_KEY_SIZE);

    /* MRSIGNER = SHA-256 of the RSA-3072 public modulus */
    uint8_t mrsigner[SHA256_DIGEST_LENGTH];
    SHA256(css->key.modulus, SE_KEY_SIZE, mrsigner);
    /* mrsigner is used for SGX sealing policy — tied to RSA-3072 key identity */

    return 0;
}

/*
 * Scale:
 *   - Intel SGX is available on all Intel Core processors (6th gen+)
 *     and Xeon Scalable (E3-1500 v5+, some Xeon E series)
 *   - Azure Confidential Computing, IBM Cloud MZR, Alibaba Cloud use SGX
 *   - Applications: DRM, password managers, cloud key management,
 *     blockchain transaction signing, privacy-preserving ML inference
 *
 * The SGX architecture specification (RSA-3072 SIGSTRUCT) is a hardware ABI.
 * Changing it requires a new SGX hardware revision and microcode update,
 * plus SDK/toolchain updates for all enclave developers.
 * Intel has not announced a PQC SIGSTRUCT format.
 */
